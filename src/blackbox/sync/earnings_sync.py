"""Earnings calendar sync service.

Syncs earnings announcements and creates activities/alerts for tracked companies.
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.earnings import EarningsClient, EarningsConfig, EarningsEvent
from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType

log = structlog.get_logger(__name__)


class EarningsSyncConfig(BaseModel):
    """Configuration for earnings sync."""

    earnings_config: EarningsConfig = Field(default_factory=EarningsConfig)
    entity_id: str = "entity:earnings_calendar"
    days_ahead: int = Field(default=14, description="Days to look ahead for upcoming earnings")
    days_back: int = Field(default=7, description="Days to look back for reported earnings")
    tracked_symbols: list[str] = Field(default_factory=list, description="Symbols to track (empty = all)")
    create_activities: bool = True
    create_alerts: bool = True
    alert_days_threshold: int = Field(default=3, description="Create alert when earnings within N days")


class EarningsSyncResult(BaseModel):
    """Result from earnings sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    events_found: int = 0
    events_upcoming: int = 0
    events_reported: int = 0
    activities_created: int = 0
    alerts_created: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class EarningsSyncService:
    """Service for syncing earnings calendar data.

    Usage:
        async with EarningsSyncService(config, activity_repo, alert_repo) as service:
            result = await service.sync()
    """

    def __init__(
        self,
        config: EarningsSyncConfig,
        activity_repository: SQLiteActivityRepository,
        alert_repository: SQLiteAlertRepository | None = None,
        client: EarningsClient | None = None,
    ) -> None:
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "EarningsSyncService":
        if self._client is None:
            self._client = EarningsClient(config=self.config.earnings_config)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    def _event_to_activity(self, event: EarningsEvent, is_upcoming: bool) -> Activity:
        """Convert earnings event to Activity model."""
        if is_upcoming:
            description = f"**{event.symbol}** - Upcoming Earnings ({event.timing_label})\n\n"
            description += f"Date: {event.date.strftime('%Y-%m-%d')}\n"
            if event.eps_estimate:
                description += f"EPS Estimate: ${event.eps_estimate:.2f}\n"
            if event.revenue_estimate:
                description += f"Revenue Estimate: ${event.revenue_estimate:,.0f}\n"
        else:
            description = f"**{event.symbol}** - Earnings Reported\n\n"
            description += f"Date: {event.date.strftime('%Y-%m-%d')}\n"
            if event.eps_actual is not None:
                description += f"EPS Actual: ${event.eps_actual:.2f}"
                if event.eps_estimate:
                    description += f" (Est: ${event.eps_estimate:.2f})"
                    pct = event.surprise_percent
                    if pct is not None:
                        emoji = "🟢" if pct > 0 else "🔴"
                        description += f" {emoji} {pct:+.1f}%"
                description += "\n"
            if event.revenue_actual is not None:
                description += f"Revenue: ${event.revenue_actual:,.0f}\n"

        return Activity(
            entity_id=self.config.entity_id,
            activity_type=ActivityType.PUBLICATION,
            source="finnhub_earnings",
            description=description,
            occurred_at=event.date,
            source_refs=[f"earnings:{event.symbol}:{event.date.strftime('%Y-%m-%d')}"],
            metadata={
                "symbol": event.symbol,
                "date": event.date.isoformat(),
                "hour": event.hour,
                "quarter": event.quarter,
                "year": event.year,
                "eps_estimate": event.eps_estimate,
                "eps_actual": event.eps_actual,
                "revenue_estimate": event.revenue_estimate,
                "revenue_actual": event.revenue_actual,
                "is_upcoming": is_upcoming,
                "is_beat": event.is_beat if not is_upcoming else None,
                "surprise_percent": event.surprise_percent if not is_upcoming else None,
            },
        )

    def _event_to_alert(self, event: EarningsEvent, days_until: int) -> Alert:
        """Convert upcoming earnings to Alert model."""
        return Alert(
            alert_type=AlertType.CORPORATE,
            title=f"Earnings Soon: {event.symbol}",
            description=f"{event.symbol} reports earnings in {days_until} days ({event.date.strftime('%Y-%m-%d')}, {event.timing_label})",
            severity=AlertSeverity.MEDIUM if days_until > 1 else AlertSeverity.HIGH,
            status=AlertStatus.NEW,
            entity_refs=[self.config.entity_id],
            source_refs=[f"earnings:{event.symbol}:{event.date.strftime('%Y-%m-%d')}"],
            detector_name="earnings_sync",
            confidence=0.9,
            detector_metadata={
                "symbol": event.symbol,
                "date": event.date.isoformat(),
                "days_until": days_until,
                "eps_estimate": event.eps_estimate,
                "timing": event.hour,
            },
        )

    async def sync(self) -> EarningsSyncResult:
        """Sync earnings calendar from Finnhub.

        Returns:
            EarningsSyncResult with sync statistics
        """
        result = EarningsSyncResult()

        try:
            log.info(
                "Starting earnings sync",
                days_ahead=self.config.days_ahead,
                days_back=self.config.days_back,
                tracked_symbols=self.config.tracked_symbols[:10] if self.config.tracked_symbols else "all",
            )

            # Fetch earnings calendar
            calendar_result = await self._client.get_earnings_calendar(
                days_ahead=self.config.days_ahead,
                days_back=self.config.days_back,
            )

            events = calendar_result.events
            result.events_found = len(events)

            # Filter by tracked symbols if configured
            if self.config.tracked_symbols:
                symbols_upper = {s.upper() for s in self.config.tracked_symbols}
                events = [e for e in events if e.symbol in symbols_upper]

            log.info("Earnings fetch complete", events_found=result.events_found, events_filtered=len(events))

            now = datetime.now(UTC)

            for event in events:
                is_upcoming = event.is_upcoming
                if is_upcoming:
                    result.events_upcoming += 1
                else:
                    result.events_reported += 1

                # Check for existing activity (deduplication)
                source_ref = f"earnings:{event.symbol}:{event.date.strftime('%Y-%m-%d')}"
                existing = await self.activity_repo.exists_by_source_ref(source_ref)

                if existing:
                    continue

                # Create activity
                if self.config.create_activities:
                    activity = self._event_to_activity(event, is_upcoming)
                    await self.activity_repo.create(activity)
                    result.activities_created += 1

                # Create alert for imminent earnings
                if self.config.create_alerts and self.alert_repo and is_upcoming:
                    days_until = (event.date.date() - now.date()).days
                    if 0 <= days_until <= self.config.alert_days_threshold:
                        alert = self._event_to_alert(event, days_until)
                        await self.alert_repo.create(alert)
                        result.alerts_created += 1

                        log.info(
                            "Created earnings alert",
                            symbol=event.symbol,
                            days_until=days_until,
                        )

        except Exception as e:
            error_msg = f"Earnings sync error: {e}"
            result.errors.append(error_msg)
            log.error("Earnings sync failed", error=str(e))

        result.completed_at = datetime.now(UTC)

        log.info(
            "Earnings sync complete",
            events_found=result.events_found,
            events_upcoming=result.events_upcoming,
            events_reported=result.events_reported,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
            duration_seconds=result.duration_seconds,
        )

        return result
