"""Earnings proximity detector.

Detects when tracked positions have upcoming earnings announcements
and flags them for review.
"""

from datetime import UTC, datetime, timedelta

import structlog
from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.models import Activity, Alert, AlertSeverity, AlertStatus, AlertType, Entity

log = structlog.get_logger(__name__)


class EarningsProximityConfig(BaseModel):
    """Configuration for earnings proximity detector."""

    tracked_symbols: list[str] = Field(
        default_factory=list,
        description="Symbols to track for earnings proximity",
    )
    warning_days: int = Field(
        default=7,
        description="Days before earnings to create warning alert",
    )
    critical_days: int = Field(
        default=3,
        description="Days before earnings to elevate to critical",
    )
    lookback_days: int = Field(
        default=30,
        description="Days to look back in activities for earnings data",
    )


class EarningsProximityDetector(BaseDetector):
    """Detector for earnings proximity alerts.

    Analyzes earnings calendar activities to flag when tracked
    positions (stocks you hold) have upcoming earnings announcements.

    Usage:
        detector = EarningsProximityDetector(config)
        alerts = await detector.detect(entities, activities)
    """

    def __init__(self, config: EarningsProximityConfig | None = None) -> None:
        self.config = config or EarningsProximityConfig()

    @property
    def name(self) -> str:
        return "earnings_proximity"

    @property
    def description(self) -> str:
        return "Detects when tracked positions have upcoming earnings announcements"

    async def detect(
        self,
        entities: list[Entity],
        activities: list[Activity] | None = None,
    ) -> list[Alert]:
        """Detect earnings proximity for tracked symbols.

        Args:
            entities: List of entities (not used directly)
            activities: List of activities to analyze

        Returns:
            List of earnings proximity alerts
        """
        if not activities:
            return []

        if not self.config.tracked_symbols:
            log.debug("No tracked symbols configured, skipping earnings proximity detection")
            return []

        tracked_upper = {s.upper() for s in self.config.tracked_symbols}
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=self.config.lookback_days)
        alerts: list[Alert] = []

        log.info(
            "Running earnings proximity detection",
            tracked_symbols=list(tracked_upper)[:10],
            total_activities=len(activities),
        )

        # Find earnings activities for tracked symbols
        for activity in activities:
            # Skip old activities (handle naive datetimes by assuming UTC)
            occurred = activity.occurred_at
            if occurred.tzinfo is None:
                occurred = occurred.replace(tzinfo=UTC)
            if occurred < cutoff:
                continue

            # Check if it's an earnings activity
            metadata = activity.metadata or {}
            symbol = metadata.get("symbol", "")
            is_upcoming = metadata.get("is_upcoming", False)

            if not symbol or not is_upcoming:
                continue

            # Check if symbol is tracked
            if symbol.upper() not in tracked_upper:
                continue

            # Parse earnings date
            earnings_date_str = metadata.get("date", "")
            try:
                if "T" in earnings_date_str:
                    earnings_date = datetime.fromisoformat(earnings_date_str)
                else:
                    earnings_date = datetime.strptime(earnings_date_str, "%Y-%m-%d").replace(tzinfo=UTC)
            except (ValueError, TypeError):
                log.warning("Invalid earnings date", symbol=symbol, date=earnings_date_str)
                continue

            # Check if earnings is still in the future
            if earnings_date < now:
                continue

            # Calculate days until earnings
            days_until = (earnings_date.date() - now.date()).days

            # Skip if too far away
            if days_until > self.config.warning_days:
                continue

            # Determine severity
            if days_until <= self.config.critical_days:
                severity = AlertSeverity.HIGH
                urgency = "imminent"
            else:
                severity = AlertSeverity.MEDIUM
                urgency = "upcoming"

            # Get timing info
            timing = metadata.get("hour", "")
            timing_label = {
                "amc": "After Market Close",
                "bmo": "Before Market Open",
                "dmh": "During Market Hours",
            }.get(timing, "Unknown")

            eps_estimate = metadata.get("eps_estimate")
            eps_str = f"EPS Est: ${eps_estimate:.2f}" if eps_estimate else ""

            # Create alert
            alert = Alert(
                alert_type=AlertType.CORPORATE,
                title=f"Earnings {urgency.title()}: {symbol}",
                description=(
                    f"**{symbol}** reports earnings in **{days_until} days** "
                    f"({earnings_date.strftime('%Y-%m-%d')}, {timing_label})"
                    f"{' | ' + eps_str if eps_str else ''}\n\n"
                    f"Consider reviewing position before announcement."
                ),
                severity=severity,
                status=AlertStatus.NEW,
                entity_refs=["entity:earnings_calendar"],
                source_refs=[f"earnings:{symbol}:{earnings_date.strftime('%Y-%m-%d')}"],
                detector_name=self.name,
                confidence=0.95,
                detector_metadata={
                    "symbol": symbol,
                    "earnings_date": earnings_date.isoformat(),
                    "days_until": days_until,
                    "timing": timing,
                    "eps_estimate": eps_estimate,
                },
            )

            alerts.append(alert)

            log.info(
                "Earnings proximity alert created",
                symbol=symbol,
                days_until=days_until,
                severity=severity.value,
            )

        log.info("Earnings proximity detection complete", alerts_created=len(alerts))
        return alerts


def create_earnings_proximity_detector(tracked_symbols: list[str] | None = None) -> EarningsProximityDetector:
    """Factory function to create an earnings proximity detector.

    Args:
        tracked_symbols: List of symbols to track (e.g., held positions)

    Returns:
        Configured EarningsProximityDetector
    """
    config = EarningsProximityConfig(tracked_symbols=tracked_symbols or [])
    return EarningsProximityDetector(config)
