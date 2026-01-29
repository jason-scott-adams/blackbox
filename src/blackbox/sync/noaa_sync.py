"""NOAA Weather Alerts sync service.

Syncs weather alerts from NOAA and creates activities/alerts for severe weather.
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.noaa import NOAAClient, NOAAConfig, WeatherAlert
from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType

log = structlog.get_logger(__name__)


class NOAASyncConfig(BaseModel):
    """Configuration for NOAA sync."""

    noaa_config: NOAAConfig = Field(default_factory=NOAAConfig)
    entity_id: str = "entity:noaa_weather"
    areas: list[str] = Field(
        default_factory=lambda: ["MO", "KS"],
        description="State/area codes to monitor",
    )
    min_severity: str = Field(default="Moderate", description="Minimum severity to track")
    create_activities: bool = True
    create_alerts: bool = True
    alert_threshold: str = Field(default="Severe", description="Minimum severity for alerts")


class NOAASyncResult(BaseModel):
    """Result from NOAA sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    alerts_found: int = 0
    alerts_tracked: int = 0
    activities_created: int = 0
    alerts_created: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class NOAASyncService:
    """Service for syncing NOAA weather alerts.

    Usage:
        async with NOAASyncService(config, activity_repo, alert_repo) as service:
            result = await service.sync()
    """

    def __init__(
        self,
        config: NOAASyncConfig,
        activity_repository: SQLiteActivityRepository,
        alert_repository: SQLiteAlertRepository | None = None,
        client: NOAAClient | None = None,
    ) -> None:
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "NOAASyncService":
        if self._client is None:
            self._client = NOAAClient(config=self.config.noaa_config)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    def _severity_to_alert_severity(self, weather_severity: str) -> AlertSeverity:
        """Map NOAA severity to alert severity."""
        mapping = {
            "extreme": AlertSeverity.CRITICAL,
            "severe": AlertSeverity.HIGH,
            "moderate": AlertSeverity.MEDIUM,
            "minor": AlertSeverity.LOW,
        }
        return mapping.get(weather_severity.lower(), AlertSeverity.MEDIUM)

    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets the threshold."""
        order = ["minor", "moderate", "severe", "extreme"]
        try:
            severity_idx = order.index(severity.lower())
            threshold_idx = order.index(threshold.lower())
            return severity_idx >= threshold_idx
        except ValueError:
            return False

    def _weather_alert_to_activity(self, alert: WeatherAlert) -> Activity:
        """Convert NOAA alert to Activity model."""
        description = f"**{alert.event}** ({alert.severity})\n\n"
        if alert.headline:
            description += f"{alert.headline}\n\n"
        description += f"Areas: {alert.area_desc[:200]}"
        if alert.instruction:
            description += f"\n\nInstructions: {alert.instruction[:300]}"

        return Activity(
            entity_id=self.config.entity_id,
            activity_type=ActivityType.WEATHER_ALERT,
            source="noaa",
            description=description,
            occurred_at=alert.onset or alert.effective or datetime.now(UTC),
            source_refs=[f"noaa:{alert.alert_id}"],
            metadata={
                "alert_id": alert.alert_id,
                "event": alert.event,
                "severity": alert.severity,
                "urgency": alert.urgency,
                "certainty": alert.certainty,
                "area_desc": alert.area_desc,
                "expires": alert.expires.isoformat() if alert.expires else None,
            },
        )

    def _weather_alert_to_system_alert(self, alert: WeatherAlert) -> Alert:
        """Convert severe weather alert to system Alert model."""
        description = alert.headline or alert.event
        if alert.instruction:
            description += f"\n\n{alert.instruction[:500]}"

        return Alert(
            alert_type=AlertType.WEATHER,
            title=f"Weather Alert: {alert.event}",
            description=description,
            severity=self._severity_to_alert_severity(alert.severity),
            status=AlertStatus.NEW,
            entity_refs=[self.config.entity_id],
            source_refs=[f"noaa:{alert.alert_id}"],
            detector_name="noaa_sync",
            confidence=0.95 if alert.certainty.lower() == "observed" else 0.8,
            detector_metadata={
                "alert_id": alert.alert_id,
                "event": alert.event,
                "severity": alert.severity,
                "urgency": alert.urgency,
                "certainty": alert.certainty,
                "area_desc": alert.area_desc[:200],
            },
        )

    async def sync(self) -> NOAASyncResult:
        """Sync active weather alerts from NOAA.

        Returns:
            NOAASyncResult with sync statistics
        """
        result = NOAASyncResult()

        try:
            log.info(
                "Starting NOAA sync",
                areas=self.config.areas,
                min_severity=self.config.min_severity,
            )

            # Fetch alerts for all configured areas
            noaa_result = await self._client.get_alerts_for_region(self.config.areas)
            result.alerts_found = len(noaa_result.alerts)

            log.info("NOAA fetch complete", alerts_found=result.alerts_found)

            for alert in noaa_result.alerts:
                # Filter by minimum severity
                if not self._meets_severity_threshold(alert.severity, self.config.min_severity):
                    continue

                result.alerts_tracked += 1

                # Check for existing activity (deduplication)
                source_ref = f"noaa:{alert.alert_id}"
                existing = await self.activity_repo.exists_by_source_ref(source_ref)

                if existing:
                    continue

                # Create activity
                if self.config.create_activities:
                    activity = self._weather_alert_to_activity(alert)
                    await self.activity_repo.create(activity)
                    result.activities_created += 1

                # Create system alert for severe/extreme weather
                if (
                    self.config.create_alerts
                    and self.alert_repo
                    and self._meets_severity_threshold(alert.severity, self.config.alert_threshold)
                ):
                    system_alert = self._weather_alert_to_system_alert(alert)
                    await self.alert_repo.create(system_alert)
                    result.alerts_created += 1

                    log.info(
                        "Created weather alert",
                        event=alert.event,
                        severity=alert.severity,
                        urgency=alert.urgency,
                    )

        except Exception as e:
            error_msg = f"NOAA sync error: {e}"
            result.errors.append(error_msg)
            log.error("NOAA sync failed", error=str(e))

        result.completed_at = datetime.now(UTC)

        log.info(
            "NOAA sync complete",
            alerts_found=result.alerts_found,
            alerts_tracked=result.alerts_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
            duration_seconds=result.duration_seconds,
        )

        return result


def create_kc_weather_sync_service(
    activity_repository: SQLiteActivityRepository,
    alert_repository: SQLiteAlertRepository | None = None,
) -> NOAASyncService:
    """Create a sync service for Kansas City metro weather alerts."""
    config = NOAASyncConfig(
        areas=["MO", "KS"],
        entity_id="entity:kc_weather",
    )
    return NOAASyncService(
        config=config,
        activity_repository=activity_repository,
        alert_repository=alert_repository,
    )
