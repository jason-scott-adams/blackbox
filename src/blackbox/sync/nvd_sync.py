"""NVD (National Vulnerability Database) sync service.

Syncs CVE data from NVD and creates activities/alerts for critical vulnerabilities.
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.nvd import CVE, NVDClient, NVDConfig
from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType

log = structlog.get_logger(__name__)


class NVDSyncConfig(BaseModel):
    """Configuration for NVD sync."""

    nvd_config: NVDConfig = Field(default_factory=NVDConfig)
    entity_id: str = "entity:nvd_cve"
    lookback_hours: int = Field(default=24, description="Hours to look back for recent CVEs")
    min_severity: str = Field(default="HIGH", description="Minimum severity to track (LOW, MEDIUM, HIGH, CRITICAL)")
    create_activities: bool = True
    create_alerts: bool = True
    alert_threshold: str = Field(default="CRITICAL", description="Minimum severity for alerts")


class NVDSyncResult(BaseModel):
    """Result from NVD sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    cves_found: int = 0
    cves_tracked: int = 0
    activities_created: int = 0
    alerts_created: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class NVDSyncService:
    """Service for syncing NVD CVE data.

    Usage:
        async with NVDSyncService(config, activity_repo, alert_repo) as service:
            result = await service.sync()
    """

    def __init__(
        self,
        config: NVDSyncConfig,
        activity_repository: SQLiteActivityRepository,
        alert_repository: SQLiteAlertRepository | None = None,
        client: NVDClient | None = None,
    ) -> None:
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "NVDSyncService":
        if self._client is None:
            self._client = NVDClient(config=self.config.nvd_config)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    def _severity_to_alert_severity(self, cvss_severity: str) -> AlertSeverity:
        """Map CVSS severity to alert severity."""
        mapping = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "HIGH": AlertSeverity.HIGH,
            "MEDIUM": AlertSeverity.MEDIUM,
            "LOW": AlertSeverity.LOW,
        }
        return mapping.get(cvss_severity.upper(), AlertSeverity.MEDIUM)

    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets the threshold."""
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            severity_idx = order.index(severity.upper())
            threshold_idx = order.index(threshold.upper())
            return severity_idx >= threshold_idx
        except ValueError:
            return False

    def _cve_to_activity(self, cve: CVE) -> Activity:
        """Convert CVE to Activity model."""
        description = f"**{cve.cve_id}** ({cve.severity})\n\n{cve.description[:500]}"
        if cve.score > 0:
            description += f"\n\nCVSS Score: {cve.score}"

        return Activity(
            entity_id=self.config.entity_id,
            activity_type=ActivityType.SECURITY_INCIDENT,
            source="nvd",
            description=description,
            occurred_at=cve.published or datetime.now(UTC),
            source_refs=[f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"],
            metadata={
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "score": cve.score,
                "weaknesses": cve.weaknesses[:5],
                "status": cve.vuln_status,
            },
        )

    def _cve_to_alert(self, cve: CVE) -> Alert:
        """Convert critical CVE to Alert model."""
        return Alert(
            alert_type=AlertType.VULNERABILITY,
            title=f"Critical CVE: {cve.cve_id}",
            description=f"{cve.description[:500]}\n\nCVSS Score: {cve.score}",
            severity=self._severity_to_alert_severity(cve.severity),
            status=AlertStatus.NEW,
            entity_refs=[self.config.entity_id],
            source_refs=[f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"],
            detector_name="nvd_sync",
            confidence=0.95,
            detector_metadata={
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "score": cve.score,
                "weaknesses": cve.weaknesses[:5],
            },
        )

    async def sync(self) -> NVDSyncResult:
        """Sync recent CVEs from NVD.

        Returns:
            NVDSyncResult with sync statistics
        """
        result = NVDSyncResult()

        try:
            log.info(
                "Starting NVD sync",
                lookback_hours=self.config.lookback_hours,
                min_severity=self.config.min_severity,
            )

            # Fetch recent CVEs
            nvd_result = await self._client.get_recent_cves(
                hours=self.config.lookback_hours,
            )
            result.cves_found = nvd_result.total_results

            log.info("NVD fetch complete", cves_found=result.cves_found)

            for cve in nvd_result.cves:
                # Filter by minimum severity
                if not self._meets_severity_threshold(cve.severity, self.config.min_severity):
                    continue

                result.cves_tracked += 1

                # Check for existing activity (deduplication)
                source_ref = f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                existing = await self.activity_repo.exists_by_source_ref(source_ref)

                if existing:
                    continue

                # Create activity
                if self.config.create_activities:
                    activity = self._cve_to_activity(cve)
                    await self.activity_repo.create(activity)
                    result.activities_created += 1

                # Create alert for critical CVEs
                if (
                    self.config.create_alerts
                    and self.alert_repo
                    and self._meets_severity_threshold(cve.severity, self.config.alert_threshold)
                ):
                    alert = self._cve_to_alert(cve)
                    await self.alert_repo.create(alert)
                    result.alerts_created += 1

                    log.info(
                        "Created CVE alert",
                        cve_id=cve.cve_id,
                        severity=cve.severity,
                        score=cve.score,
                    )

        except Exception as e:
            error_msg = f"NVD sync error: {e}"
            result.errors.append(error_msg)
            log.error("NVD sync failed", error=str(e))

        result.completed_at = datetime.now(UTC)

        log.info(
            "NVD sync complete",
            cves_found=result.cves_found,
            cves_tracked=result.cves_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
            duration_seconds=result.duration_seconds,
        )

        return result
