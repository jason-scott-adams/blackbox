"""GitHub Security Advisories sync service.

Syncs security advisories from GitHub Advisory Database and creates activities/alerts.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.github_advisory import (
    GitHubAdvisory,
    GitHubAdvisoryClient,
    GitHubAdvisoryConfig,
)
from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType

log = structlog.get_logger(__name__)


class GitHubSyncConfig(BaseModel):
    """Configuration for GitHub Advisory sync."""

    github_config: GitHubAdvisoryConfig = Field(default_factory=GitHubAdvisoryConfig)
    entity_id: str = "entity:github_advisory"
    lookback_days: int = Field(default=7, description="Days to look back for advisories")
    ecosystems: list[str] = Field(
        default_factory=lambda: ["pip", "npm", "go", "rust"],
        description="Package ecosystems to track",
    )
    min_severity: str = Field(default="medium", description="Minimum severity to track")
    create_activities: bool = True
    create_alerts: bool = True
    alert_threshold: str = Field(default="high", description="Minimum severity for alerts")


class GitHubSyncResult(BaseModel):
    """Result from GitHub Advisory sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    advisories_found: int = 0
    advisories_tracked: int = 0
    activities_created: int = 0
    alerts_created: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class GitHubSyncService:
    """Service for syncing GitHub Security Advisories.

    Usage:
        async with GitHubSyncService(config, activity_repo, alert_repo) as service:
            result = await service.sync()
    """

    def __init__(
        self,
        config: GitHubSyncConfig,
        activity_repository: SQLiteActivityRepository,
        alert_repository: SQLiteAlertRepository | None = None,
        client: GitHubAdvisoryClient | None = None,
    ) -> None:
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "GitHubSyncService":
        if self._client is None:
            self._client = GitHubAdvisoryClient(config=self.config.github_config)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    def _severity_to_alert_severity(self, severity: str) -> AlertSeverity:
        """Map GitHub severity to alert severity."""
        mapping = {
            "critical": AlertSeverity.CRITICAL,
            "high": AlertSeverity.HIGH,
            "medium": AlertSeverity.MEDIUM,
            "low": AlertSeverity.LOW,
        }
        return mapping.get(severity.lower(), AlertSeverity.MEDIUM)

    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets the threshold."""
        order = ["low", "medium", "high", "critical"]
        try:
            severity_idx = order.index(severity.lower())
            threshold_idx = order.index(threshold.lower())
            return severity_idx >= threshold_idx
        except ValueError:
            return False

    def _advisory_to_activity(self, advisory: GitHubAdvisory) -> Activity:
        """Convert GitHub Advisory to Activity model."""
        packages = ", ".join(advisory.affected_packages[:5])
        description = f"**{advisory.ghsa_id}**"
        if advisory.cve_id:
            description += f" ({advisory.cve_id})"
        description += f"\n\n{advisory.summary}"
        if packages:
            description += f"\n\nAffected: {packages}"
        if advisory.cvss_score:
            description += f"\nCVSS: {advisory.cvss_score}"

        return Activity(
            entity_id=self.config.entity_id,
            activity_type=ActivityType.SECURITY_INCIDENT,
            source="github_advisory",
            description=description,
            occurred_at=advisory.published_at or datetime.now(UTC),
            source_refs=[f"https://github.com/advisories/{advisory.ghsa_id}"],
            metadata={
                "ghsa_id": advisory.ghsa_id,
                "cve_id": advisory.cve_id,
                "severity": advisory.severity,
                "cvss_score": advisory.cvss_score,
                "affected_packages": advisory.affected_packages[:10],
            },
        )

    def _advisory_to_alert(self, advisory: GitHubAdvisory) -> Alert:
        """Convert critical advisory to Alert model."""
        packages = ", ".join(advisory.affected_packages[:5])
        description = advisory.summary
        if packages:
            description += f"\n\nAffected packages: {packages}"

        return Alert(
            alert_type=AlertType.VULNERABILITY,
            title=f"Security Advisory: {advisory.ghsa_id}",
            description=description,
            severity=self._severity_to_alert_severity(advisory.severity),
            status=AlertStatus.NEW,
            entity_refs=[self.config.entity_id],
            source_refs=[f"https://github.com/advisories/{advisory.ghsa_id}"],
            detector_name="github_sync",
            confidence=0.95,
            detector_metadata={
                "ghsa_id": advisory.ghsa_id,
                "cve_id": advisory.cve_id,
                "severity": advisory.severity,
                "cvss_score": advisory.cvss_score,
                "affected_packages": advisory.affected_packages[:10],
            },
        )

    async def sync(self) -> GitHubSyncResult:
        """Sync recent advisories from GitHub.

        Returns:
            GitHubSyncResult with sync statistics
        """
        result = GitHubSyncResult()

        try:
            log.info(
                "Starting GitHub Advisory sync",
                lookback_days=self.config.lookback_days,
                ecosystems=self.config.ecosystems,
                min_severity=self.config.min_severity,
            )

            published_since = datetime.now(UTC) - timedelta(days=self.config.lookback_days)

            # Fetch advisories for each ecosystem
            all_advisories: list[GitHubAdvisory] = []

            for ecosystem in self.config.ecosystems:
                try:
                    gh_result = await self._client.list_advisories(
                        ecosystem=ecosystem,
                        published_since=published_since,
                    )
                    all_advisories.extend(gh_result.advisories)
                    log.debug("Fetched ecosystem advisories", ecosystem=ecosystem, count=len(gh_result.advisories))
                except Exception as e:
                    error_msg = f"Failed to fetch {ecosystem} advisories: {e}"
                    result.errors.append(error_msg)
                    log.warning(error_msg)

            result.advisories_found = len(all_advisories)
            log.info("GitHub fetch complete", advisories_found=result.advisories_found)

            # Deduplicate by GHSA ID
            seen_ids: set[str] = set()
            unique_advisories = []
            for advisory in all_advisories:
                if advisory.ghsa_id not in seen_ids:
                    seen_ids.add(advisory.ghsa_id)
                    unique_advisories.append(advisory)

            for advisory in unique_advisories:
                # Filter by minimum severity
                if not self._meets_severity_threshold(advisory.severity, self.config.min_severity):
                    continue

                result.advisories_tracked += 1

                # Check for existing activity (deduplication)
                source_ref = f"https://github.com/advisories/{advisory.ghsa_id}"
                existing = await self.activity_repo.exists_by_source_ref(source_ref)

                if existing:
                    continue

                # Create activity
                if self.config.create_activities:
                    activity = self._advisory_to_activity(advisory)
                    await self.activity_repo.create(activity)
                    result.activities_created += 1

                # Create alert for high/critical advisories
                if (
                    self.config.create_alerts
                    and self.alert_repo
                    and self._meets_severity_threshold(advisory.severity, self.config.alert_threshold)
                ):
                    alert = self._advisory_to_alert(advisory)
                    await self.alert_repo.create(alert)
                    result.alerts_created += 1

                    log.info(
                        "Created advisory alert",
                        ghsa_id=advisory.ghsa_id,
                        severity=advisory.severity,
                    )

        except Exception as e:
            error_msg = f"GitHub sync error: {e}"
            result.errors.append(error_msg)
            log.error("GitHub sync failed", error=str(e))

        result.completed_at = datetime.now(UTC)

        log.info(
            "GitHub Advisory sync complete",
            advisories_found=result.advisories_found,
            advisories_tracked=result.advisories_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
            duration_seconds=result.duration_seconds,
        )

        return result
