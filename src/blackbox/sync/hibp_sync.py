"""Have I Been Pwned synchronization service.

Syncs breach data from HIBP into Black Box's activity and alert stores.
Creates activities for each breach found, and alerts for new exposures.

Supports pluggable breach clients via Protocol:
- HIBPClient: Official HIBP API (paid, comprehensive)
- Custom clients implementing BreachClient protocol
"""

from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

import structlog
from pydantic import BaseModel, ConfigDict, Field

from blackbox.clients.base import BreachClient
from blackbox.clients.hibp import Breach, HIBPClient, HIBPConfig
from blackbox.models import Activity, Alert
from blackbox.models.activity import ActivityType
from blackbox.models.alert import AlertSeverity, AlertStatus, AlertType
from blackbox.utils.datetime import utc_now

logger = structlog.get_logger()


class HIBPSyncConfig(BaseModel):
    """Configuration for HIBP sync.

    Supports pluggable breach clients. Provide either:
    1. hibp_config (for HIBP client) + client_factory=None (uses default)
    2. client_factory (for custom client implementation)

    If both are provided, client_factory takes precedence.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    hibp_config: HIBPConfig | None = Field(
        default=None,
        description="HIBP client configuration (optional, uses default if client_factory not provided)",
    )

    client_factory: Callable[[], BreachClient] | None = Field(
        default=None,
        description="Factory function to create breach client instance",
    )

    # Emails to monitor
    emails: list[str] = Field(
        default_factory=list,
        description="Email addresses to check for breaches",
    )

    # Sync settings
    create_activities: bool = Field(
        default=True,
        description="Create activities from breach data",
    )
    create_alerts: bool = Field(
        default=True,
        description="Create alerts for new breaches",
    )
    include_unverified: bool = Field(
        default=True,
        description="Include unverified breaches in results",
    )


class HIBPSyncResult(BaseModel):
    """Result of an HIBP sync operation."""

    sync_id: str = Field(description="Unique ID for this sync run")
    started_at: datetime = Field(description="When sync started")
    completed_at: datetime | None = Field(default=None, description="When sync completed")

    # Counts
    emails_checked: int = Field(default=0, description="Number of emails checked")
    breaches_found: int = Field(default=0, description="Total breaches found")
    new_breaches: int = Field(default=0, description="New breaches not seen before")
    activities_created: int = Field(default=0, description="Activities created")
    alerts_created: int = Field(default=0, description="Alerts created")
    pastes_found: int = Field(default=0, description="Pastes containing email")

    # Details
    breaches_by_email: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Breaches per email address",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Error messages encountered during sync",
    )


class HIBPSyncService:
    """Service for syncing breach data to Black Box.

    Checks configured email addresses against a breach database.
    Creates activities for each breach and alerts for new exposures.

    Supports multiple breach clients via BreachClient protocol:
    - HIBPClient: Official Have I Been Pwned API (paid)
    - Custom implementations of BreachClient protocol

    Example usage with HIBP (default):
        sync_service = HIBPSyncService(
            config=HIBPSyncConfig(
                hibp_config=HIBPConfig(api_key="your-key"),
                emails=["user@example.com"],
            ),
            activity_repository=storage.activities,
            alert_repository=storage.alerts,
        )

        result = await sync_service.sync()
    """

    def __init__(
        self,
        config: HIBPSyncConfig,
        activity_repository: Any,
        alert_repository: Any | None = None,
    ) -> None:
        """Initialize the sync service.

        Args:
            config: Sync configuration with hibp_config or client_factory
            activity_repository: Repository for storing activities
            alert_repository: Repository for storing alerts (optional)

        Raises:
            ValueError: If neither hibp_config nor client_factory provided
        """
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client: BreachClient | None = None
        self._seen_breaches: dict[str, set[str]] = {}  # email -> set of breach names

    async def _get_client(self) -> BreachClient:
        """Get or create breach client.

        Uses client_factory if provided, otherwise creates HIBPClient from hibp_config.
        """
        if self._client is None:
            if self.config.client_factory:
                self._client = self.config.client_factory()
            elif self.config.hibp_config:
                self._client = HIBPClient(self.config.hibp_config)
            else:
                raise ValueError(
                    "HIBPSyncConfig must provide either client_factory or hibp_config"
                )
        return self._client

    async def close(self) -> None:
        """Close the HIBP client connection."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> "HIBPSyncService":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Async context manager exit."""
        await self.close()

    async def check_connection(self) -> bool:
        """Check if HIBP API is reachable.

        Returns:
            True if connection is healthy
        """
        try:
            client = await self._get_client()
            # Try to list breaches as a health check
            await client.list_breaches()
            return True
        except Exception as e:
            logger.warning("HIBP connection check failed", error=str(e))
            return False

    async def load_seen_breaches(self) -> None:
        """Load previously seen breaches from activity repository.

        Call this before sync() to enable tracking of new vs known breaches.
        """
        try:
            # Search for activities created by this sync service
            activities = await self.activity_repo.list(
                source="hibp_sync",
                limit=10000,
            )
            for activity in activities:
                if "email" in activity.metadata and "breach_name" in activity.metadata:
                    email = activity.metadata["email"]
                    breach_name = activity.metadata["breach_name"]
                    if email not in self._seen_breaches:
                        self._seen_breaches[email] = set()
                    self._seen_breaches[email].add(breach_name)

            total = sum(len(b) for b in self._seen_breaches.values())
            logger.debug(
                "Loaded seen HIBP breaches",
                emails=len(self._seen_breaches),
                total_breaches=total,
            )
        except Exception as e:
            logger.warning("Failed to load seen breaches", error=str(e))

    def _is_new_breach(self, email: str, breach_name: str) -> bool:
        """Check if a breach is new for an email."""
        if email not in self._seen_breaches:
            return True
        return breach_name not in self._seen_breaches[email]

    def _mark_breach_seen(self, email: str, breach_name: str) -> None:
        """Mark a breach as seen for an email."""
        if email not in self._seen_breaches:
            self._seen_breaches[email] = set()
        self._seen_breaches[email].add(breach_name)

    async def sync(self) -> HIBPSyncResult:
        """Sync all configured emails.

        Returns:
            Sync result with counts and any errors
        """
        sync_id = f"hibp_sync_{uuid4().hex[:12]}"

        result = HIBPSyncResult(
            sync_id=sync_id,
            started_at=utc_now(),
        )

        if not self.config.emails:
            result.errors.append("No email addresses configured")
            result.completed_at = utc_now()
            return result

        logger.info(
            "Starting HIBP sync",
            sync_id=sync_id,
            emails=len(self.config.emails),
        )

        try:
            # Load previously seen breaches for tracking new ones
            await self.load_seen_breaches()

            # Check each email
            client = await self._get_client()

            for email in self.config.emails:
                try:
                    await self._check_email(client, email, result)
                    result.emails_checked += 1
                except Exception as e:
                    error_msg = f"Failed to check {email}: {e}"
                    result.errors.append(error_msg)
                    logger.warning(error_msg)

        except Exception as e:
            error_msg = f"Sync failed: {e}"
            result.errors.append(error_msg)
            logger.error("HIBP sync failed", sync_id=sync_id, error=str(e))

        result.completed_at = utc_now()

        logger.info(
            "HIBP sync completed",
            sync_id=sync_id,
            emails_checked=result.emails_checked,
            breaches_found=result.breaches_found,
            new_breaches=result.new_breaches,
            alerts_created=result.alerts_created,
        )

        return result

    async def sync_single_email(self, email: str) -> HIBPSyncResult:
        """Sync a single email address.

        Args:
            email: Email address to check

        Returns:
            Sync result
        """
        sync_id = f"hibp_sync_{uuid4().hex[:12]}"

        result = HIBPSyncResult(
            sync_id=sync_id,
            started_at=utc_now(),
        )

        logger.info(
            "Starting single email HIBP sync",
            sync_id=sync_id,
            email=email[:3] + "***",  # Partial redaction
        )

        try:
            await self.load_seen_breaches()

            client = await self._get_client()
            await self._check_email(client, email, result)
            result.emails_checked = 1

        except Exception as e:
            error_msg = f"Sync failed: {e}"
            result.errors.append(error_msg)
            logger.error("HIBP sync failed", sync_id=sync_id, error=str(e))

        result.completed_at = utc_now()
        return result

    async def _check_email(
        self,
        client: BreachClient,
        email: str,
        result: HIBPSyncResult,
    ) -> None:
        """Check a single email for breaches.

        Args:
            client: HIBP client
            email: Email address to check
            result: Sync result to update
        """
        # Check breaches
        breaches = await client.check_email(
            email,
            truncate_response=False,
            include_unverified=self.config.include_unverified,
        )

        result.breaches_by_email[email] = [b.name for b in breaches]
        result.breaches_found += len(breaches)

        for breach in breaches:
            is_new = self._is_new_breach(email, breach.name)
            if is_new:
                result.new_breaches += 1

            # Create activity
            if self.config.create_activities:
                await self._create_activity(email, breach, result)

            # Create alert for new breaches
            if is_new and self.config.create_alerts and self.alert_repo:
                await self._create_alert(email, breach, result)

            self._mark_breach_seen(email, breach.name)

        # Also check pastes
        try:
            pastes = await client.check_pastes(email)
            result.pastes_found += len(pastes)
        except Exception:
            # Pastes may not be available for all API tiers
            pass

    async def _create_activity(
        self,
        email: str,
        breach: Breach,
        result: HIBPSyncResult,
    ) -> None:
        """Create an activity from a breach finding.

        Args:
            email: Email address
            breach: Breach data
            result: Sync result to update
        """
        # Mask email for privacy in description
        masked_email = email[:3] + "***@" + email.split("@")[-1]

        activity = Activity(
            entity_id=f"hibp:{email.replace('@', '_at_')}",
            activity_type=ActivityType.DATA_BREACH,
            source="hibp_sync",
            description=f"Breach detected: {masked_email} found in {breach.title}",
            occurred_at=breach.breach_datetime or utc_now(),
            source_refs=[f"https://haveibeenpwned.com/PwnedWebsites#{breach.name}"],
            metadata={
                "email": email,
                "breach_name": breach.name,
                "breach_title": breach.title,
                "breach_domain": breach.domain,
                "breach_date": breach.breach_date,
                "pwn_count": breach.pwn_count,
                "data_classes": breach.data_classes,
                "is_verified": breach.is_verified,
                "exposed_passwords": breach.exposed_passwords,
            },
        )

        await self.activity_repo.create(activity)
        result.activities_created += 1

        logger.debug(
            "Created activity from HIBP breach",
            breach=breach.name,
            email=masked_email,
        )

    async def _create_alert(
        self,
        email: str,
        breach: Breach,
        result: HIBPSyncResult,
    ) -> None:
        """Create an alert for a new breach finding.

        Args:
            email: Email address
            breach: Breach data
            result: Sync result to update
        """
        # Determine severity based on what was exposed
        if breach.exposed_passwords:
            severity = AlertSeverity.CRITICAL
        elif "Social security numbers" in breach.data_classes:
            severity = AlertSeverity.CRITICAL
        elif any(
            c in breach.data_classes
            for c in ["Credit cards", "Bank account numbers", "Financial data"]
        ):
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM

        masked_email = email[:3] + "***@" + email.split("@")[-1]

        alert = Alert(
            alert_type=AlertType.BREACH,
            title=f"Credential Exposure: {breach.title}",
            description=(
                f"Email address {masked_email} was found in the {breach.title} data breach. "
                f"This breach occurred on {breach.breach_date} and affected {breach.pwn_count:,} accounts. "
                f"Exposed data types: {', '.join(breach.data_classes)}."
            ),
            severity=severity,
            status=AlertStatus.NEW,
            entity_refs=[f"hibp:{email.replace('@', '_at_')}"],
            source_refs=[f"https://haveibeenpwned.com/PwnedWebsites#{breach.name}"],
            detector_name="hibp_sync",
            detector_metadata={
                "email": email,
                "breach_name": breach.name,
                "data_classes": breach.data_classes,
                "is_verified": breach.is_verified,
                "breach_date": breach.breach_date,
                "pwn_count": breach.pwn_count,
                "exposed_passwords": breach.exposed_passwords,
            },
            confidence=0.95 if breach.is_verified else 0.7,
        )

        await self.alert_repo.create(alert)
        result.alerts_created += 1

        logger.info(
            "Created alert for HIBP breach",
            breach=breach.name,
            severity=severity.value,
        )


# Global sync service instance
_hibp_sync_service: HIBPSyncService | None = None


def get_hibp_sync_service() -> HIBPSyncService | None:
    """Get the global HIBP sync service instance."""
    return _hibp_sync_service


def set_hibp_sync_service(service: HIBPSyncService | None) -> None:
    """Set the global HIBP sync service instance."""
    global _hibp_sync_service
    _hibp_sync_service = service
