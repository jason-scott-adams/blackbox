"""SEC EDGAR filings sync service.

Syncs 8-K, 10-K, 10-Q and other SEC filings for tracked companies.
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.sec import MATERIAL_EVENTS, SECClient, SECConfig, SECFiling
from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType

log = structlog.get_logger(__name__)


class SECSyncConfig(BaseModel):
    """Configuration for SEC sync."""

    sec_config: SECConfig = Field(default_factory=SECConfig)
    entity_id: str = "entity:sec_filings"
    days_back: int = Field(default=7, description="Days to look back for filings")
    tracked_companies: list[str] = Field(default_factory=list, description="Companies to track (empty = all)")
    form_types: list[str] = Field(
        default=["8-K", "10-K", "10-Q"],
        description="Form types to track",
    )
    create_activities: bool = True
    create_alerts: bool = True
    alert_on_material: bool = Field(default=True, description="Create alerts for material 8-K filings")
    alert_on_financials: bool = Field(default=True, description="Create alerts for 10-K/10-Q filings")


class SECSyncResult(BaseModel):
    """Result from SEC sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    filings_found: int = 0
    filings_tracked: int = 0
    activities_created: int = 0
    alerts_created: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class SECSyncService:
    """Service for syncing SEC EDGAR filings.

    Usage:
        async with SECSyncService(config, activity_repo, alert_repo) as service:
            result = await service.sync()
    """

    def __init__(
        self,
        config: SECSyncConfig,
        activity_repository: SQLiteActivityRepository,
        alert_repository: SQLiteAlertRepository | None = None,
        client: SECClient | None = None,
    ) -> None:
        self.config = config
        self.activity_repo = activity_repository
        self.alert_repo = alert_repository
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "SECSyncService":
        if self._client is None:
            self._client = SECClient(config=self.config.sec_config)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    def _filing_to_activity(self, filing: SECFiling) -> Activity:
        """Convert SEC filing to Activity model."""
        description = f"**{filing.company_name}** ({filing.ticker or filing.cik})\n\n"
        description += f"Form: {filing.form_type}\n"
        description += f"Filed: {filing.filed_date.strftime('%Y-%m-%d')}\n"

        if filing.items:
            description += "\n**Items:**\n"
            for item in filing.items[:5]:  # Limit to 5 items
                item_desc = MATERIAL_EVENTS.get(item, f"Item {item}")
                description += f"- {item}: {item_desc}\n"

        if filing.description:
            description += f"\n{filing.description[:300]}"

        return Activity(
            entity_id=self.config.entity_id,
            activity_type=ActivityType.FILING,
            source="sec_edgar",
            description=description,
            occurred_at=filing.filed_date,
            source_refs=[f"sec:{filing.accession_number}"],
            metadata={
                "accession_number": filing.accession_number,
                "cik": filing.cik,
                "company_name": filing.company_name,
                "ticker": filing.ticker,
                "form_type": filing.form_type,
                "items": filing.items,
                "is_material": filing.is_material,
                "is_earnings_related": filing.is_earnings_related,
                "sec_url": filing.sec_url,
            },
        )

    def _filing_to_alert(self, filing: SECFiling) -> Alert:
        """Convert material SEC filing to Alert model."""
        if filing.form_type == "8-K":
            title = f"Material Event: {filing.company_name} ({filing.form_type})"
            item_descriptions = filing.item_descriptions
            description = f"{filing.company_name} filed an 8-K with material events:\n"
            for desc in item_descriptions[:3]:
                description += f"- {desc}\n"
            severity = AlertSeverity.HIGH
        else:
            title = f"Financial Filing: {filing.company_name} ({filing.form_type})"
            description = f"{filing.company_name} filed {filing.form_type} on {filing.filed_date.strftime('%Y-%m-%d')}"
            severity = AlertSeverity.MEDIUM

        return Alert(
            alert_type=AlertType.CORPORATE,
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.NEW,
            entity_refs=[self.config.entity_id],
            source_refs=[f"sec:{filing.accession_number}"],
            detector_name="sec_sync",
            confidence=0.95,
            detector_metadata={
                "accession_number": filing.accession_number,
                "company_name": filing.company_name,
                "ticker": filing.ticker,
                "form_type": filing.form_type,
                "items": filing.items,
                "sec_url": filing.sec_url,
            },
        )

    async def sync(self) -> SECSyncResult:
        """Sync SEC filings from EDGAR.

        Returns:
            SECSyncResult with sync statistics
        """
        result = SECSyncResult()

        try:
            log.info(
                "Starting SEC sync",
                days_back=self.config.days_back,
                form_types=self.config.form_types,
                tracked_companies=self.config.tracked_companies[:10] if self.config.tracked_companies else "all",
            )

            # Fetch filings
            if self.config.tracked_companies:
                # Search for specific companies
                all_filings = []
                for company in self.config.tracked_companies:
                    search_result = await self._client.search_filings(
                        company=company,
                        form_types=self.config.form_types,
                        days_back=self.config.days_back,
                    )
                    all_filings.extend(search_result.filings)
                # Deduplicate by accession number
                seen = set()
                filings = []
                for f in all_filings:
                    if f.accession_number not in seen:
                        seen.add(f.accession_number)
                        filings.append(f)
            else:
                search_result = await self._client.search_filings(
                    form_types=self.config.form_types,
                    days_back=self.config.days_back,
                )
                filings = search_result.filings

            result.filings_found = len(filings)
            log.info("SEC fetch complete", filings_found=result.filings_found)

            for filing in filings:
                result.filings_tracked += 1

                # Check for existing activity (deduplication)
                source_ref = f"sec:{filing.accession_number}"
                existing = await self.activity_repo.exists_by_source_ref(source_ref)

                if existing:
                    continue

                # Create activity
                if self.config.create_activities:
                    activity = self._filing_to_activity(filing)
                    await self.activity_repo.create(activity)
                    result.activities_created += 1

                # Create alert for material filings
                should_alert = False
                if self.config.create_alerts and self.alert_repo:
                    if self.config.alert_on_material and filing.form_type == "8-K" and filing.is_material:
                        should_alert = True
                    elif self.config.alert_on_financials and filing.form_type in ("10-K", "10-Q"):
                        should_alert = True

                if should_alert:
                    alert = self._filing_to_alert(filing)
                    await self.alert_repo.create(alert)
                    result.alerts_created += 1

                    log.info(
                        "Created SEC alert",
                        company=filing.company_name,
                        form_type=filing.form_type,
                        items=filing.items[:3] if filing.items else [],
                    )

        except Exception as e:
            error_msg = f"SEC sync error: {e}"
            result.errors.append(error_msg)
            log.error("SEC sync failed", error=str(e))

        result.completed_at = datetime.now(UTC)

        log.info(
            "SEC sync complete",
            filings_found=result.filings_found,
            filings_tracked=result.filings_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
            duration_seconds=result.duration_seconds,
        )

        return result
