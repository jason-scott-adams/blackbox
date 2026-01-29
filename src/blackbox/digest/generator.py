"""Digest generator.

Generates JSON digests summarizing recent Black Box activity
for downstream consumption.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field

from blackbox.models.activity import Activity
from blackbox.models.alert import Alert, AlertSeverity, AlertStatus


class DigestConfig(BaseModel):
    """Configuration for digest generation."""

    output_dir: Annotated[
        Path,
        Field(
            default=Path("./inbox"),
            description="Directory to write digests",
        ),
    ]
    lookback_hours: Annotated[
        int,
        Field(default=24, description="Hours of activity to include"),
    ]
    include_resolved_alerts: Annotated[
        bool,
        Field(default=False, description="Include resolved/dismissed alerts"),
    ]


class DigestItem(BaseModel):
    """A single item in the digest."""

    type: Annotated[str, Field(description="Item type (activity or alert)")]
    title: Annotated[str, Field(description="Item title")]
    description: Annotated[str, Field(description="Item description")]
    source: Annotated[str, Field(description="Data source")]
    timestamp: Annotated[str, Field(description="ISO timestamp")]
    severity: Annotated[str | None, Field(default=None, description="Severity for alerts")]
    metadata: Annotated[dict, Field(default_factory=dict)]
    matches_watches: Annotated[list[str], Field(default_factory=list, description="Watch topics this item matches")]


class DigestFlag(BaseModel):
    """A flag requiring review."""

    title: Annotated[str, Field(description="Flag title")]
    description: Annotated[str, Field(description="Why this needs review")]
    severity: Annotated[str, Field(description="Severity level")]
    alert_id: Annotated[str | None, Field(default=None)]


class FinancialItem(BaseModel):
    """A financial item (earnings, filing, or news)."""

    type: Annotated[str, Field(description="Type: earnings, filing, or news")]
    symbol: Annotated[str | None, Field(default=None, description="Stock ticker")]
    title: Annotated[str, Field(description="Item title")]
    description: Annotated[str, Field(description="Item description")]
    timestamp: Annotated[str, Field(description="ISO timestamp")]
    metadata: Annotated[dict, Field(default_factory=dict)]


class FinancialSection(BaseModel):
    """Financial section of the digest."""

    upcoming_earnings: Annotated[list[FinancialItem], Field(default_factory=list, description="Upcoming earnings events")]
    recent_filings: Annotated[list[FinancialItem], Field(default_factory=list, description="Recent SEC filings")]
    market_news: Annotated[list[FinancialItem], Field(default_factory=list, description="Financial news headlines")]
    summary: Annotated[str, Field(default="", description="Financial highlights summary")]


class Digest(BaseModel):
    """Complete digest output.

    Format:
    - date: YYYY-MM-DD
    - source: domain name
    - summary: one paragraph overview
    - items: list of collected items
    - flags_for_review: items needing attention
    - raw_data_pointers: references to source data
    - financial: financial section with earnings, filings, news
    """

    date: Annotated[str, Field(description="Date in YYYY-MM-DD format")]
    source: Annotated[str, Field(default="blackbox")]
    summary: Annotated[str, Field(description="One paragraph overview")]
    items: Annotated[list[DigestItem], Field(default_factory=list)]
    flags_for_review: Annotated[list[DigestFlag], Field(default_factory=list)]
    raw_data_pointers: Annotated[list[str], Field(default_factory=list)]
    financial: Annotated[FinancialSection | None, Field(default=None, description="Financial section")]


class DigestGenerator:
    """Generates digests from Black Box data."""

    def __init__(
        self,
        config: DigestConfig | None = None,
        watch_topics: list[str] | None = None,
    ) -> None:
        self.config = config or DigestConfig()
        self.watch_topics = [t.lower() for t in (watch_topics or [])]

    def _check_watches(self, text: str) -> list[str]:
        """Check if text matches any watch topics.

        Args:
            text: Text to check (title, description, etc.)

        Returns:
            List of matching watch topics (original case preserved in return)
        """
        if not text or not self.watch_topics:
            return []

        text_lower = text.lower()
        matches = []
        for topic in self.watch_topics:
            if topic in text_lower:
                matches.append(topic)
        return matches

    def generate(
        self,
        activities: list[Activity],
        alerts: list[Alert],
    ) -> Digest:
        """Generate a digest from activities and alerts.

        Args:
            activities: Recent activities to include
            alerts: Recent alerts to include

        Returns:
            Digest ready for output
        """
        now = datetime.now(UTC)
        cutoff = now - timedelta(hours=self.config.lookback_hours)

        # Filter by time window (handle both naive and aware datetimes)
        recent_activities = [
            a for a in activities
            if a.occurred_at and self._is_after_cutoff(a.occurred_at, cutoff)
        ]
        recent_alerts = self._filter_alerts(alerts, cutoff)

        # Convert to digest items
        items = []
        for activity in recent_activities:
            items.append(self._activity_to_item(activity))

        for alert in recent_alerts:
            items.append(self._alert_to_item(alert))

        # Sort by timestamp (most recent first)
        items.sort(key=lambda x: x.timestamp, reverse=True)

        # Generate flags for high-priority alerts
        flags = self._generate_flags(recent_alerts)

        # Generate financial section
        financial = self._generate_financial_section(recent_activities, recent_alerts)

        # Generate summary (including financial highlights)
        summary = self._generate_summary(recent_activities, recent_alerts, flags, financial)

        # Collect raw data pointers
        raw_pointers = self._collect_raw_pointers(recent_activities, recent_alerts)

        return Digest(
            date=now.strftime("%Y-%m-%d"),
            source="blackbox",
            summary=summary,
            items=items,
            flags_for_review=flags,
            raw_data_pointers=raw_pointers,
            financial=financial,
        )

    def _is_after_cutoff(self, dt: datetime, cutoff: datetime) -> bool:
        """Compare datetime with cutoff, handling naive vs aware datetimes."""
        # If datetime is naive, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt >= cutoff

    def _filter_alerts(self, alerts: list[Alert], cutoff: datetime) -> list[Alert]:
        """Filter alerts by time and status."""
        filtered = []
        for alert in alerts:
            if not self._is_after_cutoff(alert.created_at, cutoff):
                continue
            if not self.config.include_resolved_alerts:
                if alert.status in (AlertStatus.RESOLVED, AlertStatus.DISMISSED):
                    continue
            filtered.append(alert)
        return filtered

    def _activity_to_item(self, activity: Activity) -> DigestItem:
        """Convert an activity to a digest item."""
        title = activity.description[:100] if activity.description else f"{activity.activity_type.value} from {activity.source}"
        # Check watches against title and description
        text_to_check = f"{title} {activity.description or ''}"
        matches = self._check_watches(text_to_check)

        # Build metadata with essential fields
        item_metadata = {
            "activity_type": activity.activity_type.value,
            "entity_id": activity.entity_id,
        }

        # Pass through useful metadata fields if present
        if activity.metadata:
            # Link is the most important for UX
            if "link" in activity.metadata:
                item_metadata["link"] = activity.metadata["link"]
            # Feed info for context
            if "feed_name" in activity.metadata:
                item_metadata["feed_name"] = activity.metadata["feed_name"]
            # CVE ID for security items
            if "cve_id" in activity.metadata:
                item_metadata["cve_id"] = activity.metadata["cve_id"]
            # SEC URL for filings
            if "sec_url" in activity.metadata:
                item_metadata["sec_url"] = activity.metadata["sec_url"]

        return DigestItem(
            type="activity",
            title=title,
            description=activity.description,
            source=activity.source,
            timestamp=activity.occurred_at.isoformat() if activity.occurred_at else "",
            metadata=item_metadata,
            matches_watches=matches,
        )

    def _alert_to_item(self, alert: Alert) -> DigestItem:
        """Convert an alert to a digest item."""
        # Check watches against title and description
        text_to_check = f"{alert.title} {alert.description}"
        matches = self._check_watches(text_to_check)

        return DigestItem(
            type="alert",
            title=alert.title,
            description=alert.description,
            source=alert.detector_name,
            timestamp=alert.created_at.isoformat(),
            severity=alert.severity.value,
            metadata={
                "alert_type": alert.alert_type.value,
                "confidence": alert.confidence,
                "status": alert.status.value,
            },
            matches_watches=matches,
        )

    def _generate_flags(self, alerts: list[Alert]) -> list[DigestFlag]:
        """Generate flags for alerts requiring review."""
        flags = []
        for alert in alerts:
            # Flag high/critical alerts and new alerts
            if alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
                flags.append(
                    DigestFlag(
                        title=alert.title,
                        description=f"{alert.severity.value.upper()}: {alert.description[:200]}",
                        severity=alert.severity.value,
                        alert_id=alert.alert_id,
                    )
                )
            elif alert.status == AlertStatus.NEW and alert.confidence >= 0.7:
                flags.append(
                    DigestFlag(
                        title=alert.title,
                        description=f"New alert (confidence: {alert.confidence:.0%}): {alert.description[:200]}",
                        severity=alert.severity.value,
                        alert_id=alert.alert_id,
                    )
                )
        return flags

    def _generate_financial_section(
        self,
        activities: list[Activity],
        alerts: list[Alert],
    ) -> FinancialSection:
        """Generate the financial section of the digest."""
        upcoming_earnings: list[FinancialItem] = []
        recent_filings: list[FinancialItem] = []
        market_news: list[FinancialItem] = []

        # Process activities for financial items
        for activity in activities:
            source = activity.source
            metadata = activity.metadata or {}

            # Earnings events
            if source == "finnhub_earnings":
                symbol = metadata.get("symbol", "")
                is_upcoming = metadata.get("is_upcoming", False)

                if is_upcoming:
                    upcoming_earnings.append(
                        FinancialItem(
                            type="earnings",
                            symbol=symbol,
                            title=f"{symbol} Earnings",
                            description=activity.description[:200] if activity.description else "",
                            timestamp=activity.occurred_at.isoformat() if activity.occurred_at else "",
                            metadata={
                                "date": metadata.get("date"),
                                "eps_estimate": metadata.get("eps_estimate"),
                                "timing": metadata.get("hour"),
                            },
                        )
                    )

            # SEC filings
            elif source == "sec_edgar":
                symbol = metadata.get("ticker", "")
                form_type = metadata.get("form_type", "")

                recent_filings.append(
                    FinancialItem(
                        type="filing",
                        symbol=symbol,
                        title=f"{symbol or metadata.get('company_name', 'Unknown')} - {form_type}",
                        description=activity.description[:200] if activity.description else "",
                        timestamp=activity.occurred_at.isoformat() if activity.occurred_at else "",
                        metadata={
                            "form_type": form_type,
                            "items": metadata.get("items", []),
                            "is_material": metadata.get("is_material", False),
                            "sec_url": metadata.get("sec_url"),
                        },
                    )
                )

            # Financial news from RSS (category = finance or crypto)
            elif source.startswith("rss:"):
                category = metadata.get("category", "")
                if category in ("finance", "crypto", "economics"):
                    market_news.append(
                        FinancialItem(
                            type="news",
                            symbol=None,
                            title=activity.description[:100] if activity.description else "",
                            description=activity.description[:200] if activity.description else "",
                            timestamp=activity.occurred_at.isoformat() if activity.occurred_at else "",
                            metadata={
                                "feed_name": metadata.get("feed_name"),
                                "link": metadata.get("link"),
                                "category": category,
                            },
                        )
                    )

        # Sort items by timestamp
        upcoming_earnings.sort(key=lambda x: x.timestamp)  # Chronological for upcoming
        recent_filings.sort(key=lambda x: x.timestamp, reverse=True)  # Most recent first
        market_news.sort(key=lambda x: x.timestamp, reverse=True)

        # Limit items
        upcoming_earnings = upcoming_earnings[:10]
        recent_filings = recent_filings[:10]
        market_news = market_news[:20]

        # Generate financial summary
        summary_parts = []
        if upcoming_earnings:
            symbols = [e.symbol for e in upcoming_earnings if e.symbol][:5]
            summary_parts.append(f"{len(upcoming_earnings)} upcoming earnings ({', '.join(symbols)})")
        if recent_filings:
            summary_parts.append(f"{len(recent_filings)} SEC filings")
        if market_news:
            summary_parts.append(f"{len(market_news)} financial news items")

        financial_summary = ". ".join(summary_parts) + "." if summary_parts else ""

        return FinancialSection(
            upcoming_earnings=upcoming_earnings,
            recent_filings=recent_filings,
            market_news=market_news,
            summary=financial_summary,
        )

    def _generate_summary(
        self,
        activities: list[Activity],
        alerts: list[Alert],
        flags: list[DigestFlag],
        financial: FinancialSection | None = None,
    ) -> str:
        """Generate a one-paragraph summary."""
        parts = []

        # Activity summary
        if activities:
            sources = {}
            for a in activities:
                sources[a.source] = sources.get(a.source, 0) + 1
            source_summary = ", ".join(f"{count} from {src}" for src, count in sources.items())
            parts.append(f"Collected {len(activities)} activities ({source_summary}).")

        # Alert summary
        if alerts:
            by_severity = {}
            for a in alerts:
                by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            severity_summary = ", ".join(f"{count} {sev}" for sev, count in by_severity.items())
            parts.append(f"Generated {len(alerts)} alerts ({severity_summary}).")

        # Flags summary
        if flags:
            parts.append(f"{len(flags)} item(s) flagged for review.")

        # Financial summary
        if financial and financial.summary:
            parts.append(f"Financial: {financial.summary}")

        if not parts:
            parts.append("No new activity in the lookback window.")

        return " ".join(parts)

    def _collect_raw_pointers(
        self,
        activities: list[Activity],
        alerts: list[Alert],
    ) -> list[str]:
        """Collect references to raw data sources."""
        pointers = set()
        for activity in activities:
            for ref in activity.source_refs:
                pointers.add(ref)
        for alert in alerts:
            for ref in alert.source_refs:
                pointers.add(ref)
        return sorted(pointers)[:50]  # Limit to prevent bloat

    def write_digest(self, digest: Digest, dry_run: bool = False) -> Path | None:
        """Write digest to the output directory.

        Args:
            digest: The digest to write
            dry_run: If True, don't actually write

        Returns:
            Path to written file, or None if dry_run
        """
        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"digest_{timestamp}.json"
        filepath = self.config.output_dir / filename

        if dry_run:
            return None

        # Write digest as JSON
        with open(filepath, "w") as f:
            json.dump(digest.model_dump(), f, indent=2, default=str)

        return filepath
