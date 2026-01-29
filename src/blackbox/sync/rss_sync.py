"""RSS sync service for Black Box.

Fetches RSS feeds and creates Activity records from entries.
Handles deduplication to avoid re-processing the same articles.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import structlog
from pydantic import BaseModel, Field

from blackbox.clients.rss import (
    ALL_NEWS_FEEDS,
    KC_LOCATION_KEYWORDS,
    KC_NEWS_FEEDS,
    FeedConfig,
    FeedEntry,
    FeedResult,
    RSSClient,
    RSSConfig,
)
from blackbox.db.repositories import SQLiteActivityRepository
from blackbox.db.session import get_session
from blackbox.models.activity import Activity, ActivityType

log = structlog.get_logger(__name__)


class RSSSyncConfig(BaseModel):
    """Configuration for RSS sync service."""

    feeds: list[FeedConfig] = Field(default_factory=list)
    entity_id: str = "entity:rss_news"
    deduplicate: bool = True
    max_entries_per_sync: int = 500


class RSSSyncResult(BaseModel):
    """Result of an RSS sync operation."""

    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    feeds_attempted: int = 0
    feeds_succeeded: int = 0
    feeds_failed: int = 0
    entries_found: int = 0
    entries_created: int = 0
    entries_skipped: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class RSSSyncService:
    """Service for syncing RSS feeds to activities.

    Fetches configured RSS feeds, converts entries to Activity records,
    and stores them in the database with deduplication.
    """

    def __init__(
        self,
        config: RSSSyncConfig,
        client: RSSClient | None = None,
    ) -> None:
        """Initialize RSS sync service.

        Args:
            config: Sync configuration
            client: Optional RSSClient (created if not provided)
        """
        self.config = config
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> RSSSyncService:
        """Enter async context."""
        if self._client is None:
            self._client = RSSClient(
                config=RSSConfig(feeds=self.config.feeds)
            )
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        """Exit async context."""
        if self._owns_client and self._client:
            await self._client.__aexit__(*args)

    async def sync(self) -> RSSSyncResult:
        """Run a full RSS sync.

        Fetches all configured feeds and creates Activity records
        for new entries.

        Returns:
            RSSSyncResult with sync statistics
        """
        result = RSSSyncResult()

        if not self._client:
            result.errors.append("Client not initialized")
            result.completed_at = datetime.now(UTC)
            return result

        log.info(
            "Starting RSS sync",
            feeds=len(self.config.feeds),
            entity_id=self.config.entity_id,
        )

        # Fetch all feeds
        feed_results = await self._client.fetch_all(
            feeds=self.config.feeds,
            concurrent_limit=5,
        )

        result.feeds_attempted = len(feed_results)

        # Process results
        all_entries: list[FeedEntry] = []
        for feed_result in feed_results:
            if feed_result.success:
                result.feeds_succeeded += 1
                all_entries.extend(feed_result.entries)
            else:
                result.feeds_failed += 1
                if feed_result.error:
                    result.errors.append(
                        f"{feed_result.feed_name}: {feed_result.error}"
                    )

        result.entries_found = len(all_entries)

        # Limit entries per sync
        if len(all_entries) > self.config.max_entries_per_sync:
            log.warning(
                "Truncating entries",
                found=len(all_entries),
                limit=self.config.max_entries_per_sync,
            )
            all_entries = all_entries[: self.config.max_entries_per_sync]

        # Convert to activities and store
        activities_to_create: list[Activity] = []

        async with get_session() as session:
            repo = SQLiteActivityRepository(session)

            for entry in all_entries:
                # Generate source ref from entry link for deduplication
                source_ref = f"rss:{entry.link}"

                # Check for duplicates
                if self.config.deduplicate:
                    exists = await repo.exists_by_source_ref(source_ref)
                    if exists:
                        result.entries_skipped += 1
                        continue

                # Create activity from entry
                activity = self._entry_to_activity(entry, source_ref)
                activities_to_create.append(activity)

            # Bulk create activities
            if activities_to_create:
                await repo.create_many(activities_to_create)
                result.entries_created = len(activities_to_create)

        result.completed_at = datetime.now(UTC)

        log.info(
            "RSS sync complete",
            feeds_succeeded=result.feeds_succeeded,
            feeds_failed=result.feeds_failed,
            entries_created=result.entries_created,
            entries_skipped=result.entries_skipped,
            duration_seconds=result.duration_seconds,
        )

        return result

    def _entry_to_activity(
        self,
        entry: FeedEntry,
        source_ref: str,
    ) -> Activity:
        """Convert a FeedEntry to an Activity.

        Args:
            entry: RSS feed entry
            source_ref: Unique source reference for deduplication

        Returns:
            Activity record
        """
        # Determine activity type based on category
        activity_type = ActivityType.PUBLICATION
        if entry.category in ("security", "vulnerability"):
            activity_type = ActivityType.SECURITY_INCIDENT

        # Build description
        description = entry.title
        if entry.summary:
            # Truncate summary for description
            summary_preview = entry.summary[:200]
            if len(entry.summary) > 200:
                summary_preview += "..."
            description = f"{entry.title}\n\n{summary_preview}"

        # Build metadata
        metadata = {
            "feed_name": entry.feed_name,
            "feed_url": entry.feed_url,
            "category": entry.category,
            "link": entry.link,
            "author": entry.author,
            "tags": entry.tags,
        }
        if entry.location_match:
            metadata["location_match"] = entry.location_match

        return Activity(
            id=uuid4(),
            entity_id=self.config.entity_id,
            activity_type=activity_type,
            source=f"rss:{entry.feed_name}",
            description=description,
            occurred_at=entry.published or datetime.now(UTC),
            source_refs=[source_ref],
            metadata=metadata,
        )


# --- Factory Functions ---


def create_kc_news_sync_service() -> RSSSyncService:
    """Create sync service for KC news feeds.

    Returns:
        RSSSyncService configured for KC news
    """
    # Add location keywords to KC feeds for filtering
    feeds = [
        FeedConfig(
            url=f.url,
            name=f.name,
            category=f.category,
            location_keywords=KC_LOCATION_KEYWORDS,
        )
        for f in KC_NEWS_FEEDS
    ]

    config = RSSSyncConfig(
        feeds=feeds,
        entity_id="entity:kc_news",
    )

    return RSSSyncService(config=config)


def create_all_news_sync_service() -> RSSSyncService:
    """Create sync service for all news feeds.

    Returns:
        RSSSyncService configured for all feeds
    """
    config = RSSSyncConfig(
        feeds=ALL_NEWS_FEEDS,
        entity_id="entity:rss_news",
    )

    return RSSSyncService(config=config)
