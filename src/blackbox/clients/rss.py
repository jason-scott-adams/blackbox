"""RSS feed client for Black Box.

Fetches and parses RSS/Atom feeds from configured news sources.
Includes preconfigured feeds for Kansas City news and tech security.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import feedparser
import httpx
import structlog
from pydantic import BaseModel, Field

log = structlog.get_logger(__name__)


# --- Feed Configuration ---


class FeedConfig(BaseModel):
    """Configuration for a single RSS feed."""

    url: str
    name: str
    category: str = "general"
    enabled: bool = True
    location_keywords: list[str] = Field(default_factory=list)


class RSSConfig(BaseModel):
    """Configuration for RSS client."""

    feeds: list[FeedConfig] = Field(default_factory=list)
    timeout: float = 30.0
    max_entries_per_feed: int = 50
    user_agent: str = "BlackBox/0.1.0 (+https://github.com/atoms/blackbox)"


# --- Feed Data Models ---


class FeedEntry(BaseModel):
    """A single entry from an RSS feed."""

    feed_name: str
    feed_url: str
    category: str
    title: str
    link: str
    published: datetime | None = None
    summary: str = ""
    author: str = ""
    tags: list[str] = Field(default_factory=list)
    location_match: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FeedResult(BaseModel):
    """Result of fetching a single feed."""

    feed_name: str
    feed_url: str
    success: bool
    entries: list[FeedEntry] = Field(default_factory=list)
    error: str | None = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --- Preconfigured Feeds ---

# Kansas City news sources
KC_NEWS_FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://www.kmbc.com/topstories-rss",
        name="KMBC 9 News",
        category="kc_news",
    ),
    FeedConfig(
        url="https://fox4kc.com/feed/",
        name="FOX 4 Kansas City",
        category="kc_news",
    ),
    FeedConfig(
        url="https://www.kcur.org/feed/",
        name="KCUR",
        category="kc_news",
        enabled=False,  # Malformed XML as of 2026-01
    ),
    FeedConfig(
        url="https://www.thepitchkc.com/feed/",
        name="The Pitch KC",
        category="kc_news",
    ),
]

# Kansas City music and arts
KC_MUSIC_FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://www.thepitchkc.com/feed/",
        name="The Pitch KC - Music",
        category="kc_music",
    ),
]

# Location keywords for KC metro area filtering
KC_LOCATION_KEYWORDS: list[str] = [
    "kansas city",
    "kc",
    "kansas",
    "missouri",
    "overland park",
    "olathe",
    "lee's summit",
    "lees summit",
    "independence",
    "shawnee",
    "blue springs",
    "lenexa",
    "merriam",
    "mission",
    "prairie village",
    "leawood",
    "raytown",
    "gladstone",
    "liberty",
    "north kansas city",
    "parkville",
    "riverside",
    "westport",
    "plaza",
    "crossroads",
    "downtown kc",
    "power and light",
    "union station",
    "crown center",
    "brookside",
    "waldo",
    "midtown",
    "hyde park",
    "volker",
    "troost",
    "39th street",
    "18th and vine",
    "jazz district",
    "river market",
    "city market",
    "west bottoms",
    "stockyards",
    "kcmo",
    "joco",
    "johnson county",
    "jackson county",
    "wyandotte",
    "kck",
    "chiefs",
    "royals",
    "sporting kc",
    "arrowhead",
    "kauffman",
    "sprint center",
    "t-mobile center",
    "starlight",
    "kemper",
    "umkc",
    "ku med",
    "rockhurst",
    "avila",
]

# Tech and security feeds
TECH_SECURITY_FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://krebsonsecurity.com/feed/",
        name="Krebs on Security",
        category="security",
    ),
    FeedConfig(
        url="https://www.schneier.com/feed/atom/",
        name="Schneier on Security",
        category="security",
    ),
    FeedConfig(
        url="https://feeds.feedburner.com/TheHackersNews",
        name="The Hacker News",
        category="security",
    ),
    FeedConfig(
        url="https://www.darkreading.com/rss.xml",
        name="Dark Reading",
        category="security",
    ),
    FeedConfig(
        url="https://threatpost.com/feed/",
        name="Threatpost",
        category="security",
        enabled=False,  # Shut down in 2023
    ),
    FeedConfig(
        url="https://www.bleepingcomputer.com/feed/",
        name="Bleeping Computer",
        category="security",
    ),
    FeedConfig(
        url="https://www.wired.com/feed/category/security/latest/rss",
        name="Wired Security",
        category="security",
    ),
    FeedConfig(
        url="https://arstechnica.com/feed/",
        name="Ars Technica",
        category="tech",
    ),
    FeedConfig(
        url="https://news.ycombinator.com/rss",
        name="Hacker News",
        category="tech",
    ),
    FeedConfig(
        url="https://www.techmeme.com/feed.xml",
        name="Techmeme",
        category="tech",
    ),
    FeedConfig(
        url="https://www.theverge.com/rss/index.xml",
        name="The Verge",
        category="tech",
    ),
]

# AI and ML feeds
AI_FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://blog.google/technology/ai/rss/",
        name="Google AI Blog",
        category="ai",
    ),
    FeedConfig(
        url="https://bair.berkeley.edu/blog/feed.xml",
        name="Berkeley AI Research",
        category="ai",
    ),
    FeedConfig(
        url="https://www.deepmind.com/blog/rss.xml",
        name="DeepMind Blog",
        category="ai",
    ),
]

# General news feeds
GENERAL_NEWS_FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://feeds.npr.org/1001/rss.xml",
        name="NPR News",
        category="news",
    ),
    FeedConfig(
        url="https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml",
        name="New York Times",
        category="news",
    ),
    FeedConfig(
        url="https://feeds.washingtonpost.com/rss/national",
        name="Washington Post",
        category="news",
    ),
    FeedConfig(
        url="https://feeds.bbci.co.uk/news/world/rss.xml",
        name="BBC World News",
        category="news",
    ),
]

# Financial feeds
FINANCIAL_FEEDS: list[FeedConfig] = [
    # Major financial news
    FeedConfig(
        url="https://www.cnbc.com/id/100003114/device/rss/rss.html",
        name="CNBC Top News",
        category="finance",
    ),
    FeedConfig(
        url="https://www.cnbc.com/id/10001147/device/rss/rss.html",
        name="CNBC Markets",
        category="finance",
    ),
    FeedConfig(
        url="https://feeds.marketwatch.com/marketwatch/topstories/",
        name="MarketWatch Top Stories",
        category="finance",
    ),
    FeedConfig(
        url="https://feeds.marketwatch.com/marketwatch/marketpulse/",
        name="MarketWatch Market Pulse",
        category="finance",
    ),
    FeedConfig(
        url="https://www.ft.com/rss/home",
        name="Financial Times",
        category="finance",
    ),
    FeedConfig(
        url="https://feeds.bloomberg.com/markets/news.rss",
        name="Bloomberg Markets",
        category="finance",
    ),
    # Crypto and alternative assets
    FeedConfig(
        url="https://cointelegraph.com/rss",
        name="CoinTelegraph",
        category="crypto",
    ),
    FeedConfig(
        url="https://www.coindesk.com/arc/outboundfeeds/rss/",
        name="CoinDesk",
        category="crypto",
    ),
    # Investment analysis
    FeedConfig(
        url="https://seekingalpha.com/feed.xml",
        name="Seeking Alpha",
        category="finance",
    ),
    FeedConfig(
        url="https://www.fool.com/feeds/index.aspx",
        name="Motley Fool",
        category="finance",
    ),
    # Economic data
    FeedConfig(
        url="https://www.federalreserve.gov/feeds/press_all.xml",
        name="Federal Reserve Press",
        category="economics",
    ),
]

# Sector-specific feeds (for position tracking)
SECTOR_FEEDS: dict[str, list[FeedConfig]] = {
    "tech": [
        FeedConfig(
            url="https://www.cnbc.com/id/19854910/device/rss/rss.html",
            name="CNBC Technology",
            category="sector:tech",
        ),
        FeedConfig(
            url="https://feeds.marketwatch.com/marketwatch/software/",
            name="MarketWatch Software",
            category="sector:tech",
        ),
    ],
    "energy": [
        FeedConfig(
            url="https://www.cnbc.com/id/19836768/device/rss/rss.html",
            name="CNBC Energy",
            category="sector:energy",
        ),
        FeedConfig(
            url="https://oilprice.com/rss/main",
            name="OilPrice",
            category="sector:energy",
        ),
    ],
    "healthcare": [
        FeedConfig(
            url="https://www.cnbc.com/id/10000108/device/rss/rss.html",
            name="CNBC Healthcare",
            category="sector:healthcare",
        ),
    ],
    "finance": [
        FeedConfig(
            url="https://www.cnbc.com/id/10000664/device/rss/rss.html",
            name="CNBC Finance",
            category="sector:finance",
        ),
    ],
}

# All feeds combined
ALL_NEWS_FEEDS: list[FeedConfig] = (
    KC_NEWS_FEEDS
    + KC_MUSIC_FEEDS
    + TECH_SECURITY_FEEDS
    + AI_FEEDS
    + GENERAL_NEWS_FEEDS
    + FINANCIAL_FEEDS
)


# --- RSS Client ---


@dataclass
class RSSClient:
    """Client for fetching and parsing RSS feeds."""

    config: RSSConfig = field(default_factory=RSSConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)

    async def __aenter__(self) -> RSSClient:
        """Enter async context."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client exists."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers={"User-Agent": self.config.user_agent},
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch_feed(self, feed_config: FeedConfig) -> FeedResult:
        """Fetch and parse a single RSS feed.

        Args:
            feed_config: Configuration for the feed to fetch

        Returns:
            FeedResult with entries or error
        """
        client = await self._ensure_client()

        try:
            log.debug("Fetching feed", feed=feed_config.name, url=feed_config.url)

            response = await client.get(feed_config.url)
            response.raise_for_status()

            # Parse with feedparser
            parsed = feedparser.parse(response.text)

            if parsed.bozo and parsed.bozo_exception:
                log.warning(
                    "Feed parsing issue",
                    feed=feed_config.name,
                    error=str(parsed.bozo_exception),
                )

            entries = []
            for entry in parsed.entries[: self.config.max_entries_per_feed]:
                feed_entry = self._parse_entry(entry, feed_config)
                if feed_entry:
                    entries.append(feed_entry)

            log.info(
                "Feed fetched",
                feed=feed_config.name,
                entries=len(entries),
            )

            return FeedResult(
                feed_name=feed_config.name,
                feed_url=feed_config.url,
                success=True,
                entries=entries,
            )

        except httpx.HTTPStatusError as e:
            log.error(
                "Feed HTTP error",
                feed=feed_config.name,
                status=e.response.status_code,
            )
            return FeedResult(
                feed_name=feed_config.name,
                feed_url=feed_config.url,
                success=False,
                error=f"HTTP {e.response.status_code}",
            )
        except Exception as e:
            log.error("Feed fetch failed", feed=feed_config.name, error=str(e))
            return FeedResult(
                feed_name=feed_config.name,
                feed_url=feed_config.url,
                success=False,
                error=str(e),
            )

    def _parse_entry(
        self, entry: Any, feed_config: FeedConfig
    ) -> FeedEntry | None:
        """Parse a feedparser entry into FeedEntry.

        Args:
            entry: Feedparser entry object
            feed_config: Feed configuration

        Returns:
            FeedEntry or None if parsing fails
        """
        try:
            # Parse published date
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6])
            elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                published = datetime(*entry.updated_parsed[:6])

            # Extract tags
            tags = []
            if hasattr(entry, "tags"):
                tags = [t.term for t in entry.tags if hasattr(t, "term")]

            # Get summary
            summary = ""
            if hasattr(entry, "summary"):
                summary = entry.summary
            elif hasattr(entry, "description"):
                summary = entry.description

            # Check for location match
            location_match = None
            if feed_config.location_keywords:
                text_to_check = f"{entry.get('title', '')} {summary}".lower()
                for keyword in feed_config.location_keywords:
                    if keyword.lower() in text_to_check:
                        location_match = keyword
                        break

            return FeedEntry(
                feed_name=feed_config.name,
                feed_url=feed_config.url,
                category=feed_config.category,
                title=entry.get("title", ""),
                link=entry.get("link", ""),
                published=published,
                summary=summary[:1000] if summary else "",  # Truncate long summaries
                author=entry.get("author", ""),
                tags=tags,
                location_match=location_match,
                raw_data={
                    "id": entry.get("id", ""),
                    "guid": entry.get("guid", ""),
                },
            )
        except Exception as e:
            log.warning(
                "Failed to parse entry",
                feed=feed_config.name,
                error=str(e),
            )
            return None

    async def fetch_all(
        self,
        feeds: list[FeedConfig] | None = None,
        concurrent_limit: int = 5,
    ) -> list[FeedResult]:
        """Fetch all configured feeds concurrently.

        Args:
            feeds: List of feed configs to fetch (uses config.feeds if None)
            concurrent_limit: Maximum concurrent requests

        Returns:
            List of FeedResults
        """
        feeds_to_fetch = feeds or self.config.feeds
        enabled_feeds = [f for f in feeds_to_fetch if f.enabled]

        log.info("Fetching feeds", count=len(enabled_feeds))

        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(concurrent_limit)

        async def fetch_with_semaphore(feed: FeedConfig) -> FeedResult:
            async with semaphore:
                return await self.fetch_feed(feed)

        results = await asyncio.gather(
            *[fetch_with_semaphore(f) for f in enabled_feeds],
            return_exceptions=True,
        )

        # Convert exceptions to failed results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(
                    FeedResult(
                        feed_name=enabled_feeds[i].name,
                        feed_url=enabled_feeds[i].url,
                        success=False,
                        error=str(result),
                    )
                )
            else:
                final_results.append(result)

        successful = sum(1 for r in final_results if r.success)
        log.info(
            "Feeds fetched",
            total=len(final_results),
            successful=successful,
            failed=len(final_results) - successful,
        )

        return final_results

    async def fetch_url(self, url: str) -> FeedResult:
        """Fetch a single URL as an RSS feed.

        Args:
            url: URL of the RSS feed

        Returns:
            FeedResult
        """
        parsed_url = urlparse(url)
        feed_config = FeedConfig(
            url=url,
            name=parsed_url.netloc,
            category="custom",
        )
        return await self.fetch_feed(feed_config)


# --- Factory Functions ---


def create_kc_news_client() -> RSSClient:
    """Create an RSS client configured for KC news feeds.

    Returns:
        RSSClient configured with KC news feeds and location keywords
    """
    feeds = [
        FeedConfig(
            url=f.url,
            name=f.name,
            category=f.category,
            location_keywords=KC_LOCATION_KEYWORDS,
        )
        for f in KC_NEWS_FEEDS
    ]
    return RSSClient(config=RSSConfig(feeds=feeds))


def create_all_news_client() -> RSSClient:
    """Create an RSS client configured for all news feeds.

    Returns:
        RSSClient configured with all available feeds
    """
    return RSSClient(config=RSSConfig(feeds=ALL_NEWS_FEEDS))
