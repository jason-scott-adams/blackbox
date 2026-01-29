"""Tests for RSS client and sync service."""

from datetime import datetime, UTC
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackbox.clients.rss import (
    ALL_NEWS_FEEDS,
    KC_LOCATION_KEYWORDS,
    KC_NEWS_FEEDS,
    FeedConfig,
    FeedEntry,
    FeedResult,
    RSSClient,
    RSSConfig,
    create_all_news_client,
    create_kc_news_client,
)
from blackbox.sync.rss_sync import (
    RSSSyncConfig,
    RSSSyncResult,
    RSSSyncService,
    create_all_news_sync_service,
    create_kc_news_sync_service,
)


class TestFeedConfig:
    """Tests for FeedConfig model."""

    def test_create_feed_config(self):
        """Test basic feed config creation."""
        config = FeedConfig(
            url="https://example.com/feed.xml",
            name="Example Feed",
            category="test",
        )
        assert config.url == "https://example.com/feed.xml"
        assert config.name == "Example Feed"
        assert config.category == "test"
        assert config.enabled is True
        assert config.location_keywords == []

    def test_feed_config_with_keywords(self):
        """Test feed config with location keywords."""
        config = FeedConfig(
            url="https://example.com/feed.xml",
            name="Local News",
            category="local",
            location_keywords=["kansas city", "kc"],
        )
        assert len(config.location_keywords) == 2
        assert "kansas city" in config.location_keywords


class TestFeedEntry:
    """Tests for FeedEntry model."""

    def test_create_feed_entry(self):
        """Test basic feed entry creation."""
        entry = FeedEntry(
            feed_name="Test Feed",
            feed_url="https://example.com/feed.xml",
            category="test",
            title="Test Article",
            link="https://example.com/article",
            published=datetime.now(UTC),
            summary="This is a test article.",
        )
        assert entry.title == "Test Article"
        assert entry.link == "https://example.com/article"
        assert entry.summary == "This is a test article."

    def test_feed_entry_with_location_match(self):
        """Test feed entry with location match."""
        entry = FeedEntry(
            feed_name="KC News",
            feed_url="https://kc.com/feed.xml",
            category="kc_news",
            title="Kansas City Event",
            link="https://kc.com/event",
            location_match="kansas city",
        )
        assert entry.location_match == "kansas city"


class TestFeedResult:
    """Tests for FeedResult model."""

    def test_successful_result(self):
        """Test successful feed result."""
        result = FeedResult(
            feed_name="Test Feed",
            feed_url="https://example.com/feed.xml",
            success=True,
            entries=[
                FeedEntry(
                    feed_name="Test Feed",
                    feed_url="https://example.com/feed.xml",
                    category="test",
                    title="Article 1",
                    link="https://example.com/1",
                ),
            ],
        )
        assert result.success is True
        assert len(result.entries) == 1
        assert result.error is None

    def test_failed_result(self):
        """Test failed feed result."""
        result = FeedResult(
            feed_name="Test Feed",
            feed_url="https://example.com/feed.xml",
            success=False,
            error="Connection timeout",
        )
        assert result.success is False
        assert result.error == "Connection timeout"
        assert len(result.entries) == 0


class TestRSSConfig:
    """Tests for RSSConfig model."""

    def test_default_config(self):
        """Test default RSS config."""
        config = RSSConfig()
        assert config.feeds == []
        assert config.timeout == 30.0
        assert config.max_entries_per_feed == 50

    def test_config_with_feeds(self):
        """Test config with feeds."""
        feeds = [
            FeedConfig(url="https://a.com/feed", name="A"),
            FeedConfig(url="https://b.com/feed", name="B"),
        ]
        config = RSSConfig(feeds=feeds)
        assert len(config.feeds) == 2


class TestPreconfiguredFeeds:
    """Tests for preconfigured feed lists."""

    def test_kc_news_feeds_exist(self):
        """Test KC news feeds are defined."""
        assert len(KC_NEWS_FEEDS) >= 3  # Some feeds removed due to dead URLs
        for feed in KC_NEWS_FEEDS:
            assert feed.url
            assert feed.name
            assert feed.category == "kc_news"

    def test_kc_location_keywords_exist(self):
        """Test KC location keywords are defined."""
        assert len(KC_LOCATION_KEYWORDS) >= 20
        assert "kansas city" in KC_LOCATION_KEYWORDS
        assert "kc" in KC_LOCATION_KEYWORDS
        assert "overland park" in KC_LOCATION_KEYWORDS

    def test_all_news_feeds_exist(self):
        """Test all news feeds are defined."""
        assert len(ALL_NEWS_FEEDS) >= 20
        categories = {f.category for f in ALL_NEWS_FEEDS}
        assert "security" in categories
        assert "tech" in categories


class TestRSSClient:
    """Tests for RSSClient."""

    def test_create_client(self):
        """Test creating RSS client."""
        client = RSSClient()
        assert client.config.feeds == []
        assert client._client is None

    def test_create_client_with_config(self):
        """Test creating client with config."""
        config = RSSConfig(
            feeds=[FeedConfig(url="https://example.com/feed", name="Test")],
            timeout=60.0,
        )
        client = RSSClient(config=config)
        assert len(client.config.feeds) == 1
        assert client.config.timeout == 60.0

    @pytest.mark.asyncio
    async def test_client_context_manager(self):
        """Test client as async context manager."""
        async with RSSClient() as client:
            assert client._client is not None
        assert client._client is None

    @pytest.mark.asyncio
    async def test_fetch_feed_success(self):
        """Test successful feed fetch."""
        client = RSSClient()

        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.text = """<?xml version="1.0"?>
        <rss version="2.0">
            <channel>
                <title>Test Feed</title>
                <item>
                    <title>Test Article</title>
                    <link>https://example.com/article</link>
                    <description>Test description</description>
                </item>
            </channel>
        </rss>"""
        mock_response.raise_for_status = MagicMock()

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_ensure.return_value = mock_client

            feed_config = FeedConfig(
                url="https://example.com/feed.xml",
                name="Test Feed",
            )
            result = await client.fetch_feed(feed_config)

            assert result.success is True
            assert result.feed_name == "Test Feed"
            assert len(result.entries) == 1
            assert result.entries[0].title == "Test Article"

    @pytest.mark.asyncio
    async def test_fetch_feed_http_error(self):
        """Test feed fetch with HTTP error."""
        import httpx

        client = RSSClient()

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.get.return_value = mock_response
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Not Found", request=MagicMock(), response=mock_response
            )
            mock_ensure.return_value = mock_client

            feed_config = FeedConfig(
                url="https://example.com/feed.xml",
                name="Test Feed",
            )
            result = await client.fetch_feed(feed_config)

            assert result.success is False
            assert "404" in result.error


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_kc_news_client(self):
        """Test creating KC news client."""
        client = create_kc_news_client()
        assert len(client.config.feeds) >= 3  # Some feeds removed due to dead URLs
        for feed in client.config.feeds:
            assert len(feed.location_keywords) > 0

    def test_create_all_news_client(self):
        """Test creating all news client."""
        client = create_all_news_client()
        assert len(client.config.feeds) >= 20


class TestRSSSyncConfig:
    """Tests for RSSSyncConfig model."""

    def test_default_config(self):
        """Test default sync config."""
        config = RSSSyncConfig()
        assert config.feeds == []
        assert config.entity_id == "entity:rss_news"
        assert config.deduplicate is True
        assert config.max_entries_per_sync == 500

    def test_config_with_feeds(self):
        """Test config with feeds."""
        config = RSSSyncConfig(
            feeds=[FeedConfig(url="https://example.com/feed", name="Test")],
            entity_id="entity:test",
        )
        assert len(config.feeds) == 1
        assert config.entity_id == "entity:test"


class TestRSSSyncResult:
    """Tests for RSSSyncResult model."""

    def test_default_result(self):
        """Test default sync result."""
        result = RSSSyncResult()
        assert result.feeds_attempted == 0
        assert result.entries_created == 0
        assert result.completed_at is None

    def test_result_duration(self):
        """Test result duration calculation."""
        result = RSSSyncResult()
        result.completed_at = datetime.now(UTC)
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0


class TestRSSSyncService:
    """Tests for RSSSyncService."""

    def test_create_service(self):
        """Test creating sync service."""
        config = RSSSyncConfig()
        service = RSSSyncService(config=config)
        assert service.config == config
        assert service._client is None

    @pytest.mark.asyncio
    async def test_service_context_manager(self):
        """Test service as async context manager."""
        config = RSSSyncConfig(feeds=[])
        async with RSSSyncService(config=config) as service:
            assert service._client is not None

    def test_create_kc_sync_service(self):
        """Test creating KC sync service."""
        service = create_kc_news_sync_service()
        assert service.config.entity_id == "entity:kc_news"
        assert len(service.config.feeds) >= 3  # Some feeds removed due to dead URLs

    def test_create_all_sync_service(self):
        """Test creating all news sync service."""
        service = create_all_news_sync_service()
        assert service.config.entity_id == "entity:rss_news"
        assert len(service.config.feeds) >= 20


class TestEntryToActivity:
    """Tests for entry to activity conversion."""

    def test_convert_publication_entry(self):
        """Test converting publication entry to activity."""
        config = RSSSyncConfig(entity_id="entity:test")
        service = RSSSyncService(config=config)

        entry = FeedEntry(
            feed_name="Tech News",
            feed_url="https://tech.com/feed",
            category="tech",
            title="New Product Launch",
            link="https://tech.com/product",
            published=datetime.now(UTC),
            summary="A new product was launched today.",
        )

        activity = service._entry_to_activity(entry, "rss:https://tech.com/product")

        assert activity.entity_id == "entity:test"
        assert activity.activity_type.value == "publication"
        assert "New Product Launch" in activity.description
        assert activity.source == "rss:Tech News"
        assert "rss:https://tech.com/product" in activity.source_refs

    def test_convert_security_entry(self):
        """Test converting security entry to activity."""
        config = RSSSyncConfig(entity_id="entity:test")
        service = RSSSyncService(config=config)

        entry = FeedEntry(
            feed_name="Security News",
            feed_url="https://sec.com/feed",
            category="security",
            title="Critical Vulnerability Found",
            link="https://sec.com/vuln",
            published=datetime.now(UTC),
        )

        activity = service._entry_to_activity(entry, "rss:https://sec.com/vuln")

        assert activity.activity_type.value == "security_incident"

    def test_convert_entry_with_location(self):
        """Test converting entry with location match."""
        config = RSSSyncConfig(entity_id="entity:test")
        service = RSSSyncService(config=config)

        entry = FeedEntry(
            feed_name="KC News",
            feed_url="https://kc.com/feed",
            category="kc_news",
            title="Kansas City Event",
            link="https://kc.com/event",
            published=datetime.now(UTC),
            location_match="kansas city",
        )

        activity = service._entry_to_activity(entry, "rss:https://kc.com/event")

        assert activity.metadata.get("location_match") == "kansas city"
