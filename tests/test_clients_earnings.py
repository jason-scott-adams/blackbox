"""Tests for the earnings calendar client."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from blackbox.clients.earnings import (
    EarningsClient,
    EarningsConfig,
    EarningsEvent,
    EarningsSearchResult,
)


class TestEarningsEvent:
    """Tests for EarningsEvent model."""

    def test_is_upcoming_true_when_no_actual(self):
        """Event is upcoming when no actual EPS reported."""
        event = EarningsEvent(
            symbol="AAPL",
            date=datetime.now(UTC) + timedelta(days=7),
            eps_estimate=1.50,
            eps_actual=None,
        )
        assert event.is_upcoming is True

    def test_is_upcoming_false_when_actual(self):
        """Event is not upcoming when actual EPS is reported."""
        event = EarningsEvent(
            symbol="AAPL",
            date=datetime.now(UTC) - timedelta(days=1),
            eps_estimate=1.50,
            eps_actual=1.60,
        )
        assert event.is_upcoming is False

    def test_surprise_percent_beat(self):
        """Surprise percent calculated correctly for beat."""
        event = EarningsEvent(
            symbol="AAPL",
            date=datetime.now(UTC),
            eps_estimate=1.00,
            eps_actual=1.10,
        )
        assert event.surprise_percent == pytest.approx(10.0)
        assert event.is_beat is True
        assert event.is_miss is False

    def test_surprise_percent_miss(self):
        """Surprise percent calculated correctly for miss."""
        event = EarningsEvent(
            symbol="AAPL",
            date=datetime.now(UTC),
            eps_estimate=1.00,
            eps_actual=0.90,
        )
        assert event.surprise_percent == pytest.approx(-10.0)
        assert event.is_beat is False
        assert event.is_miss is True

    def test_surprise_percent_none_when_no_data(self):
        """Surprise percent is None when no actual or estimate."""
        event = EarningsEvent(
            symbol="AAPL",
            date=datetime.now(UTC),
        )
        assert event.surprise_percent is None
        assert event.is_beat is False
        assert event.is_miss is False

    def test_timing_labels(self):
        """Timing labels are correct."""
        event = EarningsEvent(symbol="AAPL", date=datetime.now(UTC), hour="amc")
        assert event.timing_label == "After Market Close"

        event = EarningsEvent(symbol="AAPL", date=datetime.now(UTC), hour="bmo")
        assert event.timing_label == "Before Market Open"

        event = EarningsEvent(symbol="AAPL", date=datetime.now(UTC), hour="dmh")
        assert event.timing_label == "During Market Hours"

        event = EarningsEvent(symbol="AAPL", date=datetime.now(UTC), hour="unknown")
        assert event.timing_label == "Unknown"


class TestEarningsConfig:
    """Tests for EarningsConfig."""

    def test_default_config(self):
        """Default config has expected values."""
        config = EarningsConfig()
        assert config.api_key == ""
        assert config.base_url == "https://finnhub.io/api/v1"
        assert config.timeout == 30.0
        assert config.rate_limit_delay == 1.0
        assert config.max_retries == 3

    def test_custom_config(self):
        """Custom config values are set."""
        config = EarningsConfig(api_key="test-key", timeout=60.0)
        assert config.api_key == "test-key"
        assert config.timeout == 60.0


class TestEarningsClient:
    """Tests for EarningsClient."""

    @pytest.fixture
    def client(self):
        """Create a client for testing."""
        return EarningsClient(config=EarningsConfig())

    @pytest.fixture
    def mock_response_data(self):
        """Sample API response data."""
        return {
            "earningsCalendar": [
                {
                    "symbol": "AAPL",
                    "date": "2026-01-28",
                    "hour": "amc",
                    "quarter": 1,
                    "year": 2026,
                    "epsEstimate": 1.50,
                    "epsActual": None,
                    "revenueEstimate": 90000000000,
                    "revenueActual": None,
                },
                {
                    "symbol": "MSFT",
                    "date": "2026-01-27",
                    "hour": "bmo",
                    "quarter": 2,
                    "year": 2026,
                    "epsEstimate": 2.00,
                    "epsActual": 2.10,
                    "revenueEstimate": 50000000000,
                    "revenueActual": 51000000000,
                },
            ]
        }

    @pytest.mark.asyncio
    async def test_context_manager(self, client):
        """Client works as async context manager."""
        async with client as c:
            assert c._client is not None
        assert client._client is None

    @pytest.mark.asyncio
    async def test_parse_event(self, client, mock_response_data):
        """Events are parsed correctly."""
        event = client._parse_event(mock_response_data["earningsCalendar"][0])

        assert event.symbol == "AAPL"
        assert event.date.strftime("%Y-%m-%d") == "2026-01-28"
        assert event.hour == "amc"
        assert event.quarter == 1
        assert event.year == 2026
        assert event.eps_estimate == 1.50
        assert event.eps_actual is None
        assert event.is_upcoming is True

    @pytest.mark.asyncio
    async def test_get_earnings_calendar(self, client, mock_response_data):
        """get_earnings_calendar makes correct request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_ensure.return_value = mock_client

            with patch.object(client, "_rate_limit", new_callable=AsyncMock):
                result = await client.get_earnings_calendar(days_ahead=7)

        assert isinstance(result, EarningsSearchResult)
        assert len(result.events) == 2
        # Events are sorted by date chronologically
        symbols = {e.symbol for e in result.events}
        assert symbols == {"AAPL", "MSFT"}

    @pytest.mark.asyncio
    async def test_get_upcoming_earnings_filters_reported(self, client, mock_response_data):
        """get_upcoming_earnings filters out reported events."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_ensure.return_value = mock_client

            with patch.object(client, "_rate_limit", new_callable=AsyncMock):
                result = await client.get_upcoming_earnings(days_ahead=7)

        # MSFT has actual EPS, so it should be filtered out
        assert len(result.events) == 1
        assert result.events[0].symbol == "AAPL"

    @pytest.mark.asyncio
    async def test_get_upcoming_earnings_filters_by_symbols(self, client, mock_response_data):
        """get_upcoming_earnings filters by tracked symbols."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_ensure.return_value = mock_client

            with patch.object(client, "_rate_limit", new_callable=AsyncMock):
                result = await client.get_upcoming_earnings(
                    symbols=["AAPL"],
                    days_ahead=7,
                )

        # Only AAPL should be returned
        assert len(result.events) == 1
        assert result.events[0].symbol == "AAPL"

    @pytest.mark.asyncio
    async def test_request_handles_rate_limit(self, client):
        """Request handles rate limiting with backoff."""
        mock_429_response = MagicMock()
        mock_429_response.status_code = 429

        mock_200_response = MagicMock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = {"earningsCalendar": []}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.side_effect = [mock_429_response, mock_200_response]
            mock_ensure.return_value = mock_client

            with patch.object(client, "_rate_limit", new_callable=AsyncMock):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await client._request("/calendar/earnings", {})

        assert result == {"earningsCalendar": []}
        assert mock_client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_request_raises_on_auth_error(self, client):
        """Request raises ClientError on authentication failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_ensure.return_value = mock_client

            with patch.object(client, "_rate_limit", new_callable=AsyncMock):
                from blackbox.exceptions import ClientError

                with pytest.raises(ClientError) as exc_info:
                    await client._request("/calendar/earnings", {})

                assert "authentication failed" in str(exc_info.value).lower()
