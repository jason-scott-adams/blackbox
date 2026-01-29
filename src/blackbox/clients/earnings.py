"""Earnings calendar client using Finnhub API.

Fetches upcoming and recent earnings announcements for tracked symbols.
API Documentation: https://finnhub.io/docs/api/earnings-calendar
"""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

from blackbox.exceptions import ClientError

log = structlog.get_logger(__name__)


class EarningsConfig(BaseModel):
    """Configuration for the Earnings client."""

    api_key: str = Field(default="", description="Finnhub API key (optional, increases rate limit)")
    base_url: str = Field(default="https://finnhub.io/api/v1")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(default=1.0, description="Delay between requests")
    max_retries: int = Field(default=3, description="Max retry attempts on failure")


class EarningsEvent(BaseModel):
    """An earnings announcement event."""

    symbol: str = Field(description="Stock ticker symbol")
    date: datetime = Field(description="Earnings announcement date")
    hour: str = Field(default="", description="Timing: 'amc' (after close), 'bmo' (before open), 'dmh' (during)")
    quarter: int = Field(default=0, description="Fiscal quarter")
    year: int = Field(default=0, description="Fiscal year")
    eps_estimate: float | None = Field(default=None, description="Estimated EPS")
    eps_actual: float | None = Field(default=None, description="Actual EPS (if reported)")
    revenue_estimate: float | None = Field(default=None, description="Estimated revenue")
    revenue_actual: float | None = Field(default=None, description="Actual revenue (if reported)")
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_upcoming(self) -> bool:
        """Check if this is an upcoming (not yet reported) event."""
        return self.eps_actual is None

    @property
    def has_surprise(self) -> bool:
        """Check if there's an earnings surprise (beat or miss)."""
        if self.eps_actual is None or self.eps_estimate is None:
            return False
        return self.eps_actual != self.eps_estimate

    @property
    def surprise_percent(self) -> float | None:
        """Calculate earnings surprise percentage."""
        if self.eps_actual is None or self.eps_estimate is None or self.eps_estimate == 0:
            return None
        return ((self.eps_actual - self.eps_estimate) / abs(self.eps_estimate)) * 100

    @property
    def is_beat(self) -> bool:
        """Check if earnings beat estimates."""
        pct = self.surprise_percent
        return pct is not None and pct > 0

    @property
    def is_miss(self) -> bool:
        """Check if earnings missed estimates."""
        pct = self.surprise_percent
        return pct is not None and pct < 0

    @property
    def timing_label(self) -> str:
        """Human-readable timing label."""
        labels = {
            "amc": "After Market Close",
            "bmo": "Before Market Open",
            "dmh": "During Market Hours",
        }
        return labels.get(self.hour, "Unknown")


class EarningsSearchResult(BaseModel):
    """Result from earnings calendar search."""

    events: list[EarningsEvent] = Field(default_factory=list)
    from_date: datetime | None = None
    to_date: datetime | None = None
    symbol_filter: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


@dataclass
class EarningsClient:
    """Async client for the Finnhub Earnings Calendar API.

    Usage:
        async with EarningsClient(config) as client:
            result = await client.get_earnings_calendar(days_ahead=7)
            for event in result.events:
                print(f"{event.symbol}: {event.date} ({event.timing_label})")
    """

    config: EarningsConfig = field(default_factory=EarningsConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _last_request_time: float = field(default=0.0, repr=False)

    async def __aenter__(self) -> "EarningsClient":
        """Enter async context."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized."""
        if self._client is None or self._client.is_closed:
            headers = {
                "User-Agent": "BlackBox/0.1.0 (+https://github.com/jason-scott-adams/blackbox)",
            }
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers=headers,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        import time

        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.config.rate_limit_delay:
            await asyncio.sleep(self.config.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    async def _request(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Make a rate-limited request to the Finnhub API."""
        client = await self._ensure_client()
        await self._rate_limit()

        # Add API key if available
        if self.config.api_key:
            params["token"] = self.config.api_key

        url = f"{self.config.base_url}{endpoint}"

        for attempt in range(self.config.max_retries):
            try:
                log.debug("Finnhub API request", endpoint=endpoint, params={k: v for k, v in params.items() if k != "token"}, attempt=attempt + 1)
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 401:
                    raise ClientError(
                        "Finnhub API authentication failed (check API key)",
                        status_code=401,
                    )

                if response.status_code == 429:
                    # Rate limited - exponential backoff
                    if attempt < self.config.max_retries - 1:
                        delay = 30 * (2**attempt)
                        log.warning("Finnhub rate limited, backing off", delay=delay)
                        await asyncio.sleep(delay)
                        continue
                    raise ClientError(
                        "Finnhub API rate limit exceeded after retries",
                        status_code=429,
                        attempts=attempt + 1,
                    )

                if response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.config.max_retries - 1:
                        delay = 5 * (2**attempt)
                        log.warning("Finnhub server error, retrying", status=response.status_code, delay=delay)
                        await asyncio.sleep(delay)
                        continue

                raise ClientError(
                    f"Finnhub API error: {response.status_code}",
                    status_code=response.status_code,
                    response_text=response.text[:500],
                )

            except httpx.RequestError as e:
                if attempt < self.config.max_retries - 1:
                    delay = 5 * (2**attempt)
                    log.warning("Finnhub request error, retrying", error=str(e), delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise ClientError(
                    f"Finnhub API connection error: {e}",
                    original_error=str(e),
                ) from e

        raise ClientError("Finnhub API request failed after all retries")

    def _parse_event(self, data: dict[str, Any]) -> EarningsEvent:
        """Parse earnings event from API response."""
        # Parse date
        date_str = data.get("date", "")
        try:
            date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            date = datetime.now(UTC)

        return EarningsEvent(
            symbol=data.get("symbol", ""),
            date=date,
            hour=data.get("hour", ""),
            quarter=data.get("quarter", 0),
            year=data.get("year", 0),
            eps_estimate=data.get("epsEstimate"),
            eps_actual=data.get("epsActual"),
            revenue_estimate=data.get("revenueEstimate"),
            revenue_actual=data.get("revenueActual"),
            raw_data=data,
        )

    async def get_earnings_calendar(
        self,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        symbol: str | None = None,
        days_ahead: int = 7,
        days_back: int = 0,
    ) -> EarningsSearchResult:
        """Get earnings calendar for a date range.

        Args:
            from_date: Start date (defaults to today - days_back)
            to_date: End date (defaults to today + days_ahead)
            symbol: Filter by specific symbol (optional)
            days_ahead: Days to look ahead (default 7)
            days_back: Days to look back (default 0)

        Returns:
            EarningsSearchResult with matching events
        """
        now = datetime.now(UTC)

        if from_date is None:
            from_date = now - timedelta(days=days_back)
        if to_date is None:
            to_date = now + timedelta(days=days_ahead)

        params: dict[str, Any] = {
            "from": from_date.strftime("%Y-%m-%d"),
            "to": to_date.strftime("%Y-%m-%d"),
        }

        if symbol:
            params["symbol"] = symbol.upper()

        data = await self._request("/calendar/earnings", params)

        events = []
        for item in data.get("earningsCalendar", []):
            try:
                event = self._parse_event(item)
                events.append(event)
            except Exception as e:
                log.warning("Failed to parse earnings event", error=str(e))

        # Sort by date
        events.sort(key=lambda e: e.date)

        return EarningsSearchResult(
            events=events,
            from_date=from_date,
            to_date=to_date,
            symbol_filter=symbol,
        )

    async def get_upcoming_earnings(
        self,
        symbols: list[str] | None = None,
        days_ahead: int = 14,
    ) -> EarningsSearchResult:
        """Get upcoming earnings for tracked symbols.

        Args:
            symbols: List of symbols to track (fetches all if None)
            days_ahead: Days to look ahead (default 14)

        Returns:
            EarningsSearchResult with upcoming events
        """
        result = await self.get_earnings_calendar(days_ahead=days_ahead)

        if symbols:
            symbols_upper = {s.upper() for s in symbols}
            result.events = [e for e in result.events if e.symbol in symbols_upper]

        # Filter to only upcoming (not yet reported)
        result.events = [e for e in result.events if e.is_upcoming]

        return result

    async def get_recent_earnings(
        self,
        symbols: list[str] | None = None,
        days_back: int = 7,
    ) -> EarningsSearchResult:
        """Get recently reported earnings.

        Args:
            symbols: List of symbols to track (fetches all if None)
            days_back: Days to look back (default 7)

        Returns:
            EarningsSearchResult with recent earnings reports
        """
        result = await self.get_earnings_calendar(days_back=days_back, days_ahead=0)

        if symbols:
            symbols_upper = {s.upper() for s in symbols}
            result.events = [e for e in result.events if e.symbol in symbols_upper]

        # Filter to only reported (has actual EPS)
        result.events = [e for e in result.events if not e.is_upcoming]

        return result

    async def get_earnings_for_symbol(self, symbol: str, days: int = 90) -> EarningsSearchResult:
        """Get earnings history and upcoming for a specific symbol.

        Args:
            symbol: Stock ticker symbol
            days: Days to look back and ahead (default 90)

        Returns:
            EarningsSearchResult with earnings for the symbol
        """
        return await self.get_earnings_calendar(
            symbol=symbol,
            days_back=days,
            days_ahead=days,
        )
