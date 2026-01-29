"""SEC EDGAR client for corporate filings.

Fetches 8-K, 10-Q, 10-K and other SEC filings for tracked companies.
API Documentation: https://www.sec.gov/search-filings/edgar-full-text-search
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


class SECConfig(BaseModel):
    """Configuration for the SEC EDGAR client."""

    base_url: str = Field(default="https://efts.sec.gov/LATEST/search-index")
    company_search_url: str = Field(default="https://www.sec.gov/cgi-bin/browse-edgar")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(default=0.1, description="SEC asks for 10 requests/sec max")
    max_retries: int = Field(default=3, description="Max retry attempts on failure")
    user_agent: str = Field(
        default="BlackBox/0.1.0 (contact@example.com)",
        description="SEC requires identifying user agent",
    )


class FilingType:
    """Common SEC filing types."""

    FORM_8K = "8-K"  # Current report (material events)
    FORM_10K = "10-K"  # Annual report
    FORM_10Q = "10-Q"  # Quarterly report
    FORM_4 = "4"  # Insider trading
    FORM_13F = "13F"  # Institutional holdings
    FORM_S1 = "S-1"  # IPO registration
    FORM_DEF14A = "DEF 14A"  # Proxy statement


# Material event types in 8-K filings
MATERIAL_EVENTS = {
    "1.01": "Entry into Material Agreement",
    "1.02": "Termination of Material Agreement",
    "1.03": "Bankruptcy or Receivership",
    "2.01": "Acquisition or Disposition of Assets",
    "2.02": "Results of Operations (Earnings)",
    "2.03": "Creation of Direct Financial Obligation",
    "2.04": "Triggering Events Affecting Obligations",
    "2.05": "Exit Activities or Material Impairments",
    "2.06": "Material Impairments",
    "3.01": "Delisting or Transfer",
    "3.02": "Unregistered Sales of Equity",
    "3.03": "Material Modification to Shareholder Rights",
    "4.01": "Changes in Registrant's Certifying Accountant",
    "4.02": "Non-Reliance on Financial Statements",
    "5.01": "Changes in Control",
    "5.02": "Departure of Directors/Officers",
    "5.03": "Amendments to Articles/Bylaws",
    "5.05": "Amendments to Code of Ethics",
    "5.06": "Change in Shell Company Status",
    "5.07": "Submission of Matters to Shareholder Vote",
    "7.01": "Regulation FD Disclosure",
    "8.01": "Other Events",
    "9.01": "Financial Statements and Exhibits",
}


class SECFiling(BaseModel):
    """An SEC filing."""

    accession_number: str = Field(description="Unique filing identifier")
    cik: str = Field(description="Central Index Key (company identifier)")
    company_name: str = Field(default="", description="Company name")
    ticker: str | None = Field(default=None, description="Stock ticker if available")
    form_type: str = Field(description="Filing type (8-K, 10-K, etc.)")
    filed_date: datetime = Field(description="Date filed with SEC")
    accepted_date: datetime | None = Field(default=None, description="Date accepted by SEC")
    description: str = Field(default="", description="Filing description")
    document_url: str = Field(default="", description="URL to primary document")
    index_url: str = Field(default="", description="URL to filing index")
    items: list[str] = Field(default_factory=list, description="8-K item numbers if applicable")
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_material(self) -> bool:
        """Check if this is a potentially material filing."""
        # 8-K filings with certain items are material
        if self.form_type == "8-K":
            material_items = {"1.01", "1.02", "1.03", "2.01", "2.02", "2.05", "4.01", "4.02", "5.01", "5.02"}
            return bool(set(self.items) & material_items)
        # 10-K/10-Q are always material
        return self.form_type in ("10-K", "10-Q")

    @property
    def is_earnings_related(self) -> bool:
        """Check if this filing contains earnings information."""
        if self.form_type == "8-K":
            return "2.02" in self.items
        return self.form_type in ("10-K", "10-Q")

    @property
    def item_descriptions(self) -> list[str]:
        """Get human-readable descriptions of 8-K items."""
        return [MATERIAL_EVENTS.get(item, f"Item {item}") for item in self.items]

    @property
    def sec_url(self) -> str:
        """Get the SEC website URL for this filing."""
        if self.accession_number and self.cik:
            acc_no_dashes = self.accession_number.replace("-", "")
            return f"https://www.sec.gov/Archives/edgar/data/{self.cik}/{acc_no_dashes}/{self.accession_number}-index.htm"
        return self.index_url


class SECSearchResult(BaseModel):
    """Result from SEC filing search."""

    filings: list[SECFiling] = Field(default_factory=list)
    total_results: int = 0
    query: str = ""
    from_date: datetime | None = None
    to_date: datetime | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


@dataclass
class SECClient:
    """Async client for the SEC EDGAR API.

    Usage:
        async with SECClient(config) as client:
            result = await client.search_filings(company="AAPL", form_types=["8-K"])
            for filing in result.filings:
                print(f"{filing.company_name}: {filing.form_type} - {filing.filed_date}")
    """

    config: SECConfig = field(default_factory=SECConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _last_request_time: float = field(default=0.0, repr=False)

    async def __aenter__(self) -> "SECClient":
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
                "User-Agent": self.config.user_agent,
                "Accept": "application/json",
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

    async def _request(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        """Make a rate-limited request to the SEC API."""
        client = await self._ensure_client()
        await self._rate_limit()

        for attempt in range(self.config.max_retries):
            try:
                log.debug("SEC API request", url=url, params=params, attempt=attempt + 1)
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 429:
                    # Rate limited - exponential backoff
                    if attempt < self.config.max_retries - 1:
                        delay = 30 * (2**attempt)
                        log.warning("SEC rate limited, backing off", delay=delay)
                        await asyncio.sleep(delay)
                        continue
                    raise ClientError(
                        "SEC API rate limit exceeded after retries",
                        status_code=429,
                        attempts=attempt + 1,
                    )

                if response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.config.max_retries - 1:
                        delay = 5 * (2**attempt)
                        log.warning("SEC server error, retrying", status=response.status_code, delay=delay)
                        await asyncio.sleep(delay)
                        continue

                raise ClientError(
                    f"SEC API error: {response.status_code}",
                    status_code=response.status_code,
                    response_text=response.text[:500],
                )

            except httpx.RequestError as e:
                if attempt < self.config.max_retries - 1:
                    delay = 5 * (2**attempt)
                    log.warning("SEC request error, retrying", error=str(e), delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise ClientError(
                    f"SEC API connection error: {e}",
                    original_error=str(e),
                ) from e

        raise ClientError("SEC API request failed after all retries")

    def _parse_filing(self, data: dict[str, Any]) -> SECFiling:
        """Parse filing data from SEC API response."""
        # Parse dates
        filed_date = datetime.now(UTC)
        if filed_str := data.get("filed"):
            try:
                filed_date = datetime.strptime(filed_str, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                pass

        accepted_date = None
        if accepted_str := data.get("acceptedDate"):
            try:
                accepted_date = datetime.fromisoformat(accepted_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Extract 8-K items from description
        items = []
        description = data.get("description", "")
        if data.get("form") == "8-K":
            # Items typically listed as "Items 2.02, 9.01" in description
            import re

            item_pattern = re.compile(r"\b(\d+\.\d+)\b")
            items = item_pattern.findall(description)

        return SECFiling(
            accession_number=data.get("accessionNo", ""),
            cik=str(data.get("cik", "")),
            company_name=data.get("companyName", ""),
            ticker=data.get("ticker"),
            form_type=data.get("form", ""),
            filed_date=filed_date,
            accepted_date=accepted_date,
            description=description,
            document_url=data.get("documentUrl", ""),
            index_url=data.get("indexUrl", ""),
            items=items,
            raw_data=data,
        )

    async def search_filings(
        self,
        query: str = "",
        company: str | None = None,
        cik: str | None = None,
        form_types: list[str] | None = None,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        days_back: int = 7,
        max_results: int = 100,
    ) -> SECSearchResult:
        """Search SEC filings.

        Args:
            query: Full-text search query
            company: Company name or ticker to search
            cik: SEC Central Index Key
            form_types: List of form types to filter (e.g., ["8-K", "10-K"])
            from_date: Start date (defaults to days_back)
            to_date: End date (defaults to today)
            days_back: Days to look back (default 7)
            max_results: Maximum results to return

        Returns:
            SECSearchResult with matching filings
        """
        now = datetime.now(UTC)

        if from_date is None:
            from_date = now - timedelta(days=days_back)
        if to_date is None:
            to_date = now

        # Build query
        q_parts = []
        if query:
            q_parts.append(query)
        if company:
            q_parts.append(f'companyName:"{company}" OR ticker:"{company.upper()}"')
        if cik:
            q_parts.append(f"cik:{cik}")
        if form_types:
            forms_q = " OR ".join(f'formType:"{f}"' for f in form_types)
            q_parts.append(f"({forms_q})")

        full_query = " AND ".join(q_parts) if q_parts else "*"

        params = {
            "q": full_query,
            "dateRange": "custom",
            "startdt": from_date.strftime("%Y-%m-%d"),
            "enddt": to_date.strftime("%Y-%m-%d"),
            "from": 0,
            "size": max_results,
        }

        data = await self._request(self.config.base_url, params)

        filings = []
        for hit in data.get("hits", {}).get("hits", []):
            try:
                source = hit.get("_source", {})
                filing = self._parse_filing(source)
                filings.append(filing)
            except Exception as e:
                log.warning("Failed to parse SEC filing", error=str(e))

        return SECSearchResult(
            filings=filings,
            total_results=data.get("hits", {}).get("total", {}).get("value", 0),
            query=full_query,
            from_date=from_date,
            to_date=to_date,
        )

    async def get_recent_8k_filings(
        self,
        companies: list[str] | None = None,
        days_back: int = 7,
    ) -> SECSearchResult:
        """Get recent 8-K filings (material events).

        Args:
            companies: List of company names/tickers to filter
            days_back: Days to look back (default 7)

        Returns:
            SECSearchResult with 8-K filings
        """
        if companies:
            # Search for multiple companies
            all_filings = []
            for company in companies:
                result = await self.search_filings(
                    company=company,
                    form_types=["8-K"],
                    days_back=days_back,
                )
                all_filings.extend(result.filings)
            # Sort by date
            all_filings.sort(key=lambda f: f.filed_date, reverse=True)
            return SECSearchResult(
                filings=all_filings,
                total_results=len(all_filings),
                query="8-K filings",
            )
        else:
            return await self.search_filings(form_types=["8-K"], days_back=days_back)

    async def get_recent_financials(
        self,
        companies: list[str] | None = None,
        days_back: int = 30,
    ) -> SECSearchResult:
        """Get recent 10-K and 10-Q filings (financial statements).

        Args:
            companies: List of company names/tickers to filter
            days_back: Days to look back (default 30)

        Returns:
            SECSearchResult with 10-K and 10-Q filings
        """
        if companies:
            all_filings = []
            for company in companies:
                result = await self.search_filings(
                    company=company,
                    form_types=["10-K", "10-Q"],
                    days_back=days_back,
                )
                all_filings.extend(result.filings)
            all_filings.sort(key=lambda f: f.filed_date, reverse=True)
            return SECSearchResult(
                filings=all_filings,
                total_results=len(all_filings),
                query="10-K/10-Q filings",
            )
        else:
            return await self.search_filings(form_types=["10-K", "10-Q"], days_back=days_back)

    async def get_insider_trades(
        self,
        companies: list[str] | None = None,
        days_back: int = 7,
    ) -> SECSearchResult:
        """Get recent Form 4 filings (insider trading).

        Args:
            companies: List of company names/tickers to filter
            days_back: Days to look back (default 7)

        Returns:
            SECSearchResult with Form 4 filings
        """
        if companies:
            all_filings = []
            for company in companies:
                result = await self.search_filings(
                    company=company,
                    form_types=["4"],
                    days_back=days_back,
                )
                all_filings.extend(result.filings)
            all_filings.sort(key=lambda f: f.filed_date, reverse=True)
            return SECSearchResult(
                filings=all_filings,
                total_results=len(all_filings),
                query="Form 4 filings",
            )
        else:
            return await self.search_filings(form_types=["4"], days_back=days_back)

    async def get_company_filings(
        self,
        company: str,
        form_types: list[str] | None = None,
        days_back: int = 90,
    ) -> SECSearchResult:
        """Get all filings for a specific company.

        Args:
            company: Company name or ticker
            form_types: Filter by form types (optional)
            days_back: Days to look back (default 90)

        Returns:
            SECSearchResult with company filings
        """
        return await self.search_filings(
            company=company,
            form_types=form_types,
            days_back=days_back,
        )
