"""NVD (National Vulnerability Database) client for CVE monitoring.

Uses the NVD API 2.0 to fetch CVE data.
API Documentation: https://nvd.nist.gov/developers/vulnerabilities
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


class NVDConfig(BaseModel):
    """Configuration for the NVD client."""

    api_key: str = Field(default="", description="NVD API key (optional, but increases rate limit)")
    base_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(
        default=6.0,
        description="Delay between requests (6s without key, 0.6s with key)",
    )
    max_retries: int = Field(default=3, description="Max retry attempts on failure")
    results_per_page: int = Field(default=100, description="Results per API page (max 2000)")


class CVSSData(BaseModel):
    """CVSS score data."""

    version: str = ""
    vector_string: str = ""
    base_score: float = 0.0
    base_severity: str = ""


class CVE(BaseModel):
    """CVE vulnerability data from NVD."""

    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-12345)")
    source_identifier: str = ""
    published: datetime | None = None
    last_modified: datetime | None = None
    vuln_status: str = ""
    descriptions: list[str] = Field(default_factory=list)
    cvss_v31: CVSSData | None = None
    cvss_v2: CVSSData | None = None
    weaknesses: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def severity(self) -> str:
        """Get the highest severity from available CVSS scores."""
        if self.cvss_v31 and self.cvss_v31.base_severity:
            return self.cvss_v31.base_severity.upper()
        if self.cvss_v2 and self.cvss_v2.base_severity:
            return self.cvss_v2.base_severity.upper()
        return "UNKNOWN"

    @property
    def score(self) -> float:
        """Get the highest score from available CVSS data."""
        if self.cvss_v31:
            return self.cvss_v31.base_score
        if self.cvss_v2:
            return self.cvss_v2.base_score
        return 0.0

    @property
    def description(self) -> str:
        """Get the first English description."""
        for desc in self.descriptions:
            return desc
        return ""

    @property
    def is_critical(self) -> bool:
        """Check if this is a critical severity CVE."""
        return self.severity == "CRITICAL"

    @property
    def is_high(self) -> bool:
        """Check if this is high severity or above."""
        return self.severity in ("CRITICAL", "HIGH")


class NVDSearchResult(BaseModel):
    """Result from NVD CVE search."""

    total_results: int = 0
    results_per_page: int = 0
    start_index: int = 0
    cves: list[CVE] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


@dataclass
class NVDClient:
    """Async client for the NVD API 2.0.

    Usage:
        async with NVDClient(config) as client:
            result = await client.search_cves(keyword="apache")
            for cve in result.cves:
                print(f"{cve.cve_id}: {cve.severity}")
    """

    config: NVDConfig = field(default_factory=NVDConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _last_request_time: float = field(default=0.0, repr=False)

    async def __aenter__(self) -> "NVDClient":
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
                "User-Agent": "BlackBox/0.1.0 (+https://github.com/atoms/blackbox)",
            }
            if self.config.api_key:
                headers["apiKey"] = self.config.api_key
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
        # With API key: 0.6s delay, without: 6s delay
        delay = 0.6 if self.config.api_key else self.config.rate_limit_delay
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self._last_request_time = time.time()

    async def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make a rate-limited request to the NVD API."""
        client = await self._ensure_client()
        await self._rate_limit()

        for attempt in range(self.config.max_retries):
            try:
                log.debug("NVD API request", params=params, attempt=attempt + 1)
                response = await client.get(self.config.base_url, params=params)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 403:
                    raise ClientError(
                        "NVD API access forbidden (check API key)",
                        status_code=403,
                    )

                if response.status_code == 429:
                    # Rate limited - exponential backoff
                    if attempt < self.config.max_retries - 1:
                        delay = 30 * (2**attempt)  # 30s, 60s, 120s
                        log.warning("NVD rate limited, backing off", delay=delay)
                        await asyncio.sleep(delay)
                        continue
                    raise ClientError(
                        "NVD API rate limit exceeded after retries",
                        status_code=429,
                        attempts=attempt + 1,
                    )

                if response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.config.max_retries - 1:
                        delay = 5 * (2**attempt)
                        log.warning("NVD server error, retrying", status=response.status_code, delay=delay)
                        await asyncio.sleep(delay)
                        continue

                raise ClientError(
                    f"NVD API error: {response.status_code}",
                    status_code=response.status_code,
                    response_text=response.text[:500],
                )

            except httpx.RequestError as e:
                if attempt < self.config.max_retries - 1:
                    delay = 5 * (2**attempt)
                    log.warning("NVD request error, retrying", error=str(e), delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise ClientError(
                    f"NVD API connection error: {e}",
                    original_error=str(e),
                ) from e

        raise ClientError("NVD API request failed after all retries")

    def _parse_cve(self, cve_data: dict[str, Any]) -> CVE:
        """Parse CVE data from NVD API response."""
        cve_item = cve_data.get("cve", {})

        # Extract descriptions (prefer English)
        descriptions = []
        for desc in cve_item.get("descriptions", []):
            if desc.get("lang") == "en":
                descriptions.append(desc.get("value", ""))

        # Extract CVSS v3.1 data
        cvss_v31 = None
        metrics = cve_item.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_v31 = CVSSData(
                version=cvss_data.get("version", "3.1"),
                vector_string=cvss_data.get("vectorString", ""),
                base_score=cvss_data.get("baseScore", 0.0),
                base_severity=cvss_data.get("baseSeverity", ""),
            )

        # Extract CVSS v2 data as fallback
        cvss_v2 = None
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_v2 = CVSSData(
                version=cvss_data.get("version", "2.0"),
                vector_string=cvss_data.get("vectorString", ""),
                base_score=cvss_data.get("baseScore", 0.0),
                base_severity=metrics["cvssMetricV2"][0].get("baseSeverity", ""),
            )

        # Extract weaknesses (CWE IDs)
        weaknesses = []
        for weakness in cve_item.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))

        # Extract references
        references = []
        for ref in cve_item.get("references", []):
            if url := ref.get("url"):
                references.append(url)

        # Parse timestamps
        published = None
        if pub_str := cve_item.get("published"):
            try:
                published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        last_modified = None
        if mod_str := cve_item.get("lastModified"):
            try:
                last_modified = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return CVE(
            cve_id=cve_item.get("id", ""),
            source_identifier=cve_item.get("sourceIdentifier", ""),
            published=published,
            last_modified=last_modified,
            vuln_status=cve_item.get("vulnStatus", ""),
            descriptions=descriptions,
            cvss_v31=cvss_v31,
            cvss_v2=cvss_v2,
            weaknesses=weaknesses,
            references=references[:10],  # Limit references
            raw_data=cve_item,
        )

    async def search_cves(
        self,
        keyword: str | None = None,
        cve_id: str | None = None,
        pub_start_date: datetime | None = None,
        pub_end_date: datetime | None = None,
        mod_start_date: datetime | None = None,
        mod_end_date: datetime | None = None,
        cvss_v3_severity: str | None = None,
        start_index: int = 0,
        results_per_page: int | None = None,
    ) -> NVDSearchResult:
        """Search for CVEs matching the given criteria.

        Args:
            keyword: Search keyword (searches descriptions)
            cve_id: Specific CVE ID to fetch
            pub_start_date: Filter by publish date start
            pub_end_date: Filter by publish date end
            mod_start_date: Filter by modification date start
            mod_end_date: Filter by modification date end
            cvss_v3_severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            start_index: Pagination offset
            results_per_page: Results per page (default from config)

        Returns:
            NVDSearchResult with matching CVEs
        """
        params: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page or self.config.results_per_page,
        }

        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_start_date:
            params["lastModStartDate"] = mod_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if mod_end_date:
            params["lastModEndDate"] = mod_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()

        data = await self._request(params)

        cves = []
        for vuln in data.get("vulnerabilities", []):
            try:
                cve = self._parse_cve(vuln)
                cves.append(cve)
            except Exception as e:
                log.warning("Failed to parse CVE", error=str(e))

        return NVDSearchResult(
            total_results=data.get("totalResults", 0),
            results_per_page=data.get("resultsPerPage", 0),
            start_index=data.get("startIndex", 0),
            cves=cves,
        )

    async def get_recent_cves(
        self,
        hours: int = 24,
        severity: str | None = None,
    ) -> NVDSearchResult:
        """Get CVEs modified in the last N hours.

        Args:
            hours: Look back period in hours (default 24)
            severity: Optional severity filter (LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            NVDSearchResult with recent CVEs
        """
        end_date = datetime.now(UTC)
        start_date = end_date - timedelta(hours=hours)

        return await self.search_cves(
            mod_start_date=start_date,
            mod_end_date=end_date,
            cvss_v3_severity=severity,
        )

    async def get_critical_cves(self, hours: int = 168) -> NVDSearchResult:
        """Get critical severity CVEs from the last N hours.

        Args:
            hours: Look back period (default 168 = 1 week)

        Returns:
            NVDSearchResult with critical CVEs
        """
        return await self.get_recent_cves(hours=hours, severity="CRITICAL")

    async def get_cve(self, cve_id: str) -> CVE | None:
        """Get a specific CVE by ID.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            CVE if found, None otherwise
        """
        result = await self.search_cves(cve_id=cve_id)
        if result.cves:
            return result.cves[0]
        return None
