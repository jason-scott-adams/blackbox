"""GitHub Security Advisories client.

Uses the GitHub REST API to fetch security advisories from the GitHub Advisory Database.
API Documentation: https://docs.github.com/en/rest/security-advisories
"""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

from blackbox.exceptions import ClientError

log = structlog.get_logger(__name__)


class GitHubAdvisoryConfig(BaseModel):
    """Configuration for the GitHub Advisory client."""

    token: str = Field(default="", description="GitHub personal access token (optional)")
    base_url: str = Field(default="https://api.github.com")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(
        default=1.0,
        description="Delay between requests in seconds",
    )
    max_retries: int = Field(default=3, description="Max retry attempts on failure")
    per_page: int = Field(default=100, description="Results per page (max 100)")


class Identifier(BaseModel):
    """Advisory identifier (CVE, GHSA, etc.)."""

    type: str = ""
    value: str = ""


class Vulnerability(BaseModel):
    """Vulnerability info within an advisory."""

    package_ecosystem: str = ""
    package_name: str = ""
    vulnerable_version_range: str = ""
    first_patched_version: str | None = None


class GitHubAdvisory(BaseModel):
    """GitHub Security Advisory data."""

    ghsa_id: str = Field(description="GitHub Security Advisory ID (e.g., GHSA-xxxx-xxxx-xxxx)")
    cve_id: str | None = Field(default=None, description="Associated CVE ID if available")
    summary: str = ""
    description: str = ""
    severity: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    updated_at: datetime | None = None
    withdrawn_at: datetime | None = None
    identifiers: list[Identifier] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    credits: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_critical(self) -> bool:
        """Check if this is a critical severity advisory."""
        return self.severity.upper() == "CRITICAL"

    @property
    def is_high(self) -> bool:
        """Check if this is high severity or above."""
        return self.severity.upper() in ("CRITICAL", "HIGH")

    @property
    def affected_packages(self) -> list[str]:
        """Get list of affected package names."""
        return [
            f"{v.package_ecosystem}:{v.package_name}"
            for v in self.vulnerabilities
            if v.package_name
        ]


class GitHubAdvisoryResult(BaseModel):
    """Result from GitHub Advisory search."""

    advisories: list[GitHubAdvisory] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    has_more: bool = False


@dataclass
class GitHubAdvisoryClient:
    """Async client for the GitHub Security Advisories API.

    Usage:
        async with GitHubAdvisoryClient(config) as client:
            result = await client.list_advisories(severity="critical")
            for advisory in result.advisories:
                print(f"{advisory.ghsa_id}: {advisory.summary}")
    """

    config: GitHubAdvisoryConfig = field(default_factory=GitHubAdvisoryConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _last_request_time: float = field(default=0.0, repr=False)

    async def __aenter__(self) -> "GitHubAdvisoryClient":
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
                "Accept": "application/vnd.github+json",
                "User-Agent": "BlackBox/0.1.0 (+https://github.com/jason-scott-adams/blackbox)",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self.config.token:
                headers["Authorization"] = f"Bearer {self.config.token}"
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
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

    async def _request(self, endpoint: str, params: dict[str, Any] | None = None) -> tuple[list[dict], bool]:
        """Make a rate-limited request to the GitHub API.

        Returns:
            Tuple of (data, has_more_pages)
        """
        client = await self._ensure_client()
        await self._rate_limit()

        for attempt in range(self.config.max_retries):
            try:
                log.debug("GitHub API request", endpoint=endpoint, params=params, attempt=attempt + 1)
                response = await client.get(endpoint, params=params)

                if response.status_code == 200:
                    data = response.json()
                    # Check for pagination
                    link_header = response.headers.get("Link", "")
                    has_more = 'rel="next"' in link_header
                    return data, has_more

                if response.status_code == 401:
                    raise ClientError(
                        "GitHub API authentication failed (check token)",
                        status_code=401,
                    )

                if response.status_code == 403:
                    # Check for rate limiting
                    if "rate limit" in response.text.lower():
                        if attempt < self.config.max_retries - 1:
                            reset_time = response.headers.get("X-RateLimit-Reset")
                            if reset_time:
                                wait_time = int(reset_time) - int(datetime.now(UTC).timestamp())
                                wait_time = min(max(wait_time, 60), 300)  # 1-5 min
                            else:
                                wait_time = 60 * (2**attempt)
                            log.warning("GitHub rate limited, waiting", wait_time=wait_time)
                            await asyncio.sleep(wait_time)
                            continue
                    raise ClientError(
                        "GitHub API access forbidden",
                        status_code=403,
                        response_text=response.text[:500],
                    )

                if response.status_code == 404:
                    return [], False

                if response.status_code >= 500:
                    if attempt < self.config.max_retries - 1:
                        delay = 5 * (2**attempt)
                        log.warning("GitHub server error, retrying", status=response.status_code, delay=delay)
                        await asyncio.sleep(delay)
                        continue

                raise ClientError(
                    f"GitHub API error: {response.status_code}",
                    status_code=response.status_code,
                    response_text=response.text[:500],
                )

            except httpx.RequestError as e:
                if attempt < self.config.max_retries - 1:
                    delay = 5 * (2**attempt)
                    log.warning("GitHub request error, retrying", error=str(e), delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise ClientError(
                    f"GitHub API connection error: {e}",
                    original_error=str(e),
                ) from e

        raise ClientError("GitHub API request failed after all retries")

    def _parse_advisory(self, data: dict[str, Any]) -> GitHubAdvisory:
        """Parse advisory data from GitHub API response."""
        # Extract identifiers
        identifiers = []
        for ident in data.get("identifiers", []):
            identifiers.append(Identifier(
                type=ident.get("type", ""),
                value=ident.get("value", ""),
            ))

        # Extract CVE ID from identifiers
        cve_id = None
        for ident in identifiers:
            if ident.type == "CVE":
                cve_id = ident.value
                break

        # Extract vulnerabilities
        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            pkg = vuln.get("package", {}) or {}
            patched = vuln.get("first_patched_version")
            # first_patched_version can be a string or a dict with "identifier"
            if isinstance(patched, str):
                patched_version = patched
            elif isinstance(patched, dict):
                patched_version = patched.get("identifier")
            else:
                patched_version = None
            vulnerabilities.append(Vulnerability(
                package_ecosystem=pkg.get("ecosystem", "") if isinstance(pkg, dict) else "",
                package_name=pkg.get("name", "") if isinstance(pkg, dict) else "",
                vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
                first_patched_version=patched_version,
            ))

        # Extract references (API returns list of URL strings)
        references = []
        for ref in data.get("references", []):
            if isinstance(ref, str):
                references.append(ref)
            elif isinstance(ref, dict) and (url := ref.get("url")):
                references.append(url)

        # Extract credits
        credits = []
        for credit in data.get("credits", []):
            if user := credit.get("user", {}):
                credits.append(user.get("login", ""))

        # Parse timestamps
        published_at = None
        if pub_str := data.get("published_at"):
            try:
                published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        updated_at = None
        if upd_str := data.get("updated_at"):
            try:
                updated_at = datetime.fromisoformat(upd_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        withdrawn_at = None
        if with_str := data.get("withdrawn_at"):
            try:
                withdrawn_at = datetime.fromisoformat(with_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Extract CVSS info
        cvss = data.get("cvss", {}) or {}

        return GitHubAdvisory(
            ghsa_id=data.get("ghsa_id", ""),
            cve_id=cve_id,
            summary=data.get("summary", ""),
            description=data.get("description", ""),
            severity=data.get("severity", ""),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector_string"),
            published_at=published_at,
            updated_at=updated_at,
            withdrawn_at=withdrawn_at,
            identifiers=identifiers,
            vulnerabilities=vulnerabilities,
            references=references[:10],
            credits=credits[:5],
            raw_data=data,
        )

    async def list_advisories(
        self,
        severity: str | None = None,
        ecosystem: str | None = None,
        package: str | None = None,
        cve_id: str | None = None,
        ghsa_id: str | None = None,
        modified_since: datetime | None = None,
        published_since: datetime | None = None,
        per_page: int | None = None,
    ) -> GitHubAdvisoryResult:
        """List security advisories from the GitHub Advisory Database.

        Args:
            severity: Filter by severity (low, medium, high, critical)
            ecosystem: Filter by ecosystem (npm, pip, maven, etc.)
            package: Filter by package name
            cve_id: Filter by CVE ID
            ghsa_id: Get a specific GHSA by ID
            modified_since: Filter by last modification time
            published_since: Filter by publish time
            per_page: Results per page (default from config)

        Returns:
            GitHubAdvisoryResult with matching advisories
        """
        params: dict[str, Any] = {
            "per_page": per_page or self.config.per_page,
            "type": "reviewed",  # Only GitHub-reviewed advisories
        }

        if severity:
            params["severity"] = severity.lower()
        if ecosystem:
            params["ecosystem"] = ecosystem.lower()
        if package:
            params["affects"] = package
        if cve_id:
            params["cve_id"] = cve_id
        if ghsa_id:
            params["ghsa_id"] = ghsa_id
        if modified_since:
            params["modified"] = f">{modified_since.strftime('%Y-%m-%d')}"
        if published_since:
            params["published"] = f">{published_since.strftime('%Y-%m-%d')}"

        data, has_more = await self._request("/advisories", params)

        advisories = []
        for item in data:
            try:
                advisory = self._parse_advisory(item)
                # Skip withdrawn advisories
                if advisory.withdrawn_at is None:
                    advisories.append(advisory)
            except Exception as e:
                log.warning("Failed to parse advisory", error=str(e))

        return GitHubAdvisoryResult(
            advisories=advisories,
            has_more=has_more,
        )

    async def get_advisory(self, ghsa_id: str) -> GitHubAdvisory | None:
        """Get a specific advisory by GHSA ID.

        Args:
            ghsa_id: The GHSA identifier (e.g., "GHSA-xxxx-xxxx-xxxx")

        Returns:
            GitHubAdvisory if found, None otherwise
        """
        try:
            data, _ = await self._request(f"/advisories/{ghsa_id}")
            if data:
                return self._parse_advisory(data)
        except ClientError as e:
            if "404" in str(e):
                return None
            raise
        return None

    async def get_critical_advisories(
        self,
        ecosystem: str | None = None,
        published_since: datetime | None = None,
    ) -> GitHubAdvisoryResult:
        """Get critical severity advisories.

        Args:
            ecosystem: Optional ecosystem filter
            published_since: Optional date filter

        Returns:
            GitHubAdvisoryResult with critical advisories
        """
        return await self.list_advisories(
            severity="critical",
            ecosystem=ecosystem,
            published_since=published_since,
        )

    async def get_advisories_for_ecosystem(
        self,
        ecosystem: str,
        severity: str | None = None,
    ) -> GitHubAdvisoryResult:
        """Get advisories for a specific ecosystem.

        Args:
            ecosystem: Package ecosystem (npm, pip, maven, rubygems, etc.)
            severity: Optional severity filter

        Returns:
            GitHubAdvisoryResult with ecosystem advisories
        """
        return await self.list_advisories(
            ecosystem=ecosystem,
            severity=severity,
        )
