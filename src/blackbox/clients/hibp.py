"""Have I Been Pwned (HIBP) API client.

HIBP provides breach data for email addresses. This client enables
checking if credentials have been exposed in known data breaches.

API Documentation: https://haveibeenpwned.com/API/v3
Rate Limit: 1 request per 1.5 seconds for breached account API

Note: Requires a paid API key from https://haveibeenpwned.com/API/Key
"""

import asyncio
import contextlib
import time
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from blackbox.exceptions import ClientError


class HIBPConfig(BaseModel):
    """Configuration for HIBP API client."""

    api_key: str = Field(description="HIBP API key (required)")
    base_url: str = Field(
        default="https://haveibeenpwned.com/api/v3",
        description="HIBP API base URL",
    )
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(
        default=1.6,
        description="Delay between requests in seconds (HIBP requires 1.5s minimum)",
    )
    max_retries: int = Field(
        default=3,
        description="Maximum retries on rate limit (429) responses",
    )
    retry_base_delay: float = Field(
        default=2.0,
        description="Base delay for exponential backoff on retries",
    )


class Breach(BaseModel):
    """A data breach from HIBP.

    Represents a known data breach that exposed user credentials.
    """

    name: str = Field(description="Unique breach identifier (e.g., 'Adobe')")
    title: str = Field(description="Human-readable breach name")
    domain: str = Field(description="Domain of the breached service")
    breach_date: str = Field(description="Date the breach occurred (YYYY-MM-DD)")
    added_date: str = Field(description="Date breach was added to HIBP")
    modified_date: str = Field(description="Date breach record was last modified")
    pwn_count: int = Field(description="Number of accounts exposed")
    description: str = Field(description="HTML description of the breach")
    logo_path: str = Field(default="", description="Path to breach logo")
    data_classes: list[str] = Field(
        default_factory=list,
        description="Types of data exposed (e.g., 'Emails', 'Passwords')",
    )
    is_verified: bool = Field(default=True, description="Breach has been verified")
    is_fabricated: bool = Field(default=False, description="Breach may be fabricated")
    is_sensitive: bool = Field(
        default=False,
        description="Breach is sensitive (e.g., adult sites)",
    )
    is_retired: bool = Field(default=False, description="Breach has been retired")
    is_spam_list: bool = Field(default=False, description="Breach is a spam list")
    is_malware: bool = Field(
        default=False,
        description="Breach was from malware distribution",
    )
    is_subscription_free: bool = Field(
        default=False,
        description="Breach is freely accessible without subscription",
    )

    @property
    def exposed_passwords(self) -> bool:
        """Check if passwords were exposed in this breach."""
        return "Passwords" in self.data_classes

    @property
    def breach_datetime(self) -> datetime | None:
        """Parse breach date as datetime."""
        try:
            return datetime.strptime(self.breach_date, "%Y-%m-%d")
        except ValueError:
            return None


class Paste(BaseModel):
    """A paste containing exposed email address.

    Pastes are text documents uploaded to paste sites that contain
    personal data, often from data breaches.
    """

    source: str = Field(description="Paste site name (e.g., 'Pastebin')")
    id: str = Field(description="Paste identifier")
    title: str | None = Field(default=None, description="Paste title if available")
    date: str | None = Field(default=None, description="Date paste was created")
    email_count: int = Field(default=0, description="Number of emails in paste")


class HIBPClient:
    """Async client for Have I Been Pwned API.

    Provides methods to check email addresses against known data breaches
    and pastes. Implements rate limiting and exponential backoff for
    429 responses.

    Example:
        async with HIBPClient(HIBPConfig(api_key="your-key")) as client:
            breaches = await client.check_email("user@example.com")
            for breach in breaches:
                print(f"Found in {breach.title} ({breach.breach_date})")
    """

    def __init__(self, config: HIBPConfig) -> None:
        """Initialize HIBP client.

        Args:
            config: HIBP configuration with API key.
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._last_request_time: float = 0

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={
                    "hibp-api-key": self.config.api_key,
                    "User-Agent": "BlackBox-OSINT",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(self.config.timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "HIBPClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Async context manager exit."""
        await self.close()

    async def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.config.rate_limit_delay:
            await asyncio.sleep(self.config.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Make an HTTP request to HIBP with rate limiting and retry.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            JSON response or None if 404 (not found)

        Raises:
            ClientError: If the request fails after retries
        """
        client = await self._get_client()
        url = f"{self.config.base_url}{endpoint}"

        for attempt in range(self.config.max_retries + 1):
            await self._rate_limit()

            try:
                response = await client.request(method, url, params=params)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 404:
                    # Not found - email not in any breaches
                    return None

                if response.status_code == 429:
                    # Rate limited - exponential backoff
                    if attempt < self.config.max_retries:
                        delay = self.config.retry_base_delay * (2**attempt)
                        # Check for Retry-After header
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            with contextlib.suppress(ValueError):
                                delay = max(delay, float(retry_after))
                        await asyncio.sleep(delay)
                        continue

                    raise ClientError(
                        "HIBP rate limit exceeded after retries",
                        url=url,
                        status_code=429,
                        attempts=attempt + 1,
                    )

                if response.status_code == 401:
                    raise ClientError(
                        "HIBP API key is invalid or missing",
                        url=url,
                        status_code=401,
                    )

                response.raise_for_status()

            except httpx.HTTPStatusError as e:
                raise ClientError(
                    "HIBP API request failed",
                    url=url,
                    status_code=e.response.status_code,
                    detail=str(e),
                ) from e

            except httpx.RequestError as e:
                raise ClientError(
                    "Failed to connect to HIBP",
                    url=url,
                    detail=str(e),
                ) from e

        return None

    async def check_email(
        self,
        email: str,
        *,
        truncate_response: bool = True,
        include_unverified: bool = True,
    ) -> list[Breach]:
        """Check if an email address has been in any data breaches.

        Args:
            email: Email address to check
            truncate_response: Return only breach names (faster)
            include_unverified: Include unverified breaches

        Returns:
            List of breaches containing this email, empty if none found
        """
        params = {
            "truncateResponse": str(truncate_response).lower(),
            "includeUnverified": str(include_unverified).lower(),
        }

        result = await self._request(
            "GET",
            f"/breachedaccount/{email}",
            params=params,
        )

        if result is None:
            return []

        # If truncated, we only get breach names - need to fetch full details
        if truncate_response and isinstance(result, list):
            # Result is list of breach names when truncated
            breaches = []
            for item in result:
                if isinstance(item, dict) and "Name" in item:
                    # Fetch full breach details
                    full_breach = await self.get_breach(item["Name"])
                    if full_breach:
                        breaches.append(full_breach)
            return breaches

        # Full response - parse directly
        if isinstance(result, list):
            return [self._parse_breach(b) for b in result if isinstance(b, dict)]

        return []

    async def check_emails(
        self,
        emails: list[str],
        *,
        truncate_response: bool = True,
        include_unverified: bool = True,
    ) -> dict[str, list[Breach]]:
        """Check multiple email addresses for breaches.

        Note: This makes sequential requests due to HIBP rate limiting.
        Each request has a 1.5s minimum delay.

        Args:
            emails: List of email addresses to check
            truncate_response: Return only breach names (faster)
            include_unverified: Include unverified breaches

        Returns:
            Dictionary mapping email to list of breaches
        """
        results: dict[str, list[Breach]] = {}

        for email in emails:
            breaches = await self.check_email(
                email,
                truncate_response=truncate_response,
                include_unverified=include_unverified,
            )
            results[email] = breaches

        return results

    async def get_breach(self, name: str) -> Breach | None:
        """Get details of a specific breach.

        Args:
            name: Breach name (e.g., "Adobe")

        Returns:
            Breach details or None if not found
        """
        result = await self._request("GET", f"/breach/{name}")

        if result is None or not isinstance(result, dict):
            return None

        return self._parse_breach(result)

    async def list_breaches(
        self,
        *,
        domain: str | None = None,
    ) -> list[Breach]:
        """List all breaches in the HIBP database.

        Args:
            domain: Optional domain filter (e.g., "adobe.com")

        Returns:
            List of all breaches
        """
        params = {}
        if domain:
            params["domain"] = domain

        result = await self._request("GET", "/breaches", params=params or None)

        if result is None or not isinstance(result, list):
            return []

        return [self._parse_breach(b) for b in result if isinstance(b, dict)]

    async def check_pastes(self, email: str) -> list[Paste]:
        """Check if an email address appears in any pastes.

        Args:
            email: Email address to check

        Returns:
            List of pastes containing this email
        """
        result = await self._request("GET", f"/pasteaccount/{email}")

        if result is None or not isinstance(result, list):
            return []

        return [self._parse_paste(p) for p in result if isinstance(p, dict)]

    def _parse_breach(self, data: dict[str, Any]) -> Breach:
        """Parse breach data from API response."""
        return Breach(
            name=data.get("Name", ""),
            title=data.get("Title", ""),
            domain=data.get("Domain", ""),
            breach_date=data.get("BreachDate", ""),
            added_date=data.get("AddedDate", ""),
            modified_date=data.get("ModifiedDate", ""),
            pwn_count=data.get("PwnCount", 0),
            description=data.get("Description", ""),
            logo_path=data.get("LogoPath", ""),
            data_classes=data.get("DataClasses", []),
            is_verified=data.get("IsVerified", True),
            is_fabricated=data.get("IsFabricated", False),
            is_sensitive=data.get("IsSensitive", False),
            is_retired=data.get("IsRetired", False),
            is_spam_list=data.get("IsSpamList", False),
            is_malware=data.get("IsMalware", False),
            is_subscription_free=data.get("IsSubscriptionFree", False),
        )

    def _parse_paste(self, data: dict[str, Any]) -> Paste:
        """Parse paste data from API response."""
        return Paste(
            source=data.get("Source", ""),
            id=data.get("Id", ""),
            title=data.get("Title"),
            date=data.get("Date"),
            email_count=data.get("EmailCount", 0),
        )
