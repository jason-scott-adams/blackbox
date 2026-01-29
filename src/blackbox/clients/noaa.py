"""NOAA Weather Alerts client.

Uses the National Weather Service API to fetch active weather alerts.
API Documentation: https://www.weather.gov/documentation/services-web-api
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


class NOAAConfig(BaseModel):
    """Configuration for the NOAA client."""

    base_url: str = Field(default="https://api.weather.gov")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    rate_limit_delay: float = Field(default=0.5, description="Delay between requests")
    max_retries: int = Field(default=3, description="Max retry attempts on failure")
    default_area: str = Field(default="MO", description="Default state/area code")


class AlertGeocoding(BaseModel):
    """Geographic info for an alert."""

    ugc: list[str] = Field(default_factory=list, description="UGC zone codes")
    same: list[str] = Field(default_factory=list, description="SAME codes")
    affected_zones: list[str] = Field(default_factory=list)


class WeatherAlert(BaseModel):
    """NOAA Weather Alert data."""

    alert_id: str = Field(description="Alert identifier")
    area_desc: str = Field(default="", description="Affected area description")
    event: str = Field(description="Event type (e.g., Tornado Warning)")
    severity: str = Field(default="", description="Severity (Extreme, Severe, Moderate, Minor, Unknown)")
    certainty: str = Field(default="", description="Certainty (Observed, Likely, Possible, Unlikely, Unknown)")
    urgency: str = Field(default="", description="Urgency (Immediate, Expected, Future, Past, Unknown)")
    headline: str = ""
    description: str = ""
    instruction: str = ""
    sender: str = ""
    sender_name: str = ""
    effective: datetime | None = None
    onset: datetime | None = None
    expires: datetime | None = None
    ends: datetime | None = None
    status: str = ""
    message_type: str = ""
    category: str = ""
    response: str = ""
    geocode: AlertGeocoding = Field(default_factory=AlertGeocoding)
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_extreme(self) -> bool:
        """Check if this is an extreme severity alert."""
        return self.severity.lower() == "extreme"

    @property
    def is_severe(self) -> bool:
        """Check if this is severe or extreme."""
        return self.severity.lower() in ("extreme", "severe")

    @property
    def is_immediate(self) -> bool:
        """Check if this alert has immediate urgency."""
        return self.urgency.lower() == "immediate"

    @property
    def is_active(self) -> bool:
        """Check if alert is currently active."""
        now = datetime.now(UTC)
        if self.expires and self.expires < now:
            return False
        if self.ends and self.ends < now:
            return False
        return True

    @property
    def priority_score(self) -> int:
        """Calculate a priority score for sorting (higher = more urgent).

        Score based on:
        - Severity: Extreme=40, Severe=30, Moderate=20, Minor=10
        - Urgency: Immediate=20, Expected=15, Future=10
        - Certainty: Observed=10, Likely=8, Possible=5
        """
        score = 0

        severity_scores = {"extreme": 40, "severe": 30, "moderate": 20, "minor": 10}
        score += severity_scores.get(self.severity.lower(), 0)

        urgency_scores = {"immediate": 20, "expected": 15, "future": 10, "past": 0}
        score += urgency_scores.get(self.urgency.lower(), 0)

        certainty_scores = {"observed": 10, "likely": 8, "possible": 5, "unlikely": 2}
        score += certainty_scores.get(self.certainty.lower(), 0)

        return score


class NOAAAlertResult(BaseModel):
    """Result from NOAA alert query."""

    alerts: list[WeatherAlert] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    title: str = ""
    updated: datetime | None = None


@dataclass
class NOAAClient:
    """Async client for the NOAA Weather API.

    Usage:
        async with NOAAClient(config) as client:
            result = await client.get_active_alerts(area="KS")
            for alert in result.alerts:
                print(f"{alert.event}: {alert.headline}")
    """

    config: NOAAConfig = field(default_factory=NOAAConfig)
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _last_request_time: float = field(default=0.0, repr=False)

    async def __aenter__(self) -> "NOAAClient":
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
                "Accept": "application/geo+json",
                "User-Agent": "(BlackBox OSINT, contact@example.com)",
            }
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

    async def _request(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Make a rate-limited request to the NOAA API."""
        client = await self._ensure_client()
        await self._rate_limit()

        for attempt in range(self.config.max_retries):
            try:
                log.debug("NOAA API request", endpoint=endpoint, params=params, attempt=attempt + 1)
                response = await client.get(endpoint, params=params)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 503:
                    # Service temporarily unavailable - common during high load
                    if attempt < self.config.max_retries - 1:
                        delay = 10 * (2**attempt)
                        log.warning("NOAA service unavailable, retrying", delay=delay)
                        await asyncio.sleep(delay)
                        continue

                if response.status_code >= 500:
                    if attempt < self.config.max_retries - 1:
                        delay = 5 * (2**attempt)
                        log.warning("NOAA server error, retrying", status=response.status_code, delay=delay)
                        await asyncio.sleep(delay)
                        continue

                raise ClientError(
                    f"NOAA API error: {response.status_code}",
                    status_code=response.status_code,
                    response_text=response.text[:500] if response.text else "",
                )

            except httpx.RequestError as e:
                if attempt < self.config.max_retries - 1:
                    delay = 5 * (2**attempt)
                    log.warning("NOAA request error, retrying", error=str(e), delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise ClientError(
                    f"NOAA API connection error: {e}",
                    original_error=str(e),
                ) from e

        raise ClientError("NOAA API request failed after all retries")

    def _parse_datetime(self, dt_str: str | None) -> datetime | None:
        """Parse ISO datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _parse_alert(self, feature: dict[str, Any]) -> WeatherAlert:
        """Parse alert data from GeoJSON feature."""
        props = feature.get("properties", {})

        # Extract geocodes
        geocodes = props.get("geocode", {})
        geocoding = AlertGeocoding(
            ugc=geocodes.get("UGC", []),
            same=geocodes.get("SAME", []),
            affected_zones=props.get("affectedZones", []),
        )

        # Extract references (related alerts)
        references = []
        for ref in props.get("references", []):
            if ref_id := ref.get("identifier"):
                references.append(ref_id)

        return WeatherAlert(
            alert_id=props.get("id", feature.get("id", "")),
            area_desc=props.get("areaDesc", ""),
            event=props.get("event", ""),
            severity=props.get("severity", ""),
            certainty=props.get("certainty", ""),
            urgency=props.get("urgency", ""),
            headline=props.get("headline", ""),
            description=props.get("description", ""),
            instruction=props.get("instruction", ""),
            sender=props.get("sender", ""),
            sender_name=props.get("senderName", ""),
            effective=self._parse_datetime(props.get("effective")),
            onset=self._parse_datetime(props.get("onset")),
            expires=self._parse_datetime(props.get("expires")),
            ends=self._parse_datetime(props.get("ends")),
            status=props.get("status", ""),
            message_type=props.get("messageType", ""),
            category=props.get("category", ""),
            response=props.get("response", ""),
            geocode=geocoding,
            references=references,
            raw_data=props,
        )

    async def get_active_alerts(
        self,
        area: str | None = None,
        event: str | None = None,
        severity: str | None = None,
        urgency: str | None = None,
        certainty: str | None = None,
        status: str = "actual",
        message_type: str | None = None,
        limit: int | None = None,
    ) -> NOAAAlertResult:
        """Get active weather alerts.

        Args:
            area: State/territory code (e.g., "KS", "MO") or zone code
            event: Event type filter (e.g., "Tornado Warning")
            severity: Severity filter (Extreme, Severe, Moderate, Minor)
            urgency: Urgency filter (Immediate, Expected, Future, Past)
            certainty: Certainty filter (Observed, Likely, Possible, Unlikely)
            status: Status filter (actual, exercise, system, test, draft)
            message_type: Message type filter (alert, update, cancel)
            limit: Max number of alerts to return

        Returns:
            NOAAAlertResult with active alerts
        """
        params: dict[str, Any] = {"status": status}

        if area:
            params["area"] = area.upper()
        if event:
            params["event"] = event
        if severity:
            params["severity"] = severity
        if urgency:
            params["urgency"] = urgency
        if certainty:
            params["certainty"] = certainty
        if message_type:
            params["message_type"] = message_type
        if limit:
            params["limit"] = limit

        data = await self._request("/alerts/active", params)

        alerts = []
        for feature in data.get("features", []):
            try:
                alert = self._parse_alert(feature)
                if alert.is_active:
                    alerts.append(alert)
            except Exception as e:
                log.warning("Failed to parse alert", error=str(e))

        # Sort by priority (highest first)
        alerts.sort(key=lambda a: a.priority_score, reverse=True)

        # Parse updated timestamp
        updated = None
        if upd_str := data.get("updated"):
            updated = self._parse_datetime(upd_str)

        return NOAAAlertResult(
            alerts=alerts,
            title=data.get("title", ""),
            updated=updated,
        )

    async def get_severe_alerts(self, area: str | None = None) -> NOAAAlertResult:
        """Get severe and extreme weather alerts.

        Args:
            area: State/territory code (default from config)

        Returns:
            NOAAAlertResult with severe alerts
        """
        area = area or self.config.default_area
        result = await self.get_active_alerts(area=area)

        # Filter to severe and extreme only
        severe_alerts = [a for a in result.alerts if a.is_severe]

        return NOAAAlertResult(
            alerts=severe_alerts,
            title=result.title,
            updated=result.updated,
        )

    async def get_alerts_for_state(self, state: str) -> NOAAAlertResult:
        """Get all active alerts for a state.

        Args:
            state: Two-letter state code (e.g., "KS", "MO")

        Returns:
            NOAAAlertResult with state alerts
        """
        return await self.get_active_alerts(area=state.upper())

    async def get_alerts_for_region(self, states: list[str]) -> NOAAAlertResult:
        """Get alerts for multiple states.

        Args:
            states: List of state codes (e.g., ["KS", "MO"])

        Returns:
            Combined NOAAAlertResult
        """
        all_alerts = []
        updated = None

        for state in states:
            try:
                result = await self.get_active_alerts(area=state)
                all_alerts.extend(result.alerts)
                if result.updated and (updated is None or result.updated > updated):
                    updated = result.updated
            except ClientError as e:
                log.warning("Failed to get alerts for state", state=state, error=str(e))

        # Deduplicate by alert_id (alerts can appear in multiple states)
        seen_ids = set()
        unique_alerts = []
        for alert in all_alerts:
            if alert.alert_id not in seen_ids:
                seen_ids.add(alert.alert_id)
                unique_alerts.append(alert)

        # Sort by priority
        unique_alerts.sort(key=lambda a: a.priority_score, reverse=True)

        return NOAAAlertResult(
            alerts=unique_alerts,
            title=f"Alerts for {', '.join(states)}",
            updated=updated,
        )


# Default areas for Kansas City metro
KC_METRO_STATES = ["KS", "MO"]


def create_kc_weather_client() -> NOAAClient:
    """Create a NOAA client configured for Kansas City metro area."""
    config = NOAAConfig(default_area="MO")
    return NOAAClient(config=config)
