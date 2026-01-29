"""Datetime utilities for consistent timestamp handling.

All timestamps in Black Box are UTC.
"""

from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    """Return current UTC datetime.

    Returns:
        Current time in UTC with timezone info
    """
    return datetime.now(UTC)


def format_iso(dt: datetime) -> str:
    """Format datetime as ISO 8601 string.

    Args:
        dt: Datetime to format

    Returns:
        ISO 8601 formatted string (e.g., "2025-12-10T14:32:00Z")
    """
    # Ensure UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(iso_string: str) -> datetime:
    """Parse ISO 8601 datetime string.

    Args:
        iso_string: ISO 8601 formatted string

    Returns:
        Datetime object with UTC timezone
    """
    # Handle both "Z" suffix and "+00:00" format
    if iso_string.endswith("Z"):
        iso_string = iso_string[:-1] + "+00:00"
    return datetime.fromisoformat(iso_string)


def days_ago(days: int) -> datetime:
    """Return datetime for N days ago.

    Args:
        days: Number of days ago

    Returns:
        Datetime for N days ago in UTC
    """
    return utc_now() - timedelta(days=days)


def age_in_days(dt: datetime) -> int:
    """Calculate age of a datetime in days.

    Args:
        dt: Datetime to calculate age of

    Returns:
        Number of days since the datetime
    """
    now = utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = now - dt
    return delta.days
