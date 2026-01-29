"""Base protocols for Black Box client implementations.

Defines interfaces for pluggable data source clients.
"""

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from blackbox.clients.hibp import Breach, Paste


class BreachClient(Protocol):
    """Protocol for breach monitoring clients.

    Any client implementing this protocol can be used with HIBPSyncService.
    This enables pluggable support for different breach data sources:
    - Have I Been Pwned (HIBP) - paid, comprehensive
    - Mozilla Monitor - free, community-driven
    - Future: Troy Hunt's K-Anonymity API, etc.
    """

    async def check_email(
        self,
        email: str,
        truncate_response: bool = True,
        include_unverified: bool = False,
    ) -> list["Breach"]:
        """Check a single email address for breaches.

        Args:
            email: Email address to check
            truncate_response: Whether to truncate response (API limitation)
            include_unverified: Whether to include unverified breaches

        Returns:
            List of breaches for this email

        Raises:
            ClientError: If API call fails
        """
        ...

    async def list_breaches(self) -> list["Breach"]:
        """List all known breaches.

        Returns:
            List of all known breaches in the database

        Raises:
            ClientError: If API call fails
        """
        ...

    async def check_pastes(self, email: str) -> list["Paste"]:
        """Check if email appears in paste sites.

        Args:
            email: Email address to check

        Returns:
            List of pastes containing the email

        Raises:
            ClientError: If API call fails
        """
        ...

    async def close(self) -> None:
        """Close client connections and cleanup resources."""
        ...
