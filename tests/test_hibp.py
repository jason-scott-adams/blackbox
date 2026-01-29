"""Tests for Have I Been Pwned (HIBP) client."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import ValidationError

from blackbox.clients.hibp import (
    Breach,
    HIBPClient,
    HIBPConfig,
    Paste,
)
from blackbox.exceptions import ClientError


class TestHIBPConfig:
    """Tests for HIBP configuration."""

    def test_default_config(self) -> None:
        """Default config has expected values."""
        config = HIBPConfig(api_key="test-key")
        assert config.api_key == "test-key"
        assert config.base_url == "https://haveibeenpwned.com/api/v3"
        assert config.timeout == 30.0
        assert config.rate_limit_delay == 1.6
        assert config.max_retries == 3
        assert config.retry_base_delay == 2.0

    def test_custom_config(self) -> None:
        """Custom config overrides defaults."""
        config = HIBPConfig(
            api_key="custom-key",
            base_url="https://custom.hibp.com",
            timeout=60.0,
            rate_limit_delay=2.0,
            max_retries=5,
        )
        assert config.api_key == "custom-key"
        assert config.base_url == "https://custom.hibp.com"
        assert config.timeout == 60.0
        assert config.rate_limit_delay == 2.0
        assert config.max_retries == 5

    def test_api_key_required(self) -> None:
        """API key is required."""
        with pytest.raises(ValidationError):
            HIBPConfig()  # type: ignore


class TestBreach:
    """Tests for Breach model."""

    def test_basic_breach(self) -> None:
        """Breach with required fields."""
        breach = Breach(
            name="Adobe",
            title="Adobe",
            domain="adobe.com",
            breach_date="2013-10-04",
            added_date="2013-12-04T00:00:00Z",
            modified_date="2022-05-15T23:52:49Z",
            pwn_count=152445165,
            description="<p>Breach description</p>",
        )
        assert breach.name == "Adobe"
        assert breach.title == "Adobe"
        assert breach.domain == "adobe.com"
        assert breach.breach_date == "2013-10-04"
        assert breach.pwn_count == 152445165

    def test_breach_with_all_fields(self) -> None:
        """Breach with all fields populated."""
        breach = Breach(
            name="Adobe",
            title="Adobe",
            domain="adobe.com",
            breach_date="2013-10-04",
            added_date="2013-12-04T00:00:00Z",
            modified_date="2022-05-15T23:52:49Z",
            pwn_count=152445165,
            description="<p>Breach description</p>",
            logo_path="https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
            data_classes=["Email addresses", "Passwords", "Password hints"],
            is_verified=True,
            is_fabricated=False,
            is_sensitive=False,
            is_retired=False,
            is_spam_list=False,
            is_malware=False,
            is_subscription_free=False,
        )
        assert breach.data_classes == ["Email addresses", "Passwords", "Password hints"]
        assert breach.is_verified is True
        assert breach.is_sensitive is False

    def test_breach_exposed_passwords(self) -> None:
        """Check if passwords were exposed."""
        breach_with_passwords = Breach(
            name="Test",
            title="Test",
            domain="test.com",
            breach_date="2020-01-01",
            added_date="2020-01-01",
            modified_date="2020-01-01",
            pwn_count=1000,
            description="Test",
            data_classes=["Passwords", "Email addresses"],
        )
        assert breach_with_passwords.exposed_passwords is True

        breach_without_passwords = Breach(
            name="Test2",
            title="Test2",
            domain="test2.com",
            breach_date="2020-01-01",
            added_date="2020-01-01",
            modified_date="2020-01-01",
            pwn_count=1000,
            description="Test",
            data_classes=["Email addresses"],
        )
        assert breach_without_passwords.exposed_passwords is False

    def test_breach_datetime(self) -> None:
        """Parse breach date as datetime."""
        breach = Breach(
            name="Test",
            title="Test",
            domain="test.com",
            breach_date="2020-06-15",
            added_date="2020-06-20",
            modified_date="2020-06-20",
            pwn_count=1000,
            description="Test",
        )
        dt = breach.breach_datetime
        assert dt is not None
        assert dt.year == 2020
        assert dt.month == 6
        assert dt.day == 15

    def test_breach_datetime_invalid(self) -> None:
        """Handle invalid breach date gracefully."""
        breach = Breach(
            name="Test",
            title="Test",
            domain="test.com",
            breach_date="invalid-date",
            added_date="2020-06-20",
            modified_date="2020-06-20",
            pwn_count=1000,
            description="Test",
        )
        assert breach.breach_datetime is None


class TestPaste:
    """Tests for Paste model."""

    def test_basic_paste(self) -> None:
        """Paste with required fields."""
        paste = Paste(
            source="Pastebin",
            id="AbCdEfGh",
        )
        assert paste.source == "Pastebin"
        assert paste.id == "AbCdEfGh"
        assert paste.title is None
        assert paste.email_count == 0

    def test_paste_with_all_fields(self) -> None:
        """Paste with all fields populated."""
        paste = Paste(
            source="Pastebin",
            id="AbCdEfGh",
            title="Leaked Emails",
            date="2020-01-15T12:30:00Z",
            email_count=150,
        )
        assert paste.title == "Leaked Emails"
        assert paste.date == "2020-01-15T12:30:00Z"
        assert paste.email_count == 150


class TestHIBPClient:
    """Tests for HIBP client."""

    def test_init(self) -> None:
        """Client initializes with config."""
        config = HIBPConfig(api_key="test-key")
        client = HIBPClient(config)
        assert client.config.api_key == "test-key"
        assert client._client is None

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Client works as async context manager."""
        config = HIBPConfig(api_key="test-key")
        async with HIBPClient(config) as client:
            assert client is not None
        # After exit, client should be closed
        assert client._client is None or client._client.is_closed

    @pytest.mark.asyncio
    async def test_check_email_found(self) -> None:
        """Check email that is in breaches."""
        mock_response = [
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "AddedDate": "2013-12-04T00:00:00Z",
                "ModifiedDate": "2022-05-15T23:52:49Z",
                "PwnCount": 152445165,
                "Description": "<p>Breach description</p>",
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsFabricated": False,
                "IsSensitive": False,
                "IsRetired": False,
                "IsSpamList": False,
                "IsMalware": False,
                "IsSubscriptionFree": False,
            }
        ]

        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            # Return full breach data (not truncated)
            mock_request.return_value = mock_response

            async with HIBPClient(config) as client:
                breaches = await client.check_email(
                    "test@example.com",
                    truncate_response=False,  # Get full response directly
                )

            assert len(breaches) == 1
            assert breaches[0].name == "Adobe"
            assert breaches[0].domain == "adobe.com"
            assert breaches[0].exposed_passwords is True

    @pytest.mark.asyncio
    async def test_check_email_not_found(self) -> None:
        """Check email that is not in any breaches."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = None  # 404 returns None

            async with HIBPClient(config) as client:
                breaches = await client.check_email("clean@example.com")

            assert breaches == []

    @pytest.mark.asyncio
    async def test_check_email_truncated_response(self) -> None:
        """Check email with truncated response (breach names only)."""
        truncated_response = [{"Name": "Adobe"}]
        full_breach_response = {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2022-05-15T23:52:49Z",
            "PwnCount": 152445165,
            "Description": "<p>Breach description</p>",
            "DataClasses": ["Email addresses"],
            "IsVerified": True,
        }

        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            # First call returns truncated list, second returns full breach details
            mock_request.side_effect = [truncated_response, full_breach_response]

            async with HIBPClient(config) as client:
                breaches = await client.check_email(
                    "test@example.com",
                    truncate_response=True,
                )

            assert len(breaches) == 1
            assert breaches[0].name == "Adobe"
            assert breaches[0].title == "Adobe"

    @pytest.mark.asyncio
    async def test_check_multiple_emails(self) -> None:
        """Check multiple email addresses."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        mock_breach = {
            "Name": "Test",
            "Title": "Test",
            "Domain": "test.com",
            "BreachDate": "2020-01-01",
            "AddedDate": "2020-01-01",
            "ModifiedDate": "2020-01-01",
            "PwnCount": 1000,
            "Description": "Test",
            "DataClasses": [],
            "IsVerified": True,
        }

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            # First email has breach, second is clean
            mock_request.side_effect = [[mock_breach], None]

            async with HIBPClient(config) as client:
                results = await client.check_emails(
                    ["breached@example.com", "clean@example.com"],
                    truncate_response=False,
                )

            assert len(results["breached@example.com"]) == 1
            assert len(results["clean@example.com"]) == 0

    @pytest.mark.asyncio
    async def test_get_breach(self) -> None:
        """Get a specific breach by name."""
        mock_response = {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2022-05-15T23:52:49Z",
            "PwnCount": 152445165,
            "Description": "<p>Breach description</p>",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
        }

        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response

            async with HIBPClient(config) as client:
                breach = await client.get_breach("Adobe")

            assert breach is not None
            assert breach.name == "Adobe"
            assert breach.pwn_count == 152445165

    @pytest.mark.asyncio
    async def test_get_breach_not_found(self) -> None:
        """Get breach that doesn't exist."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = None

            async with HIBPClient(config) as client:
                breach = await client.get_breach("NonExistent")

            assert breach is None

    @pytest.mark.asyncio
    async def test_list_breaches(self) -> None:
        """List all breaches."""
        mock_response = [
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "AddedDate": "2013-12-04T00:00:00Z",
                "ModifiedDate": "2022-05-15T23:52:49Z",
                "PwnCount": 152445165,
                "Description": "Test",
                "DataClasses": [],
            },
            {
                "Name": "LinkedIn",
                "Title": "LinkedIn",
                "Domain": "linkedin.com",
                "BreachDate": "2012-05-05",
                "AddedDate": "2016-05-21T00:00:00Z",
                "ModifiedDate": "2016-05-21T00:00:00Z",
                "PwnCount": 164611595,
                "Description": "Test",
                "DataClasses": [],
            },
        ]

        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response

            async with HIBPClient(config) as client:
                breaches = await client.list_breaches()

            assert len(breaches) == 2
            assert breaches[0].name == "Adobe"
            assert breaches[1].name == "LinkedIn"

    @pytest.mark.asyncio
    async def test_list_breaches_with_domain_filter(self) -> None:
        """List breaches filtered by domain."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = []

            async with HIBPClient(config) as client:
                await client.list_breaches(domain="adobe.com")

            # Verify the request was made with domain parameter
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            assert call_args[1]["params"]["domain"] == "adobe.com"

    @pytest.mark.asyncio
    async def test_check_pastes(self) -> None:
        """Check if email appears in pastes."""
        mock_response = [
            {
                "Source": "Pastebin",
                "Id": "AbCdEfGh",
                "Title": "Leaked Emails",
                "Date": "2020-01-15T12:30:00Z",
                "EmailCount": 150,
            }
        ]

        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response

            async with HIBPClient(config) as client:
                pastes = await client.check_pastes("test@example.com")

            assert len(pastes) == 1
            assert pastes[0].source == "Pastebin"
            assert pastes[0].id == "AbCdEfGh"
            assert pastes[0].email_count == 150


class TestHIBPClientErrorHandling:
    """Tests for HIBP client error handling."""

    @pytest.mark.asyncio
    async def test_invalid_api_key(self) -> None:
        """Handle 401 unauthorized response."""
        config = HIBPConfig(api_key="invalid-key", rate_limit_delay=0)

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.request.return_value = mock_response
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                with pytest.raises(ClientError) as exc_info:
                    await client.check_email("test@example.com")

            assert "invalid or missing" in str(exc_info.value).lower()
            assert exc_info.value.context.get("status_code") == 401

    @pytest.mark.asyncio
    async def test_rate_limiting_with_retry(self) -> None:
        """Handle 429 rate limit with retry."""
        config = HIBPConfig(
            api_key="test-key",
            rate_limit_delay=0,
            max_retries=2,
            retry_base_delay=0.01,  # Fast for testing
        )

        mock_429_response = MagicMock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {}

        mock_200_response = MagicMock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = []

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            # First request: 429, second request: 200
            mock_client.request.side_effect = [mock_429_response, mock_200_response]
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                breaches = await client.check_email("test@example.com")

            assert breaches == []
            assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_rate_limiting_exhausted(self) -> None:
        """Handle 429 rate limit when retries exhausted."""
        config = HIBPConfig(
            api_key="test-key",
            rate_limit_delay=0,
            max_retries=1,
            retry_base_delay=0.01,
        )

        mock_429_response = MagicMock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {}

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.request.return_value = mock_429_response
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                with pytest.raises(ClientError) as exc_info:
                    await client.check_email("test@example.com")

            assert "rate limit" in str(exc_info.value).lower()
            assert exc_info.value.context.get("status_code") == 429

    @pytest.mark.asyncio
    async def test_rate_limiting_with_retry_after_header(self) -> None:
        """Respect Retry-After header in 429 response."""
        config = HIBPConfig(
            api_key="test-key",
            rate_limit_delay=0,
            max_retries=2,
            retry_base_delay=0.01,
        )

        mock_429_response = MagicMock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {"Retry-After": "0.01"}

        mock_200_response = MagicMock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = []

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.request.side_effect = [mock_429_response, mock_200_response]
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                breaches = await client.check_email("test@example.com")

            assert breaches == []

    @pytest.mark.asyncio
    async def test_connection_error(self) -> None:
        """Handle connection errors."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.request.side_effect = httpx.ConnectError("Connection refused")
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                with pytest.raises(ClientError) as exc_info:
                    await client.check_email("test@example.com")

            assert "Failed to connect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_error(self) -> None:
        """Handle HTTP errors."""
        config = HIBPConfig(api_key="test-key", rate_limit_delay=0)

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=mock_response,
        )

        with patch.object(HIBPClient, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.request.return_value = mock_response
            mock_get_client.return_value = mock_client

            async with HIBPClient(config) as client:
                with pytest.raises(ClientError) as exc_info:
                    await client.check_email("test@example.com")

            assert exc_info.value.context.get("status_code") == 500
