"""Tests for HIBP sync service."""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from blackbox.clients.hibp import Breach, HIBPConfig, Paste
from blackbox.models.alert import AlertSeverity
from blackbox.sync.hibp_sync import (
    HIBPSyncConfig,
    HIBPSyncResult,
    HIBPSyncService,
    get_hibp_sync_service,
    set_hibp_sync_service,
)


@pytest.fixture
def hibp_config():
    """Create HIBP configuration."""
    return HIBPConfig(api_key="test-key")


@pytest.fixture
def sync_config(hibp_config):
    """Create sync configuration."""
    return HIBPSyncConfig(
        hibp_config=hibp_config,
        emails=["test@example.com", "user@test.com"],
    )


@pytest.fixture
def mock_activity_repo():
    """Create mock activity repository."""
    repo = AsyncMock()
    repo.create = AsyncMock()
    repo.list = AsyncMock(return_value=[])
    return repo


@pytest.fixture
def mock_alert_repo():
    """Create mock alert repository."""
    repo = AsyncMock()
    repo.create = AsyncMock()
    return repo


@pytest.fixture
def sample_breach():
    """Create sample breach data."""
    return Breach(
        name="TestBreach",
        title="Test Breach",
        domain="test.com",
        breach_date="2023-01-15",
        added_date="2023-02-01",
        modified_date="2023-02-15",
        pwn_count=1000000,
        description="A test data breach",
        data_classes=["Emails", "Passwords", "Usernames"],
        is_verified=True,
    )


@pytest.fixture
def sample_breach_no_password():
    """Create sample breach without password exposure."""
    return Breach(
        name="EmailOnlyBreach",
        title="Email Only Breach",
        domain="emailonly.com",
        breach_date="2023-06-01",
        added_date="2023-06-15",
        modified_date="2023-06-20",
        pwn_count=50000,
        description="A breach with only emails exposed",
        data_classes=["Emails"],
        is_verified=True,
    )


class TestHIBPSyncConfig:
    """Tests for HIBPSyncConfig model."""

    def test_default_config(self, hibp_config):
        """Test default configuration values."""
        config = HIBPSyncConfig(hibp_config=hibp_config)
        assert config.emails == []
        assert config.create_activities is True
        assert config.create_alerts is True
        assert config.include_unverified is True

    def test_custom_config(self, hibp_config):
        """Test custom configuration."""
        config = HIBPSyncConfig(
            hibp_config=hibp_config,
            emails=["a@test.com", "b@test.com"],
            create_activities=False,
            create_alerts=False,
            include_unverified=False,
        )
        assert config.emails == ["a@test.com", "b@test.com"]
        assert config.create_activities is False
        assert config.create_alerts is False
        assert config.include_unverified is False


class TestHIBPSyncResult:
    """Tests for HIBPSyncResult model."""

    def test_result_creation(self):
        """Test creating a sync result."""
        result = HIBPSyncResult(
            sync_id="test_sync_123",
            started_at=datetime.now(),
        )
        assert result.sync_id == "test_sync_123"
        assert result.emails_checked == 0
        assert result.breaches_found == 0
        assert result.completed_at is None

    def test_result_with_counts(self):
        """Test result with various counts."""
        result = HIBPSyncResult(
            sync_id="test_sync_456",
            started_at=datetime.now(),
            emails_checked=5,
            breaches_found=10,
            new_breaches=3,
            activities_created=10,
            alerts_created=3,
        )
        assert result.emails_checked == 5
        assert result.breaches_found == 10
        assert result.new_breaches == 3


class TestHIBPSyncService:
    """Tests for HIBPSyncService."""

    @pytest.mark.asyncio
    async def test_init(self, sync_config, mock_activity_repo, mock_alert_repo):
        """Test service initialization."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )
        assert service.config == sync_config
        assert service._client is None

    @pytest.mark.asyncio
    async def test_context_manager(self, sync_config, mock_activity_repo):
        """Test async context manager."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
        )

        async with service as s:
            assert s is service

    @pytest.mark.asyncio
    async def test_check_connection_success(
        self, sync_config, mock_activity_repo
    ):
        """Test successful connection check."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.list_breaches = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            result = await service.check_connection()
            assert result is True

    @pytest.mark.asyncio
    async def test_check_connection_failure(
        self, sync_config, mock_activity_repo
    ):
        """Test failed connection check."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.list_breaches = AsyncMock(side_effect=Exception("Connection failed"))
            mock_get.return_value = mock_client

            result = await service.check_connection()
            assert result is False

    @pytest.mark.asyncio
    async def test_sync_no_emails(self, hibp_config, mock_activity_repo):
        """Test sync with no emails configured."""
        config = HIBPSyncConfig(hibp_config=hibp_config, emails=[])
        service = HIBPSyncService(
            config=config,
            activity_repository=mock_activity_repo,
        )

        result = await service.sync()

        assert result.emails_checked == 0
        assert "No email addresses configured" in result.errors

    @pytest.mark.asyncio
    async def test_sync_creates_activities(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach
    ):
        """Test that sync creates activities for breaches."""
        # Configure for one email only
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            result = await service.sync()

            assert result.emails_checked == 1
            assert result.breaches_found == 1
            assert result.activities_created == 1
            mock_activity_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_creates_alerts_for_new_breaches(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach
    ):
        """Test that sync creates alerts for new breaches."""
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            result = await service.sync()

            assert result.new_breaches == 1
            assert result.alerts_created == 1
            mock_alert_repo.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_no_alerts_for_seen_breaches(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach
    ):
        """Test that sync doesn't create alerts for previously seen breaches."""
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        # Mark breach as seen
        service._seen_breaches["test@example.com"] = {sample_breach.name}

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            # Don't load seen breaches from repo
            with patch.object(service, "load_seen_breaches", new_callable=AsyncMock):
                result = await service.sync()

            assert result.new_breaches == 0
            assert result.alerts_created == 0

    @pytest.mark.asyncio
    async def test_sync_single_email(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach
    ):
        """Test syncing a single email."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            result = await service.sync_single_email("adhoc@test.com")

            assert result.emails_checked == 1
            assert result.breaches_found == 1

    @pytest.mark.asyncio
    async def test_alert_severity_critical_for_passwords(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach
    ):
        """Test that breaches with passwords get critical severity."""
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            await service.sync()

            # Check that alert was created with critical severity
            call_args = mock_alert_repo.create.call_args
            alert = call_args[0][0]
            assert alert.severity == AlertSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_alert_severity_medium_for_email_only(
        self, sync_config, mock_activity_repo, mock_alert_repo, sample_breach_no_password
    ):
        """Test that email-only breaches get medium severity."""
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[sample_breach_no_password])
            mock_client.check_pastes = AsyncMock(return_value=[])
            mock_get.return_value = mock_client

            await service.sync()

            # Check that alert was created with medium severity
            call_args = mock_alert_repo.create.call_args
            alert = call_args[0][0]
            assert alert.severity == AlertSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_sync_tracks_pastes(
        self, sync_config, mock_activity_repo, mock_alert_repo
    ):
        """Test that sync tracks paste counts."""
        sync_config.emails = ["test@example.com"]

        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
            alert_repository=mock_alert_repo,
        )

        sample_paste = Paste(
            source="Pastebin",
            id="ABC123",
            email_count=100,
        )

        with patch.object(service, "_get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_email = AsyncMock(return_value=[])
            mock_client.check_pastes = AsyncMock(return_value=[sample_paste])
            mock_get.return_value = mock_client

            result = await service.sync()

            assert result.pastes_found == 1

    @pytest.mark.asyncio
    async def test_is_new_breach(self, sync_config, mock_activity_repo):
        """Test new breach detection logic."""
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
        )

        # New email, new breach
        assert service._is_new_breach("new@test.com", "SomeBreach") is True

        # Add seen breach
        service._mark_breach_seen("new@test.com", "SomeBreach")

        # Now it's not new
        assert service._is_new_breach("new@test.com", "SomeBreach") is False

        # Different breach for same email is new
        assert service._is_new_breach("new@test.com", "DifferentBreach") is True


class TestGlobalFunctions:
    """Tests for global service functions."""

    def test_get_and_set_service(self, sync_config, mock_activity_repo):
        """Test getting and setting global service."""
        # Initially None
        set_hibp_sync_service(None)
        assert get_hibp_sync_service() is None

        # Set service
        service = HIBPSyncService(
            config=sync_config,
            activity_repository=mock_activity_repo,
        )
        set_hibp_sync_service(service)
        assert get_hibp_sync_service() is service

        # Clean up
        set_hibp_sync_service(None)
