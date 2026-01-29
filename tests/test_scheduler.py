"""Tests for the scheduler service."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestSchedulerService:
    """Tests for SchedulerService."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings with default intervals."""
        settings = MagicMock()
        settings.rss_sync_interval = 30
        settings.hibp_sync_interval = 1440
        settings.nvd_sync_interval = 240
        settings.github_sync_interval = 360
        settings.noaa_sync_interval = 60
        settings.earnings_sync_interval = 360
        settings.sec_sync_interval = 120
        settings.detection_interval = 60
        settings.digest_interval = 1440
        settings.hibp_api_key = ""
        settings.hibp_email_list = []
        settings.nvd_api_key = ""
        settings.github_token = ""
        settings.finnhub_api_key = ""
        settings.sec_tracked_companies_list = []
        return settings

    def test_scheduler_creates_expected_jobs(self, mock_settings):
        """Scheduler should create all expected jobs."""
        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            from blackbox.scheduler.service import SchedulerService

            service = SchedulerService()
            scheduler = service._setup_scheduler()

            jobs = scheduler.get_jobs()
            job_ids = [j.id for j in jobs]

            assert "rss_sync" in job_ids
            assert "hibp_sync" in job_ids
            assert "nvd_sync" in job_ids
            assert "github_sync" in job_ids
            assert "noaa_sync" in job_ids
            assert "earnings_sync" in job_ids
            assert "sec_sync" in job_ids
            assert "detection" in job_ids
            assert "digest" in job_ids
            assert len(jobs) == 9

    def test_scheduler_uses_config_intervals(self, mock_settings):
        """Scheduler should use intervals from settings."""
        mock_settings.rss_sync_interval = 60  # Override to 60 min
        mock_settings.detection_interval = 120  # Override to 120 min

        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            from blackbox.scheduler.service import SchedulerService

            service = SchedulerService()
            scheduler = service._setup_scheduler()

            rss_job = scheduler.get_job("rss_sync")
            detection_job = scheduler.get_job("detection")

            # Check triggers use configured intervals
            assert rss_job.trigger.interval.total_seconds() == 60 * 60  # 60 min
            assert detection_job.trigger.interval.total_seconds() == 120 * 60  # 120 min

    @pytest.mark.asyncio
    async def test_run_once_executes_all_jobs(self, mock_settings):
        """--once flag should run all jobs and exit."""
        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            with patch(
                "blackbox.scheduler.service.run_rss_sync", new_callable=AsyncMock
            ) as mock_rss:
                with patch(
                    "blackbox.scheduler.service.run_hibp_sync", new_callable=AsyncMock
                ) as mock_hibp:
                    with patch(
                        "blackbox.scheduler.service.run_detection", new_callable=AsyncMock
                    ) as mock_detect:
                        with patch(
                            "blackbox.scheduler.service.run_digest", new_callable=AsyncMock
                        ) as mock_digest:
                            from blackbox.scheduler.service import SchedulerService

                            service = SchedulerService()
                            await service.run(run_once=True)

                            mock_rss.assert_called_once()
                            mock_hibp.assert_called_once()
                            mock_detect.assert_called_once()
                            mock_digest.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_job_executes_specific_job(self, mock_settings):
        """run_job should execute a specific job by id."""
        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            with patch(
                "blackbox.scheduler.service.run_rss_sync", new_callable=AsyncMock
            ) as mock_rss:
                from blackbox.scheduler.service import SchedulerService

                service = SchedulerService()
                result = await service.run_job("rss_sync")

                assert result is True
                mock_rss.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_job_returns_false_for_unknown(self, mock_settings):
        """run_job should return False for unknown job id."""
        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            from blackbox.scheduler.service import SchedulerService

            service = SchedulerService()
            result = await service.run_job("unknown_job")

            assert result is False


class TestJobs:
    """Tests for individual job functions."""

    @pytest.mark.asyncio
    async def test_rss_sync_handles_errors(self):
        """RSS sync job should handle errors gracefully."""
        with patch(
            "blackbox.db.session.init_db", new_callable=AsyncMock
        ) as mock_init:
            mock_init.side_effect = Exception("DB error")

            from blackbox.scheduler.jobs import run_rss_sync

            # Should not raise, returns False on error
            result = await run_rss_sync()
            assert result is False

    @pytest.mark.asyncio
    async def test_hibp_sync_skips_when_no_api_key(self):
        """HIBP sync should skip when API key not configured."""
        mock_settings = MagicMock()
        mock_settings.hibp_api_key = ""
        mock_settings.hibp_email_list = []

        with patch("blackbox.config.get_settings", return_value=mock_settings):
            from blackbox.scheduler.jobs import run_hibp_sync

            # Should complete without error, returns True (skipped successfully)
            result = await run_hibp_sync()
            assert result is True

    @pytest.mark.asyncio
    async def test_hibp_sync_skips_when_no_emails(self):
        """HIBP sync should skip when no emails configured."""
        mock_settings = MagicMock()
        mock_settings.hibp_api_key = "test-key"
        mock_settings.hibp_email_list = []

        with patch("blackbox.config.get_settings", return_value=mock_settings):
            from blackbox.scheduler.jobs import run_hibp_sync

            result = await run_hibp_sync()
            assert result is True

    @pytest.mark.asyncio
    async def test_detection_handles_no_activities(self):
        """Detection should handle empty activity list."""
        with patch("blackbox.db.session.init_db", new_callable=AsyncMock):
            mock_session = AsyncMock()
            mock_entity_repo = MagicMock()
            mock_entity_repo.list = AsyncMock(return_value=[])
            mock_activity_repo = MagicMock()
            mock_activity_repo.list = AsyncMock(return_value=[])
            mock_alert_repo = MagicMock()

            with patch("blackbox.db.session.get_session") as mock_get_session:
                mock_get_session.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session
                )
                mock_get_session.return_value.__aexit__ = AsyncMock()

                with patch(
                    "blackbox.db.repositories.SQLiteEntityRepository",
                    return_value=mock_entity_repo,
                ):
                    with patch(
                        "blackbox.db.repositories.SQLiteActivityRepository",
                        return_value=mock_activity_repo,
                    ):
                        with patch(
                            "blackbox.db.repositories.SQLiteAlertRepository",
                            return_value=mock_alert_repo,
                        ):
                            from blackbox.scheduler.jobs import run_detection

                            result = await run_detection()
                            assert result is True

    @pytest.mark.asyncio
    async def test_digest_handles_errors(self):
        """Digest job should handle errors gracefully."""
        with patch(
            "blackbox.db.session.init_db", new_callable=AsyncMock
        ) as mock_init:
            mock_init.side_effect = Exception("DB error")

            from blackbox.scheduler.jobs import run_digest

            result = await run_digest()
            assert result is False


class TestStateFile:
    """Tests for state file management."""

    @pytest.fixture
    def mock_settings(self):
        """Create mock settings."""
        settings = MagicMock()
        settings.rss_sync_interval = 30
        settings.hibp_sync_interval = 1440
        settings.nvd_sync_interval = 240
        settings.github_sync_interval = 360
        settings.noaa_sync_interval = 60
        settings.earnings_sync_interval = 360
        settings.sec_sync_interval = 120
        settings.detection_interval = 60
        settings.digest_interval = 1440
        return settings

    def test_update_state_creates_file(self, tmp_path, mock_settings):
        """State update should create state file."""
        with patch(
            "blackbox.scheduler.service.get_settings", return_value=mock_settings
        ):
            with patch("blackbox.scheduler.service.STATE_FILE", tmp_path / ".state"):
                from blackbox.scheduler.service import SchedulerService

                service = SchedulerService()
                service._update_state("running", "test")

                state_file = tmp_path / ".state"
                assert state_file.exists()
                content = state_file.read_text()
                assert "running" in content
                assert "test" in content
