"""Scheduler service for Black Box.

Runs automated syncs, pattern detection, and digest generation
using APScheduler. Follows Juno's autonomous loop patterns for
signal handling and graceful shutdown.
"""

import asyncio
import signal
from datetime import datetime
from pathlib import Path
from typing import Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from blackbox.config import get_settings
from blackbox.scheduler.jobs import (
    run_detection,
    run_digest,
    run_earnings_sync,
    run_github_sync,
    run_hibp_sync,
    run_noaa_sync,
    run_nvd_sync,
    run_rss_sync,
    run_sec_sync,
)

log = structlog.get_logger(__name__)

# State file for monitoring (relative to working directory)
STATE_FILE = Path("data/.scheduler_state")


class SchedulerService:
    """APScheduler-based service for automated Black Box operations.

    Schedules and runs:
    - RSS feed sync (default: every 30 min)
    - HIBP breach check (default: daily)
    - NVD CVE sync (default: every 4 hours)
    - GitHub Advisory sync (default: every 6 hours)
    - NOAA weather alerts (default: hourly)
    - Earnings calendar sync (default: every 6 hours)
    - SEC filings sync (default: every 2 hours)
    - Pattern detection (default: hourly)
    - Digest generation (default: daily)
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self.scheduler: AsyncIOScheduler | None = None
        self._shutdown_event = asyncio.Event()

    def _update_state(self, status: str, details: str = "") -> None:
        """Update state file for monitoring."""
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().isoformat()
        STATE_FILE.write_text(f"{timestamp}|{status}|{details}")

    def _setup_scheduler(self) -> AsyncIOScheduler:
        """Create and configure the scheduler with all jobs."""
        scheduler = AsyncIOScheduler()

        # RSS sync
        scheduler.add_job(
            run_rss_sync,
            IntervalTrigger(minutes=self.settings.rss_sync_interval),
            id="rss_sync",
            name="RSS Feed Sync",
            max_instances=1,
        )

        # HIBP sync
        scheduler.add_job(
            run_hibp_sync,
            IntervalTrigger(minutes=self.settings.hibp_sync_interval),
            id="hibp_sync",
            name="HIBP Breach Check",
            max_instances=1,
        )

        # NVD sync
        scheduler.add_job(
            run_nvd_sync,
            IntervalTrigger(minutes=self.settings.nvd_sync_interval),
            id="nvd_sync",
            name="NVD CVE Sync",
            max_instances=1,
        )

        # GitHub Advisory sync
        scheduler.add_job(
            run_github_sync,
            IntervalTrigger(minutes=self.settings.github_sync_interval),
            id="github_sync",
            name="GitHub Advisory Sync",
            max_instances=1,
        )

        # NOAA sync
        scheduler.add_job(
            run_noaa_sync,
            IntervalTrigger(minutes=self.settings.noaa_sync_interval),
            id="noaa_sync",
            name="NOAA Weather Alerts",
            max_instances=1,
        )

        # Earnings calendar sync
        scheduler.add_job(
            run_earnings_sync,
            IntervalTrigger(minutes=self.settings.earnings_sync_interval),
            id="earnings_sync",
            name="Earnings Calendar Sync",
            max_instances=1,
        )

        # SEC filings sync
        scheduler.add_job(
            run_sec_sync,
            IntervalTrigger(minutes=self.settings.sec_sync_interval),
            id="sec_sync",
            name="SEC Filings Sync",
            max_instances=1,
        )

        # Pattern detection
        scheduler.add_job(
            run_detection,
            IntervalTrigger(minutes=self.settings.detection_interval),
            id="detection",
            name="Pattern Detection",
            max_instances=1,
        )

        # Digest generation
        scheduler.add_job(
            run_digest,
            IntervalTrigger(minutes=self.settings.digest_interval),
            id="digest",
            name="Digest Generation",
            max_instances=1,
        )

        return scheduler

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        log.info("Received shutdown signal", signal=signum)
        self._shutdown_event.set()

    async def run(self, run_once: bool = False) -> None:
        """Run the scheduler.

        Args:
            run_once: If True, run all jobs once and exit (for testing)
        """
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        log.info("Starting Black Box scheduler")
        self._update_state("starting")

        if run_once:
            # Run all jobs once for testing
            log.info("Running all jobs once (--once mode)")
            await self._run_all_jobs()
            self._update_state("completed", "once mode")
            return

        # Set up and start scheduler
        self.scheduler = self._setup_scheduler()
        self.scheduler.start()

        jobs = self.scheduler.get_jobs()
        log.info(
            "Scheduler started",
            jobs=len(jobs),
            rss_interval=f"{self.settings.rss_sync_interval}m",
            hibp_interval=f"{self.settings.hibp_sync_interval}m",
            detection_interval=f"{self.settings.detection_interval}m",
            digest_interval=f"{self.settings.digest_interval}m",
        )
        self._update_state("running", f"jobs={len(jobs)}")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

        log.info("Shutting down scheduler")
        self.scheduler.shutdown(wait=True)
        self._update_state("stopped", "clean shutdown")

    async def _run_all_jobs(self) -> None:
        """Run all jobs once (for --once mode)."""
        jobs: list[tuple[str, Callable]] = [
            ("RSS sync", run_rss_sync),
            ("HIBP sync", run_hibp_sync),
            ("NVD sync", run_nvd_sync),
            ("GitHub sync", run_github_sync),
            ("NOAA sync", run_noaa_sync),
            ("Earnings sync", run_earnings_sync),
            ("SEC sync", run_sec_sync),
            ("Detection", run_detection),
            ("Digest", run_digest),
        ]

        for name, job_func in jobs:
            log.info(f"Running {name}...")
            try:
                await job_func()
            except Exception as e:
                log.error(f"{name} failed", error=str(e))

    async def run_job(self, job_id: str) -> bool:
        """Run a specific job immediately.

        Args:
            job_id: One of "rss_sync", "hibp_sync", "nvd_sync", "github_sync",
                    "noaa_sync", "earnings_sync", "sec_sync", "detection", "digest"

        Returns:
            True if job executed, False if job_id not found.
        """
        job_map = {
            "rss_sync": run_rss_sync,
            "hibp_sync": run_hibp_sync,
            "nvd_sync": run_nvd_sync,
            "github_sync": run_github_sync,
            "noaa_sync": run_noaa_sync,
            "earnings_sync": run_earnings_sync,
            "sec_sync": run_sec_sync,
            "detection": run_detection,
            "digest": run_digest,
        }

        if job_id not in job_map:
            log.error("Unknown job", job_id=job_id)
            return False

        await job_map[job_id]()
        return True
