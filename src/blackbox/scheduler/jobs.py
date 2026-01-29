"""Job wrappers for scheduler.

Each job wraps existing sync/detect/digest logic with error handling
and logging. Jobs catch exceptions to prevent one failure from
affecting the scheduler.
"""

import structlog

log = structlog.get_logger(__name__)


async def run_rss_sync() -> bool:
    """Run RSS feed sync job.

    Returns:
        True if sync succeeded, False otherwise.
    """
    from blackbox.db.session import init_db
    from blackbox.sync.rss_sync import create_all_news_sync_service

    try:
        await init_db()

        async with create_all_news_sync_service() as sync_service:
            result = await sync_service.sync()

        log.info(
            "RSS sync complete",
            feeds_succeeded=result.feeds_succeeded,
            feeds_failed=result.feeds_failed,
            entries_created=result.entries_created,
        )
        return result.feeds_succeeded > 0

    except Exception as e:
        log.error("RSS sync failed", error=str(e))
        return False


async def run_hibp_sync() -> bool:
    """Run HIBP breach check job.

    Skips silently if HIBP is not configured.

    Returns:
        True if sync succeeded or was skipped, False on error.
    """
    from blackbox.clients.hibp import HIBPConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.hibp_sync import HIBPSyncConfig, HIBPSyncService

    try:
        settings = get_settings()

        # Skip if not configured
        if not settings.hibp_api_key:
            log.debug("HIBP not configured (no API key), skipping")
            return True

        emails = settings.hibp_email_list
        if not emails:
            log.debug("HIBP not configured (no emails), skipping")
            return True

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            sync_config = HIBPSyncConfig(
                hibp_config=HIBPConfig(api_key=settings.hibp_api_key),
                emails=emails,
                create_activities=True,
                create_alerts=True,
            )

            async with HIBPSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "HIBP sync complete",
            emails_checked=result.emails_checked,
            new_breaches=result.new_breaches,
        )
        return True

    except Exception as e:
        log.error("HIBP sync failed", error=str(e))
        return False


async def run_nvd_sync() -> bool:
    """Run NVD CVE sync job.

    Returns:
        True if sync succeeded, False otherwise.
    """
    from blackbox.clients.nvd import NVDConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.nvd_sync import NVDSyncConfig, NVDSyncService

    try:
        settings = get_settings()

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            nvd_config = NVDConfig(api_key=settings.nvd_api_key)
            sync_config = NVDSyncConfig(nvd_config=nvd_config)

            async with NVDSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "NVD sync complete",
            cves_found=result.cves_found,
            activities_created=result.activities_created,
        )
        return True

    except Exception as e:
        log.error("NVD sync failed", error=str(e))
        return False


async def run_github_sync() -> bool:
    """Run GitHub Security Advisories sync job.

    Returns:
        True if sync succeeded, False otherwise.
    """
    from blackbox.clients.github_advisory import GitHubAdvisoryConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.github_sync import GitHubSyncConfig, GitHubSyncService

    try:
        settings = get_settings()

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            github_config = GitHubAdvisoryConfig(token=settings.github_token)
            sync_config = GitHubSyncConfig(github_config=github_config)

            async with GitHubSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "GitHub sync complete",
            advisories_found=result.advisories_found,
            activities_created=result.activities_created,
        )
        return True

    except Exception as e:
        log.error("GitHub sync failed", error=str(e))
        return False


async def run_noaa_sync() -> bool:
    """Run NOAA weather alerts sync job.

    Returns:
        True if sync succeeded, False otherwise.
    """
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.noaa_sync import NOAASyncConfig, NOAASyncService

    try:
        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            sync_config = NOAASyncConfig(areas=["MO", "KS"])

            async with NOAASyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "NOAA sync complete",
            alerts_found=result.alerts_found,
            activities_created=result.activities_created,
        )
        return True

    except Exception as e:
        log.error("NOAA sync failed", error=str(e))
        return False


async def run_earnings_sync() -> bool:
    """Run earnings calendar sync job.

    Skips silently if no symbols are tracked.

    Returns:
        True if sync succeeded or was skipped, False on error.
    """
    from blackbox.clients.earnings import EarningsConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.earnings_sync import EarningsSyncConfig, EarningsSyncService

    try:
        settings = get_settings()

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            earnings_config = EarningsConfig(api_key=settings.finnhub_api_key)
            sync_config = EarningsSyncConfig(
                earnings_config=earnings_config,
                tracked_symbols=settings.sec_tracked_companies_list,
            )

            async with EarningsSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "Earnings sync complete",
            events_found=result.events_found,
            activities_created=result.activities_created,
        )
        return True

    except Exception as e:
        log.error("Earnings sync failed", error=str(e))
        return False


async def run_sec_sync() -> bool:
    """Run SEC EDGAR filings sync job.

    Returns:
        True if sync succeeded, False otherwise.
    """
    from blackbox.clients.sec import SECConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.sec_sync import SECSyncConfig, SECSyncService

    try:
        settings = get_settings()

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            sec_config = SECConfig(user_agent=settings.sec_user_agent)
            sync_config = SECSyncConfig(
                sec_config=sec_config,
                tracked_companies=settings.sec_tracked_companies_list,
            )

            async with SECSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "SEC sync complete",
            filings_found=result.filings_found,
            activities_created=result.activities_created,
        )
        return True

    except Exception as e:
        log.error("SEC sync failed", error=str(e))
        return False


async def run_detection() -> bool:
    """Run pattern detection job.

    Returns:
        True if detection succeeded, False otherwise.
    """
    from blackbox.config import get_settings
    from blackbox.db.repositories import (
        SQLiteActivityRepository,
        SQLiteAlertRepository,
        SQLiteEntityRepository,
    )
    from blackbox.db.session import get_session, init_db
    from blackbox.detectors import (
        AnomalyDetector,
        BrokerDetector,
        CascadeDetector,
        RhymeDetector,
        SilenceDetector,
        create_earnings_proximity_detector,
    )

    try:
        settings = get_settings()

        await init_db()

        async with get_session() as session:
            entity_repo = SQLiteEntityRepository(session)
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            entities = await entity_repo.list(limit=1000)
            activities = await activity_repo.list(limit=10000)

            if not activities:
                log.debug("No activities for detection")
                return True

            total_alerts = 0

            # Run silence detector
            silence_detector = SilenceDetector()
            alerts = await silence_detector.detect(entities, activities)
            for alert in alerts:
                await alert_repo.create(alert)
            total_alerts += len(alerts)

            # Run anomaly detector
            anomaly_detector = AnomalyDetector()
            alerts = await anomaly_detector.detect(entities, activities)
            for alert in alerts:
                await alert_repo.create(alert)
            total_alerts += len(alerts)

            # Run cascade detector
            cascade_detector = CascadeDetector()
            alerts = await cascade_detector.detect(entities, activities)
            for alert in alerts:
                await alert_repo.create(alert)
            total_alerts += len(alerts)

            # Run broker detector
            broker_detector = BrokerDetector()
            alerts = await broker_detector.detect(entities, activities)
            for alert in alerts:
                await alert_repo.create(alert)
            total_alerts += len(alerts)

            # Run rhyme detector
            rhyme_detector = RhymeDetector()
            alerts = await rhyme_detector.detect(entities, activities)
            for alert in alerts:
                await alert_repo.create(alert)
            total_alerts += len(alerts)

            # Run earnings proximity detector
            tracked_symbols = settings.sec_tracked_companies_list
            if tracked_symbols:
                earnings_detector = create_earnings_proximity_detector(tracked_symbols)
                earnings_alerts = await earnings_detector.detect(entities, activities)
                for alert in earnings_alerts:
                    await alert_repo.create(alert)
                total_alerts += len(earnings_alerts)

        log.info("Detection complete", alerts_created=total_alerts)
        return True

    except Exception as e:
        log.error("Detection failed", error=str(e))
        return False


def _load_watch_topics() -> list[str]:
    """Load watch topics from Juno's watches file."""
    import re
    from pathlib import Path

    watches_file = Path("/home/atoms/.claude/MEMORY/context/watches.md")
    if not watches_file.exists():
        return []

    content = watches_file.read_text()
    topics = []

    # Match: - **topic** — Added YYYY-MM-DD
    pattern = r"- \*\*(.+?)\*\* — Added"
    for match in re.finditer(pattern, content):
        topics.append(match.group(1))

    return topics


async def run_digest() -> bool:
    """Run digest generation job.

    Only writes digest if there are items to report.

    Returns:
        True if generation succeeded, False otherwise.
    """
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.digest import DigestConfig, DigestGenerator

    try:
        await init_db()

        # Load watch topics from Juno
        watch_topics = _load_watch_topics()
        if watch_topics:
            log.info("Loaded watch topics", topics=watch_topics)

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            activities = await activity_repo.list(limit=1000)
            alerts = await alert_repo.list(limit=500)

        config = DigestConfig()
        generator = DigestGenerator(config, watch_topics=watch_topics)
        digest = generator.generate(activities, alerts)

        # Only write if there's something to report
        if digest.items or digest.flags_for_review:
            filepath = generator.write_digest(digest)
            log.info("Digest written", path=str(filepath), items=len(digest.items))
        else:
            log.debug("No items for digest")

        return True

    except Exception as e:
        log.error("Digest generation failed", error=str(e))
        return False
