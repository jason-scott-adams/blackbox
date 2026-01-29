"""Command-line interface for Black Box.

CLI for sync, detect, and digest commands.
"""

import argparse
import asyncio
import sys

import structlog

# Configure structlog for simple console output
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)


def get_logger(name: str):
    """Get a structured logger."""
    return structlog.get_logger(name)


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="blackbox",
        description="Black Box: Personal OSINT pattern detection system",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Database commands
    db_parser = subparsers.add_parser("db", help="Database management")
    db_subparsers = db_parser.add_subparsers(dest="db_command", help="Database commands")

    db_init_parser = db_subparsers.add_parser("init", help="Initialize the database")
    db_init_parser.add_argument(
        "--path",
        default=None,
        help="Path to database file (default: data/blackbox.db)",
    )

    db_subparsers.add_parser("status", help="Show database status")

    db_reset_parser = db_subparsers.add_parser("reset", help="Reset the database")
    db_reset_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Sync commands
    sync_parser = subparsers.add_parser("sync", help="Sync data sources")
    sync_subparsers = sync_parser.add_subparsers(dest="sync_command", help="Sync commands")

    sync_subparsers.add_parser("rss", help="Sync RSS feeds")
    sync_subparsers.add_parser("hibp", help="Check HIBP for breaches")
    sync_subparsers.add_parser("nvd", help="Sync NVD vulnerabilities")
    sync_subparsers.add_parser("github", help="Sync GitHub security advisories")
    sync_subparsers.add_parser("noaa", help="Sync NOAA weather alerts")
    sync_subparsers.add_parser("earnings", help="Sync earnings calendar")
    sync_subparsers.add_parser("sec", help="Sync SEC EDGAR filings")
    sync_subparsers.add_parser("all", help="Run all syncs")

    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Run pattern detectors")
    detect_parser.add_argument(
        "detector",
        nargs="?",
        default="all",
        choices=["all", "silence", "earnings", "anomaly", "cascade", "broker", "rhyme"],
        help="Detector to run (default: all)",
    )

    # Digest command
    digest_parser = subparsers.add_parser("digest", help="Generate digest")
    digest_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview without writing",
    )
    digest_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours of activity to include (default: 24)",
    )

    # Serve command (scheduler)
    serve_parser = subparsers.add_parser("serve", help="Run the scheduler daemon")
    serve_parser.add_argument(
        "--once",
        action="store_true",
        help="Run all jobs once and exit (for testing)",
    )

    # Check command
    subparsers.add_parser("check", help="System health check")

    args = parser.parse_args()

    if args.command == "db":
        return run_db(args, db_parser)
    elif args.command == "sync":
        return run_sync(args, sync_parser)
    elif args.command == "detect":
        return run_detect(args)
    elif args.command == "digest":
        return run_digest(args)
    elif args.command == "serve":
        return run_serve(args)
    elif args.command == "check":
        return run_check()
    else:
        parser.print_help()
        return 0


def run_db(args: argparse.Namespace, db_parser: argparse.ArgumentParser) -> int:
    """Handle database commands."""
    log = get_logger("db")

    if args.db_command == "init":
        return asyncio.run(db_init(args.path, log))
    elif args.db_command == "status":
        return asyncio.run(db_status(log))
    elif args.db_command == "reset":
        return asyncio.run(db_reset(args.force, log))
    else:
        db_parser.print_help()
        return 0


async def db_init(db_path: str | None, log) -> int:
    """Initialize the database."""
    from pathlib import Path

    from blackbox.db.session import get_database_url, init_db

    try:
        path = Path(db_path) if db_path else None
        url = get_database_url(path)
        log.info("Initializing database", url=url)

        await init_db(path)
        log.info("Database initialized successfully")
        return 0
    except Exception as e:
        log.error("Failed to initialize database", error=str(e))
        return 1


async def db_status(log) -> int:
    """Show database status."""
    import os
    from pathlib import Path

    from blackbox.db.session import DEFAULT_DB_PATH, get_database_url

    try:
        env_path = os.environ.get("BLACKBOX_DB_PATH")
        db_path = Path(env_path) if env_path else DEFAULT_DB_PATH

        url = get_database_url(db_path)
        log.info("Database configuration", url=url)

        if db_path.exists():
            size_bytes = db_path.stat().st_size
            size_kb = size_bytes / 1024
            log.info("Database file exists", path=str(db_path), size_kb=f"{size_kb:.2f}")

            # Connect and count records
            from blackbox.db.session import init_db

            await init_db(db_path)

            from blackbox.db.session import get_session

            async with get_session() as session:
                from sqlalchemy import text

                tables = ["entities", "activities", "alerts", "detection_runs", "sync_configs"]
                for table in tables:
                    try:
                        result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        log.info(f"Table: {table}", count=count)
                    except Exception:
                        log.warning(f"Table {table} does not exist")
        else:
            log.warning("Database file does not exist", path=str(db_path))
            log.info("Run 'blackbox db init' to create the database")

        return 0
    except Exception as e:
        log.error("Failed to get database status", error=str(e))
        return 1


async def db_reset(force: bool, log) -> int:
    """Reset the database."""
    from blackbox.db.session import create_all_tables, drop_all_tables, init_db

    try:
        if not force:
            response = input("This will DELETE ALL DATA. Continue? [y/N] ")
            if response.lower() != "y":
                log.info("Aborted")
                return 0

        log.info("Resetting database")

        await init_db()
        await drop_all_tables()
        log.info("Dropped all tables")

        await create_all_tables()
        log.info("Recreated all tables")

        log.info("Database reset complete")
        return 0
    except Exception as e:
        log.error("Failed to reset database", error=str(e))
        return 1


def run_sync(args: argparse.Namespace, sync_parser: argparse.ArgumentParser) -> int:
    """Handle sync commands."""
    log = get_logger("sync")

    if args.sync_command == "rss":
        return asyncio.run(sync_rss(log))
    elif args.sync_command == "hibp":
        return asyncio.run(sync_hibp(log))
    elif args.sync_command == "nvd":
        return asyncio.run(sync_nvd(log))
    elif args.sync_command == "github":
        return asyncio.run(sync_github(log))
    elif args.sync_command == "noaa":
        return asyncio.run(sync_noaa(log))
    elif args.sync_command == "earnings":
        return asyncio.run(sync_earnings(log))
    elif args.sync_command == "sec":
        return asyncio.run(sync_sec(log))
    elif args.sync_command == "all":
        return asyncio.run(sync_all(log))
    else:
        sync_parser.print_help()
        return 0


async def sync_rss(log) -> int:
    """Sync RSS feeds."""
    from blackbox.db.session import init_db
    from blackbox.sync.rss_sync import create_all_news_sync_service

    try:
        # Initialize database
        await init_db()

        # Create and run sync service
        async with create_all_news_sync_service() as sync_service:
            result = await sync_service.sync()

        log.info(
            "RSS sync complete",
            feeds_succeeded=result.feeds_succeeded,
            feeds_failed=result.feeds_failed,
            entries_created=result.entries_created,
            entries_skipped=result.entries_skipped,
            duration_seconds=f"{result.duration_seconds:.2f}" if result.duration_seconds else None,
        )

        if result.errors:
            for error in result.errors[:5]:  # Show first 5 errors
                log.warning("Feed error", error=error)

        return 0 if result.feeds_succeeded > 0 else 1

    except Exception as e:
        log.error("RSS sync failed", error=str(e))
        return 1


async def sync_hibp(log) -> int:
    """Sync HIBP breach data."""
    from blackbox.clients.hibp import HIBPConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.hibp_sync import HIBPSyncConfig, HIBPSyncService

    try:
        settings = get_settings()

        # Check for API key
        if not settings.hibp_api_key:
            log.error("HIBP API key not configured. Set BLACKBOX_HIBP_API_KEY in .env")
            return 1

        # Check for emails to monitor
        emails = settings.hibp_email_list
        if not emails:
            log.error("No emails configured. Set BLACKBOX_HIBP_EMAILS in .env")
            return 1

        log.info("Starting HIBP sync", email_count=len(emails))

        # Initialize database
        await init_db()

        # Create sync service with repositories
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
            breaches_found=result.breaches_found,
            new_breaches=result.new_breaches,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        if result.errors:
            for error in result.errors[:5]:  # Show first 5 errors
                log.warning("HIBP error", error=error)

        return 0 if result.emails_checked > 0 else 1

    except Exception as e:
        log.error("HIBP sync failed", error=str(e))
        return 1


async def sync_nvd(log) -> int:
    """Sync NVD CVE data."""
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.nvd_sync import NVDSyncConfig, NVDSyncService

    try:
        settings = get_settings()

        log.info("Starting NVD sync")

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Configure NVD sync with optional API key
            from blackbox.clients.nvd import NVDConfig

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
            cves_tracked=result.cves_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        return 0

    except Exception as e:
        log.error("NVD sync failed", error=str(e))
        return 1


async def sync_github(log) -> int:
    """Sync GitHub Security Advisories."""
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.github_sync import GitHubSyncConfig, GitHubSyncService

    try:
        settings = get_settings()

        log.info("Starting GitHub Advisory sync")

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Configure GitHub sync with optional token
            from blackbox.clients.github_advisory import GitHubAdvisoryConfig

            github_config = GitHubAdvisoryConfig(token=settings.github_token)
            sync_config = GitHubSyncConfig(github_config=github_config)

            async with GitHubSyncService(
                config=sync_config,
                activity_repository=activity_repo,
                alert_repository=alert_repo,
            ) as sync_service:
                result = await sync_service.sync()

        log.info(
            "GitHub Advisory sync complete",
            advisories_found=result.advisories_found,
            advisories_tracked=result.advisories_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        return 0

    except Exception as e:
        log.error("GitHub sync failed", error=str(e))
        return 1


async def sync_noaa(log) -> int:
    """Sync NOAA weather alerts."""
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.noaa_sync import NOAASyncConfig, NOAASyncService

    try:
        log.info("Starting NOAA sync")

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
            alerts_tracked=result.alerts_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        return 0

    except Exception as e:
        log.error("NOAA sync failed", error=str(e))
        return 1


async def sync_earnings(log) -> int:
    """Sync earnings calendar."""
    from blackbox.clients.earnings import EarningsConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.earnings_sync import EarningsSyncConfig, EarningsSyncService

    try:
        settings = get_settings()

        log.info("Starting earnings sync")

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Configure earnings sync with optional API key
            earnings_config = EarningsConfig(api_key=settings.finnhub_api_key)
            sync_config = EarningsSyncConfig(
                earnings_config=earnings_config,
                tracked_symbols=settings.sec_tracked_companies_list,  # Reuse SEC tracked companies
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
            events_upcoming=result.events_upcoming,
            events_reported=result.events_reported,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        return 0

    except Exception as e:
        log.error("Earnings sync failed", error=str(e))
        return 1


async def sync_sec(log) -> int:
    """Sync SEC EDGAR filings."""
    from blackbox.clients.sec import SECConfig
    from blackbox.config import get_settings
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.sync.sec_sync import SECSyncConfig, SECSyncService

    try:
        settings = get_settings()

        log.info("Starting SEC sync")

        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Configure SEC sync
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
            filings_tracked=result.filings_tracked,
            activities_created=result.activities_created,
            alerts_created=result.alerts_created,
        )

        return 0

    except Exception as e:
        log.error("SEC sync failed", error=str(e))
        return 1


async def sync_all(log) -> int:
    """Run all syncs."""
    log.info("Running all syncs...")

    results = []

    # RSS sync
    results.append(await sync_rss(log))

    # HIBP sync
    results.append(await sync_hibp(log))

    # NVD sync
    results.append(await sync_nvd(log))

    # GitHub sync
    results.append(await sync_github(log))

    # NOAA sync
    results.append(await sync_noaa(log))

    # Earnings sync
    results.append(await sync_earnings(log))

    # SEC sync
    results.append(await sync_sec(log))

    # Return 0 if at least one sync succeeded
    return 0 if any(r == 0 for r in results) else 1


def run_detect(args: argparse.Namespace) -> int:
    """Run pattern detectors."""
    log = get_logger("detect")
    return asyncio.run(detect_patterns(args.detector, log))


async def detect_patterns(detector_name: str, log) -> int:
    """Run pattern detection."""
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
    from blackbox.notifications import notify_voice

    try:
        settings = get_settings()

        # Initialize database
        await init_db()

        async with get_session() as session:
            entity_repo = SQLiteEntityRepository(session)
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Load entities and activities
            entities = await entity_repo.list(limit=1000)
            activities = await activity_repo.list(limit=10000)

            log.info(
                "Loaded data for detection",
                entities=len(entities),
                activities=len(activities),
            )

            if not activities:
                log.info("No activities found. Run sync first.")
                return 0

            total_alerts = 0

            # Run silence detector
            if detector_name in ("all", "silence"):
                log.info("Running silence detector...")
                detector = SilenceDetector()
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Silence detector complete", alerts_generated=len(alerts))

            # Run anomaly detector
            if detector_name in ("all", "anomaly"):
                log.info("Running anomaly detector...")
                detector = AnomalyDetector()
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Anomaly detector complete", alerts_generated=len(alerts))

            # Run cascade detector
            if detector_name in ("all", "cascade"):
                log.info("Running cascade detector...")
                detector = CascadeDetector()
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Cascade detector complete", alerts_generated=len(alerts))

            # Run broker detector
            if detector_name in ("all", "broker"):
                log.info("Running broker detector...")
                detector = BrokerDetector()
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Broker detector complete", alerts_generated=len(alerts))

            # Run rhyme detector
            if detector_name in ("all", "rhyme"):
                log.info("Running rhyme detector...")
                detector = RhymeDetector()
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Rhyme detector complete", alerts_generated=len(alerts))

            # Run earnings proximity detector
            if detector_name in ("all", "earnings"):
                log.info("Running earnings proximity detector...")
                tracked_symbols = settings.sec_tracked_companies_list
                detector = create_earnings_proximity_detector(tracked_symbols)
                alerts = await detector.detect(entities, activities)

                for alert in alerts:
                    await alert_repo.create(alert)
                    await notify_voice(alert)
                    log.info(
                        "Alert created",
                        type=alert.alert_type.value,
                        severity=alert.severity.value,
                        title=alert.title,
                        confidence=f"{alert.confidence:.2f}",
                    )

                total_alerts += len(alerts)
                log.info("Earnings proximity detector complete", alerts_generated=len(alerts))

            log.info("Detection complete", total_alerts=total_alerts)
            return 0

    except Exception as e:
        log.error("Detection failed", error=str(e))
        return 1


def run_digest(args: argparse.Namespace) -> int:
    """Generate digest."""
    log = get_logger("digest")
    return asyncio.run(generate_digest(args.dry_run, args.hours, log))


async def generate_digest(dry_run: bool, lookback_hours: int, log) -> int:
    """Generate and write digest."""
    from blackbox.db.repositories import SQLiteActivityRepository, SQLiteAlertRepository
    from blackbox.db.session import get_session, init_db
    from blackbox.digest import DigestConfig, DigestGenerator

    try:
        # Initialize database
        await init_db()

        async with get_session() as session:
            activity_repo = SQLiteActivityRepository(session)
            alert_repo = SQLiteAlertRepository(session)

            # Fetch recent data
            activities = await activity_repo.list(limit=1000)
            alerts = await alert_repo.list(limit=500)

            log.info(
                "Loaded data for digest",
                activities=len(activities),
                alerts=len(alerts),
            )

            # Generate digest
            config = DigestConfig(lookback_hours=lookback_hours)
            generator = DigestGenerator(config)
            digest = generator.generate(activities, alerts)

            log.info(
                "Digest generated",
                items=len(digest.items),
                flags=len(digest.flags_for_review),
                summary=digest.summary[:100] + "..." if len(digest.summary) > 100 else digest.summary,
            )

            if dry_run:
                # Print digest to console
                import json
                print("\n--- DIGEST PREVIEW ---")
                print(json.dumps(digest.model_dump(), indent=2, default=str))
                print("--- END PREVIEW ---\n")
                log.info("Dry run complete - no file written")
                return 0

            # Write digest
            filepath = generator.write_digest(digest)
            log.info("Digest written", path=str(filepath))

            return 0

    except Exception as e:
        log.error("Digest generation failed", error=str(e))
        return 1


def run_serve(args: argparse.Namespace) -> int:
    """Run the scheduler daemon."""
    log = get_logger("serve")
    return asyncio.run(serve_scheduler(args.once, log))


async def serve_scheduler(run_once: bool, log) -> int:
    """Start the scheduler service."""
    from blackbox.scheduler import SchedulerService

    try:
        service = SchedulerService()
        await service.run(run_once=run_once)
        return 0
    except Exception as e:
        log.error("Scheduler failed", error=str(e))
        return 1


def run_check() -> int:
    """Run system health check."""
    log = get_logger("check")

    log.info("Running system health check...")

    try:
        from blackbox.models import Activity, Alert, Entity  # noqa: F401

        log.info("Core models loaded successfully")
    except ImportError as e:
        log.error("Failed to import core models", error=str(e))
        return 1

    try:
        from blackbox.db import ActivityModel, AlertModel, EntityModel  # noqa: F401

        log.info("Database models loaded successfully")
    except ImportError as e:
        log.error("Failed to import database models", error=str(e))
        return 1

    try:
        from blackbox.config import get_settings

        settings = get_settings()
        log.info("Configuration loaded", db_path=str(settings.db_path))
    except Exception as e:
        log.error("Failed to load configuration", error=str(e))
        return 1

    log.info("System check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
