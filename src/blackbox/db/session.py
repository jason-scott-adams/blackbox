"""Database session management for Black Box.

Provides async SQLAlchemy session management for SQLite with proper
configuration for async operations (check_same_thread=False).
"""

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from blackbox.db.models import Base

# Default database location
DEFAULT_DB_PATH = Path("data/blackbox.db")

# Global engine and session factory (lazily initialized)
_engine = None
_async_session_factory = None


def get_database_url(db_path: Path | str | None = None) -> str:
    """Get the SQLite database URL.

    Args:
        db_path: Optional path to the database file. If not provided,
                 uses BLACKBOX_DB_PATH env var or default location.

    Returns:
        SQLite connection URL for async operations.
    """
    if db_path is None:
        db_path = os.environ.get("BLACKBOX_DB_PATH", str(DEFAULT_DB_PATH))

    db_path = Path(db_path)

    # Ensure parent directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Use aiosqlite driver for async operations
    # check_same_thread=False is required for async SQLite
    return f"sqlite+aiosqlite:///{db_path}?check_same_thread=False"


def get_test_database_url() -> str:
    """Get an in-memory SQLite URL for testing."""
    return "sqlite+aiosqlite:///:memory:?check_same_thread=False"


def _get_engine_and_session():
    """Get or create the engine and session factory."""
    global _engine, _async_session_factory

    if _engine is None:
        url = get_database_url()
        _engine = create_async_engine(
            url,
            echo=os.environ.get("BLACKBOX_DB_ECHO", "").lower() == "true",
            pool_pre_ping=True,
        )
        _async_session_factory = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    return _engine, _async_session_factory


def get_engine():
    """Get the SQLAlchemy async engine."""
    eng, _ = _get_engine_and_session()
    return eng


def get_session_factory():
    """Get the async session factory."""
    _, factory = _get_engine_and_session()
    return factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for getting an async database session.

    Usage:
        async with get_session() as session:
            result = await session.execute(select(EntityModel))
    """
    _, factory = _get_engine_and_session()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all_tables(engine_override=None) -> None:
    """Create all database tables.

    Args:
        engine_override: Optional engine to use instead of the global one.
    """
    eng = engine_override
    if eng is None:
        eng, _ = _get_engine_and_session()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all_tables(engine_override=None) -> None:
    """Drop all database tables.

    Args:
        engine_override: Optional engine to use instead of the global one.
    """
    eng = engine_override
    if eng is None:
        eng, _ = _get_engine_and_session()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def init_db(db_path: Path | str | None = None) -> None:
    """Initialize the database with all tables.

    This is a convenience function that creates the engine and all tables.

    Args:
        db_path: Optional path to the database file.
    """
    global _engine, _async_session_factory

    url = get_database_url(db_path)
    _engine = create_async_engine(
        url,
        echo=os.environ.get("BLACKBOX_DB_ECHO", "").lower() == "true",
        pool_pre_ping=True,
    )
    _async_session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    await create_all_tables(_engine)


def reset_engine() -> None:
    """Reset the global engine and session factory.

    Useful for testing or when switching databases.
    """
    global _engine, _async_session_factory
    _engine = None
    _async_session_factory = None


async def create_test_engine():
    """Create an in-memory engine for testing.

    Returns:
        Tuple of (engine, session_factory) configured for testing.
    """
    url = get_test_database_url()
    test_engine = create_async_engine(
        url,
        echo=False,
        pool_pre_ping=True,
    )
    test_session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    return test_engine, test_session_factory
