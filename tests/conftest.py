"""Pytest fixtures for Black Box tests."""

import pytest
import pytest_asyncio

from blackbox.db.session import create_test_engine, reset_engine


@pytest.fixture(autouse=True)
def reset_db_engine():
    """Reset database engine before each test."""
    reset_engine()
    yield
    reset_engine()


@pytest_asyncio.fixture
async def db_session():
    """Create a test database session."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    engine, factory = await create_test_engine()

    async with factory() as session:
        yield session

    await engine.dispose()
