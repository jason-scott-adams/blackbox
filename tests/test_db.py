"""Tests for database models and session management."""

from datetime import datetime, UTC

import pytest

from blackbox.db.models import ActivityModel, AlertModel, EntityModel
from blackbox.db.session import create_test_engine, get_session, init_db, reset_engine


class TestDatabaseSession:
    """Tests for database session management."""

    @pytest.mark.asyncio
    async def test_create_test_engine(self):
        """Test creating a test engine."""
        engine, factory = await create_test_engine()
        assert engine is not None
        assert factory is not None
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_init_db(self, tmp_path):
        """Test database initialization."""
        db_path = tmp_path / "test.db"
        await init_db(db_path)

        assert db_path.exists()
        reset_engine()


class TestEntityModel:
    """Tests for EntityModel."""

    @pytest.mark.asyncio
    async def test_create_entity(self, db_session):
        """Test creating an entity in the database."""
        from uuid import uuid4

        entity = EntityModel(
            id=str(uuid4()),
            schema_type="Person",
            name="Test Person",
            aliases=["TP"],
            properties={"email": ["test@example.com"]},
            source_refs=[],
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        db_session.add(entity)
        await db_session.commit()

        # Query it back
        from sqlalchemy import select

        result = await db_session.execute(
            select(EntityModel).where(EntityModel.name == "Test Person")
        )
        fetched = result.scalar_one()

        assert fetched.name == "Test Person"
        assert fetched.schema_type == "Person"
        assert "TP" in fetched.aliases


class TestActivityModel:
    """Tests for ActivityModel."""

    @pytest.mark.asyncio
    async def test_create_activity(self, db_session):
        """Test creating an activity in the database."""
        from uuid import uuid4

        # First create an entity
        entity_id = str(uuid4())
        entity = EntityModel(
            id=entity_id,
            schema_type="Person",
            name="Test Person",
            aliases=[],
            properties={},
            source_refs=[],
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        db_session.add(entity)
        await db_session.flush()

        # Create activity
        activity = ActivityModel(
            id=str(uuid4()),
            entity_id=entity_id,
            activity_type="publication",
            source="test",
            description="Test activity",
            occurred_at=datetime.now(UTC),
            recorded_at=datetime.now(UTC),
            source_refs=[],
            metadata_={},
        )
        db_session.add(activity)
        await db_session.commit()

        # Query it back
        from sqlalchemy import select

        result = await db_session.execute(
            select(ActivityModel).where(ActivityModel.description == "Test activity")
        )
        fetched = result.scalar_one()

        assert fetched.activity_type == "publication"
        assert fetched.entity_id == entity_id


class TestAlertModel:
    """Tests for AlertModel."""

    @pytest.mark.asyncio
    async def test_create_alert(self, db_session):
        """Test creating an alert in the database."""
        from uuid import uuid4

        alert = AlertModel(
            id=str(uuid4()),
            alert_type="silence",
            title="Test Alert",
            description="Test description",
            confidence=0.8,
            severity="medium",
            status="new",
            entity_refs=[],
            source_refs=[],
            detector_name="silence_detector",
            detector_metadata={},
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        db_session.add(alert)
        await db_session.commit()

        # Query it back
        from sqlalchemy import select

        result = await db_session.execute(
            select(AlertModel).where(AlertModel.title == "Test Alert")
        )
        fetched = result.scalar_one()

        assert fetched.alert_type == "silence"
        assert fetched.confidence == 0.8
        assert fetched.severity == "medium"
