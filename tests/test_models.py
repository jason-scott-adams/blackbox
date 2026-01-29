"""Tests for Pydantic models."""

from datetime import datetime, UTC
from uuid import UUID

import pytest

from blackbox.models import (
    Activity,
    ActivityType,
    Alert,
    AlertSeverity,
    AlertStatus,
    AlertType,
    Entity,
)


class TestEntity:
    """Tests for Entity model."""

    def test_create_entity(self):
        """Test basic entity creation."""
        entity = Entity(
            schema_type="Person",
            name="Test Person",
        )
        assert entity.schema_type == "Person"
        assert entity.name == "Test Person"
        assert isinstance(entity.id, UUID)
        assert entity.aliases == []
        assert entity.properties == {}

    def test_entity_id_format(self):
        """Test entity_id property format."""
        entity = Entity(schema_type="Company", name="Test Corp")
        assert entity.entity_id.startswith("entity:")
        assert str(entity.id) in entity.entity_id

    def test_add_alias(self):
        """Test adding aliases."""
        entity = Entity(schema_type="Person", name="John Doe")
        entity.add_alias("J. Doe")
        assert "J. Doe" in entity.aliases

        # Should not add duplicate
        entity.add_alias("J. Doe")
        assert entity.aliases.count("J. Doe") == 1

        # Should not add name as alias
        entity.add_alias("John Doe")
        assert "John Doe" not in entity.aliases

    def test_set_property(self):
        """Test setting properties."""
        entity = Entity(schema_type="Person", name="Test")
        entity.set_property("email", ["test@example.com"])
        assert entity.properties["email"] == ["test@example.com"]

    def test_add_property_value(self):
        """Test adding property values."""
        entity = Entity(schema_type="Person", name="Test")
        entity.add_property_value("phone", "555-1234")
        entity.add_property_value("phone", "555-5678")
        assert entity.properties["phone"] == ["555-1234", "555-5678"]

        # Should not add duplicate
        entity.add_property_value("phone", "555-1234")
        assert entity.properties["phone"].count("555-1234") == 1


class TestActivity:
    """Tests for Activity model."""

    def test_create_activity(self):
        """Test basic activity creation."""
        activity = Activity(
            entity_id="entity:123",
            activity_type=ActivityType.PUBLICATION,
            source="test",
            occurred_at=datetime.now(UTC),
        )
        assert activity.entity_id == "entity:123"
        assert activity.activity_type == ActivityType.PUBLICATION
        assert isinstance(activity.id, UUID)

    def test_activity_id_format(self):
        """Test activity_id property format."""
        activity = Activity(
            entity_id="entity:123",
            activity_type=ActivityType.FILING,
            source="SEC",
            occurred_at=datetime.now(UTC),
        )
        assert activity.activity_id.startswith("activity:")

    def test_activity_types(self):
        """Test all activity types are valid."""
        for activity_type in ActivityType:
            activity = Activity(
                entity_id="entity:123",
                activity_type=activity_type,
                source="test",
                occurred_at=datetime.now(UTC),
            )
            assert activity.activity_type == activity_type


class TestAlert:
    """Tests for Alert model."""

    def test_create_alert(self):
        """Test basic alert creation."""
        alert = Alert(
            alert_type=AlertType.SILENCE,
            title="Test Alert",
            description="Test description",
            confidence=0.8,
            detector_name="silence_detector",
        )
        assert alert.alert_type == AlertType.SILENCE
        assert alert.title == "Test Alert"
        assert alert.confidence == 0.8
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.status == AlertStatus.NEW

    def test_alert_id_format(self):
        """Test alert_id property format."""
        alert = Alert(
            alert_type=AlertType.BREACH,
            title="Breach",
            description="Data breach",
            confidence=0.9,
            detector_name="hibp",
        )
        assert alert.alert_id.startswith("alert:")

    def test_confidence_validation(self):
        """Test confidence score validation."""
        # Valid confidence
        alert = Alert(
            alert_type=AlertType.ANOMALY,
            title="Test",
            description="Test",
            confidence=0.5,
            detector_name="test",
        )
        assert alert.confidence == 0.5

        # Invalid confidence (too high)
        with pytest.raises(ValueError):
            Alert(
                alert_type=AlertType.ANOMALY,
                title="Test",
                description="Test",
                confidence=1.5,
                detector_name="test",
            )

        # Invalid confidence (negative)
        with pytest.raises(ValueError):
            Alert(
                alert_type=AlertType.ANOMALY,
                title="Test",
                description="Test",
                confidence=-0.1,
                detector_name="test",
            )

    def test_acknowledge(self):
        """Test acknowledging an alert."""
        alert = Alert(
            alert_type=AlertType.SILENCE,
            title="Test",
            description="Test",
            confidence=0.7,
            detector_name="test",
        )
        assert alert.status == AlertStatus.NEW
        assert alert.acknowledged_at is None

        alert.acknowledge()
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_at is not None

    def test_resolve(self):
        """Test resolving an alert."""
        alert = Alert(
            alert_type=AlertType.SILENCE,
            title="Test",
            description="Test",
            confidence=0.7,
            detector_name="test",
        )
        alert.resolve()
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None

    def test_dismiss(self):
        """Test dismissing an alert."""
        alert = Alert(
            alert_type=AlertType.SILENCE,
            title="Test",
            description="Test",
            confidence=0.7,
            detector_name="test",
        )
        alert.dismiss()
        assert alert.status == AlertStatus.DISMISSED
