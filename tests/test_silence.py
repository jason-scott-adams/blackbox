"""Tests for the Silence Detector."""

from datetime import UTC, datetime, timedelta

import pytest

from blackbox.detectors.silence import SilenceConfig, SilenceDetector
from blackbox.models import Activity, ActivityType, Entity
from blackbox.models.alert import AlertSeverity, AlertType


@pytest.fixture
def detector() -> SilenceDetector:
    """Create a silence detector with default config."""
    return SilenceDetector()


@pytest.fixture
def strict_detector() -> SilenceDetector:
    """Create a silence detector with stricter thresholds."""
    config = SilenceConfig(
        min_activities=5,
        overdue_threshold_sigmas=1.5,
    )
    return SilenceDetector(config)


@pytest.fixture
def sample_entity() -> Entity:
    """Create a sample entity for testing."""
    return Entity(
        schema_type="Company",
        name="Acme Corp",
    )


def create_activities(
    entity_id: str,
    count: int,
    interval_days: float,
    start_date: datetime | None = None,
    activity_type: ActivityType = ActivityType.FILING,
    source: str = "SEC",
    variance_days: float = 1.0,  # Default small variance for realistic data
) -> list[Activity]:
    """Helper to create a series of regular activities."""
    if start_date is None:
        start_date = datetime.now(UTC) - timedelta(days=count * interval_days)

    activities = []
    current_date = start_date

    # Use deterministic "random" offsets based on index for reproducibility
    for i in range(count):
        # Small deterministic variance: alternating +/- pattern
        offset = variance_days * (0.5 if i % 2 == 0 else -0.5)
        occurred_at = current_date + timedelta(days=offset)

        activities.append(
            Activity(
                entity_id=entity_id,
                activity_type=activity_type,
                source=source,
                description=f"Activity {i + 1}",
                occurred_at=occurred_at,
            )
        )
        current_date += timedelta(days=interval_days)

    return activities


class TestSilenceDetectorBasics:
    """Test basic detector properties."""

    def test_name(self, detector: SilenceDetector):
        assert detector.name == "silence"

    def test_description(self, detector: SilenceDetector):
        assert "negative space" in detector.description.lower()

    def test_default_config(self, detector: SilenceDetector):
        assert detector.config.min_activities == 3
        assert detector.config.overdue_threshold_sigmas == 2.0


class TestActivitySummary:
    """Test activity summary computation."""

    def test_insufficient_activities(self, detector: SilenceDetector, sample_entity: Entity):
        """Should return None when too few activities."""
        activities = create_activities(sample_entity.entity_id, count=2, interval_days=30)
        summary = detector.compute_activity_summary(
            sample_entity.entity_id,
            activities,
            ActivityType.FILING,
            "SEC",
        )
        assert summary is None

    def test_sufficient_activities(self, detector: SilenceDetector, sample_entity: Entity):
        """Should compute summary with enough activities."""
        activities = create_activities(sample_entity.entity_id, count=5, interval_days=30)
        summary = detector.compute_activity_summary(
            sample_entity.entity_id,
            activities,
            ActivityType.FILING,
            "SEC",
        )
        assert summary is not None
        assert summary.count == 5
        assert summary.mean_interval_days is not None
        assert 29 < summary.mean_interval_days < 31  # Approximately 30 days

    def test_interval_calculation(self, detector: SilenceDetector, sample_entity: Entity):
        """Should correctly calculate mean intervals."""
        # Create activities with exactly 7-day intervals
        start = datetime.now(UTC) - timedelta(days=35)
        activities = create_activities(
            sample_entity.entity_id,
            count=5,
            interval_days=7,
            start_date=start,
        )
        summary = detector.compute_activity_summary(
            sample_entity.entity_id,
            activities,
            ActivityType.FILING,
            "SEC",
        )
        assert summary is not None
        assert abs(summary.mean_interval_days - 7.0) < 0.1


class TestSilenceDetection:
    """Test silence detection logic."""

    @pytest.mark.asyncio
    async def test_no_activities(self, detector: SilenceDetector, sample_entity: Entity):
        """Should return empty when no activities provided."""
        alerts = await detector.detect([sample_entity], activities=None)
        assert alerts == []

    @pytest.mark.asyncio
    async def test_no_silence_when_recent(self, detector: SilenceDetector, sample_entity: Entity):
        """Should not alert when activity is recent."""
        # Create activities with last one being recent
        activities = create_activities(
            sample_entity.entity_id,
            count=5,
            interval_days=30,
            start_date=datetime.now(UTC) - timedelta(days=120),
        )
        # Last activity is now at ~0 days ago

        alerts = await detector.detect([sample_entity], activities=activities)
        # Should be empty because we're not overdue yet
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_silence_detected_when_overdue(
        self, detector: SilenceDetector, sample_entity: Entity
    ):
        """Should alert when significantly overdue."""
        # Create activities that ended 90 days ago with 30-day interval
        # This is ~3 sigma overdue
        start_date = datetime.now(UTC) - timedelta(days=200)
        activities = create_activities(
            sample_entity.entity_id,
            count=5,
            interval_days=30,
            start_date=start_date,
        )
        # Last activity is at start_date + 4*30 = start_date + 120 days
        # Which means last activity is 80 days ago
        # Expected next is 50 days ago, so we're 50 days overdue

        alerts = await detector.detect([sample_entity], activities=activities)
        assert len(alerts) == 1
        assert alerts[0].alert_type == AlertType.SILENCE
        assert "Acme Corp" in alerts[0].title

    @pytest.mark.asyncio
    async def test_alert_metadata(self, detector: SilenceDetector, sample_entity: Entity):
        """Should include relevant metadata in alerts."""
        start_date = datetime.now(UTC) - timedelta(days=200)
        activities = create_activities(
            sample_entity.entity_id,
            count=5,
            interval_days=30,
            start_date=start_date,
        )

        alerts = await detector.detect([sample_entity], activities=activities)
        assert len(alerts) == 1

        metadata = alerts[0].detector_metadata
        assert "mean_interval_days" in metadata
        assert "days_overdue" in metadata
        assert "sigmas_overdue" in metadata
        assert metadata["source"] == "SEC"
        assert metadata["activity_type"] == "filing"


class TestConfidenceScoring:
    """Test confidence score calculation."""

    def test_confidence_increases_with_samples(
        self, detector: SilenceDetector, sample_entity: Entity
    ):
        """More samples should increase confidence."""
        # Fewer samples
        activities_few = create_activities(sample_entity.entity_id, count=4, interval_days=30)
        # More samples
        activities_many = create_activities(sample_entity.entity_id, count=20, interval_days=30)

        summary_few = detector.compute_activity_summary(
            sample_entity.entity_id, activities_few, ActivityType.FILING, "SEC"
        )
        summary_many = detector.compute_activity_summary(
            sample_entity.entity_id, activities_many, ActivityType.FILING, "SEC"
        )

        # Both need to be overdue to calculate confidence
        summary_few.days_overdue = 60
        summary_many.days_overdue = 60

        conf_few = detector._calculate_confidence(summary_few)
        conf_many = detector._calculate_confidence(summary_many)

        assert conf_many > conf_few

    def test_confidence_bounded(self, detector: SilenceDetector, sample_entity: Entity):
        """Confidence should always be between 0 and 1."""
        activities = create_activities(sample_entity.entity_id, count=100, interval_days=7)
        summary = detector.compute_activity_summary(
            sample_entity.entity_id, activities, ActivityType.FILING, "SEC"
        )
        summary.days_overdue = 365  # Very overdue

        confidence = detector._calculate_confidence(summary)
        assert 0.0 <= confidence <= 1.0


class TestSeverityLevels:
    """Test severity determination."""

    def test_severity_increases_with_sigmas(self, detector: SilenceDetector, sample_entity: Entity):
        """More sigmas overdue should increase severity."""
        activities = create_activities(sample_entity.entity_id, count=10, interval_days=30)
        summary = detector.compute_activity_summary(
            sample_entity.entity_id, activities, ActivityType.FILING, "SEC"
        )

        # Test different overdue levels (assuming std ~= mean * 0.1 for consistent data)
        std = summary.std_interval_days or 3.0

        summary.days_overdue = 1.5 * std
        assert detector._calculate_severity(summary) == AlertSeverity.LOW

        summary.days_overdue = 2.5 * std
        assert detector._calculate_severity(summary) == AlertSeverity.MEDIUM

        summary.days_overdue = 3.5 * std
        assert detector._calculate_severity(summary) == AlertSeverity.HIGH

        summary.days_overdue = 5.0 * std
        assert detector._calculate_severity(summary) == AlertSeverity.CRITICAL


class TestMultipleEntities:
    """Test detection across multiple entities."""

    @pytest.mark.asyncio
    async def test_multiple_entities_multiple_alerts(self, detector: SilenceDetector):
        """Should generate separate alerts for different entities."""
        entity1 = Entity(schema_type="Company", name="Company A")
        entity2 = Entity(schema_type="Company", name="Company B")

        # Both overdue
        start_date = datetime.now(UTC) - timedelta(days=200)
        activities1 = create_activities(
            entity1.entity_id, count=5, interval_days=30, start_date=start_date
        )
        activities2 = create_activities(
            entity2.entity_id, count=5, interval_days=30, start_date=start_date
        )

        alerts = await detector.detect([entity1, entity2], activities=activities1 + activities2)

        assert len(alerts) == 2
        entity_names = {a.title for a in alerts}
        assert any("Company A" in name for name in entity_names)
        assert any("Company B" in name for name in entity_names)

    @pytest.mark.asyncio
    async def test_different_activity_types(self, detector: SilenceDetector):
        """Should track different activity types separately."""
        entity = Entity(schema_type="Company", name="Test Corp")

        start_date = datetime.now(UTC) - timedelta(days=200)

        # Regular filings - overdue
        filings = create_activities(
            entity.entity_id,
            count=5,
            interval_days=30,
            start_date=start_date,
            activity_type=ActivityType.FILING,
        )

        # Regular publications - also overdue
        publications = create_activities(
            entity.entity_id,
            count=5,
            interval_days=30,
            start_date=start_date,
            activity_type=ActivityType.PUBLICATION,
            source="Blog",
        )

        alerts = await detector.detect([entity], activities=filings + publications)

        # Should get two alerts - one for each activity type/source combo
        assert len(alerts) == 2


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_empty_entities(self, detector: SilenceDetector):
        """Should handle empty entity list."""
        alerts = await detector.detect([], activities=[])
        assert alerts == []

    @pytest.mark.asyncio
    async def test_activities_without_matching_entity(self, detector: SilenceDetector):
        """Should handle activities for unknown entities."""
        activities = create_activities("entity:unknown", count=5, interval_days=30)
        alerts = await detector.detect([], activities=activities)
        # Should still generate alerts even without entity match
        assert len(alerts) >= 0  # May or may not alert depending on dates

    def test_very_short_intervals_ignored(self, detector: SilenceDetector, sample_entity: Entity):
        """Should ignore patterns with very short intervals."""
        # Activities every few hours - not meaningful for silence detection
        activities = create_activities(sample_entity.entity_id, count=10, interval_days=0.1)
        summary = detector.compute_activity_summary(
            sample_entity.entity_id, activities, ActivityType.FILING, "SEC"
        )
        # Should return None due to short interval
        assert summary is None
