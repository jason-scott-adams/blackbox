"""Tests for digest generation."""

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from blackbox.digest import Digest, DigestConfig, DigestFlag, DigestGenerator, DigestItem
from blackbox.models import Activity, ActivityType, Alert, AlertSeverity, AlertStatus, AlertType


class TestDigestModels:
    """Tests for digest data models."""

    def test_digest_item_creation(self):
        """Test DigestItem creation."""
        item = DigestItem(
            type="activity",
            title="Test Activity",
            description="A test description",
            source="rss:test",
            timestamp=datetime.now(UTC).isoformat(),
        )
        assert item.type == "activity"
        assert item.title == "Test Activity"
        assert item.severity is None
        assert item.metadata == {}

    def test_digest_item_with_severity(self):
        """Test DigestItem with severity for alerts."""
        item = DigestItem(
            type="alert",
            title="Security Alert",
            description="Something bad happened",
            source="hibp",
            timestamp=datetime.now(UTC).isoformat(),
            severity="high",
            metadata={"confidence": 0.9},
        )
        assert item.severity == "high"
        assert item.metadata["confidence"] == 0.9

    def test_digest_flag_creation(self):
        """Test DigestFlag creation."""
        flag = DigestFlag(
            title="Critical Issue",
            description="Needs immediate attention",
            severity="critical",
            alert_id="alert:20260120:1234",
        )
        assert flag.title == "Critical Issue"
        assert flag.severity == "critical"
        assert flag.alert_id is not None

    def test_digest_creation(self):
        """Test Digest model creation."""
        digest = Digest(
            date="2026-01-20",
            summary="Test summary",
            items=[],
            flags_for_review=[],
            raw_data_pointers=[],
        )
        assert digest.date == "2026-01-20"
        assert digest.source == "blackbox"
        assert len(digest.items) == 0

    def test_digest_with_items(self):
        """Test Digest with items and flags."""
        item = DigestItem(
            type="activity",
            title="Test",
            description="Test",
            source="test",
            timestamp=datetime.now(UTC).isoformat(),
        )
        flag = DigestFlag(
            title="Review this",
            description="Important",
            severity="high",
        )
        digest = Digest(
            date="2026-01-20",
            summary="One item, one flag",
            items=[item],
            flags_for_review=[flag],
            raw_data_pointers=["ref:123"],
        )
        assert len(digest.items) == 1
        assert len(digest.flags_for_review) == 1
        assert len(digest.raw_data_pointers) == 1


class TestDigestConfig:
    """Tests for DigestConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DigestConfig()
        assert config.lookback_hours == 24
        assert config.include_resolved_alerts is False
        assert config.output_dir == Path("/home/atoms/code/juno-inbox/blackbox")

    def test_custom_config(self):
        """Test custom configuration."""
        config = DigestConfig(
            output_dir=Path("/tmp/test"),
            lookback_hours=48,
            include_resolved_alerts=True,
        )
        assert config.output_dir == Path("/tmp/test")
        assert config.lookback_hours == 48
        assert config.include_resolved_alerts is True


class TestDigestGenerator:
    """Tests for DigestGenerator."""

    def _make_activity(
        self,
        description: str = "Test activity",
        source: str = "test",
        occurred_at: datetime | None = None,
    ) -> Activity:
        """Helper to create test activities."""
        return Activity(
            entity_id="entity:test",
            activity_type=ActivityType.PUBLICATION,
            source=source,
            description=description,
            occurred_at=occurred_at or datetime.now(UTC),
            source_refs=["ref:test"],
        )

    def _make_alert(
        self,
        title: str = "Test Alert",
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        status: AlertStatus = AlertStatus.NEW,
        confidence: float = 0.8,
        created_at: datetime | None = None,
    ) -> Alert:
        """Helper to create test alerts."""
        alert = Alert(
            alert_type=AlertType.BREACH,
            title=title,
            description="Test alert description",
            confidence=confidence,
            severity=severity,
            status=status,
            detector_name="test_detector",
            source_refs=["ref:alert"],
        )
        if created_at:
            alert.created_at = created_at
        return alert

    def test_generator_creation(self):
        """Test generator instantiation."""
        generator = DigestGenerator()
        assert generator.config.lookback_hours == 24

    def test_generator_with_config(self):
        """Test generator with custom config."""
        config = DigestConfig(lookback_hours=48)
        generator = DigestGenerator(config)
        assert generator.config.lookback_hours == 48

    def test_generate_empty_digest(self):
        """Test generating digest with no data."""
        generator = DigestGenerator()
        digest = generator.generate([], [])
        assert digest.source == "blackbox"
        assert len(digest.items) == 0
        assert len(digest.flags_for_review) == 0
        assert "No new activity" in digest.summary

    def test_generate_with_activities(self):
        """Test generating digest with activities."""
        generator = DigestGenerator()
        activities = [
            self._make_activity("Activity 1", "rss:hn"),
            self._make_activity("Activity 2", "rss:reddit"),
        ]
        digest = generator.generate(activities, [])
        assert len(digest.items) == 2
        assert all(item.type == "activity" for item in digest.items)
        assert "2 activities" in digest.summary

    def test_generate_with_alerts(self):
        """Test generating digest with alerts."""
        generator = DigestGenerator()
        alerts = [
            self._make_alert("Alert 1", AlertSeverity.LOW),
            self._make_alert("Alert 2", AlertSeverity.HIGH),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.items) == 2
        assert all(item.type == "alert" for item in digest.items)
        assert "2 alerts" in digest.summary

    def test_generate_with_mixed_data(self):
        """Test generating digest with both activities and alerts."""
        generator = DigestGenerator()
        activities = [self._make_activity()]
        alerts = [self._make_alert()]
        digest = generator.generate(activities, alerts)
        assert len(digest.items) == 2
        types = {item.type for item in digest.items}
        assert types == {"activity", "alert"}

    def test_filters_old_activities(self):
        """Test that old activities are filtered out."""
        config = DigestConfig(lookback_hours=24)
        generator = DigestGenerator(config)

        old_time = datetime.now(UTC) - timedelta(hours=48)
        new_time = datetime.now(UTC) - timedelta(hours=1)

        activities = [
            self._make_activity("Old", occurred_at=old_time),
            self._make_activity("New", occurred_at=new_time),
        ]
        digest = generator.generate(activities, [])
        assert len(digest.items) == 1
        assert digest.items[0].title.startswith("New")

    def test_filters_old_alerts(self):
        """Test that old alerts are filtered out."""
        config = DigestConfig(lookback_hours=24)
        generator = DigestGenerator(config)

        old_time = datetime.now(UTC) - timedelta(hours=48)
        new_time = datetime.now(UTC) - timedelta(hours=1)

        alerts = [
            self._make_alert("Old Alert", created_at=old_time),
            self._make_alert("New Alert", created_at=new_time),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.items) == 1
        assert digest.items[0].title == "New Alert"

    def test_filters_resolved_alerts(self):
        """Test that resolved/dismissed alerts are filtered by default."""
        generator = DigestGenerator()
        alerts = [
            self._make_alert("New Alert", status=AlertStatus.NEW),
            self._make_alert("Resolved Alert", status=AlertStatus.RESOLVED),
            self._make_alert("Dismissed Alert", status=AlertStatus.DISMISSED),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.items) == 1
        assert digest.items[0].title == "New Alert"

    def test_includes_resolved_alerts_when_configured(self):
        """Test including resolved alerts when configured."""
        config = DigestConfig(include_resolved_alerts=True)
        generator = DigestGenerator(config)
        alerts = [
            self._make_alert("New Alert", status=AlertStatus.NEW),
            self._make_alert("Resolved Alert", status=AlertStatus.RESOLVED),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.items) == 2

    def test_generates_flags_for_high_severity(self):
        """Test that high/critical alerts generate flags."""
        generator = DigestGenerator()
        # Use low confidence so only severity triggers flags
        alerts = [
            self._make_alert("Low", severity=AlertSeverity.LOW, confidence=0.5),
            self._make_alert("Medium", severity=AlertSeverity.MEDIUM, confidence=0.5),
            self._make_alert("High", severity=AlertSeverity.HIGH, confidence=0.5),
            self._make_alert("Critical", severity=AlertSeverity.CRITICAL, confidence=0.5),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.flags_for_review) == 2
        flag_titles = {f.title for f in digest.flags_for_review}
        assert "High" in flag_titles
        assert "Critical" in flag_titles

    def test_generates_flags_for_high_confidence_new_alerts(self):
        """Test that new alerts with high confidence generate flags."""
        generator = DigestGenerator()
        alerts = [
            self._make_alert("Low Confidence", confidence=0.5, severity=AlertSeverity.MEDIUM),
            self._make_alert("High Confidence", confidence=0.8, severity=AlertSeverity.MEDIUM),
        ]
        digest = generator.generate([], alerts)
        assert len(digest.flags_for_review) == 1
        assert digest.flags_for_review[0].title == "High Confidence"

    def test_collects_raw_pointers(self):
        """Test that source refs are collected as raw pointers."""
        generator = DigestGenerator()
        activities = [self._make_activity()]
        alerts = [self._make_alert()]
        digest = generator.generate(activities, alerts)
        assert "ref:test" in digest.raw_data_pointers
        assert "ref:alert" in digest.raw_data_pointers

    def test_items_sorted_by_timestamp(self):
        """Test that items are sorted by timestamp (most recent first)."""
        generator = DigestGenerator()
        now = datetime.now(UTC)
        activities = [
            self._make_activity("Older", occurred_at=now - timedelta(hours=2)),
            self._make_activity("Newer", occurred_at=now - timedelta(hours=1)),
        ]
        digest = generator.generate(activities, [])
        assert digest.items[0].title.startswith("Newer")
        assert digest.items[1].title.startswith("Older")

    def test_handles_naive_datetimes(self):
        """Test that naive datetimes are handled (assumed UTC)."""
        generator = DigestGenerator()
        # Create activity with naive datetime (no tzinfo)
        naive_time = datetime.now() - timedelta(hours=1)
        activities = [self._make_activity("Naive datetime", occurred_at=naive_time)]
        # Should not raise an exception
        digest = generator.generate(activities, [])
        assert len(digest.items) == 1


class TestDigestWriter:
    """Tests for digest file writing."""

    def test_write_digest_dry_run(self):
        """Test dry run doesn't write file."""
        generator = DigestGenerator()
        digest = Digest(
            date="2026-01-20",
            summary="Test",
            items=[],
            flags_for_review=[],
            raw_data_pointers=[],
        )
        result = generator.write_digest(digest, dry_run=True)
        assert result is None

    def test_write_digest_creates_file(self):
        """Test that digest is written to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = DigestConfig(output_dir=Path(tmpdir))
            generator = DigestGenerator(config)
            digest = Digest(
                date="2026-01-20",
                summary="Test digest",
                items=[],
                flags_for_review=[],
                raw_data_pointers=[],
            )
            filepath = generator.write_digest(digest)
            assert filepath is not None
            assert filepath.exists()
            assert filepath.suffix == ".json"

    def test_write_digest_valid_json(self):
        """Test that written digest is valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = DigestConfig(output_dir=Path(tmpdir))
            generator = DigestGenerator(config)
            item = DigestItem(
                type="activity",
                title="Test",
                description="Test",
                source="test",
                timestamp=datetime.now(UTC).isoformat(),
            )
            digest = Digest(
                date="2026-01-20",
                summary="Test digest",
                items=[item],
                flags_for_review=[],
                raw_data_pointers=["ref:1"],
            )
            filepath = generator.write_digest(digest)

            # Read and verify JSON
            with open(filepath) as f:
                data = json.load(f)

            assert data["date"] == "2026-01-20"
            assert data["source"] == "blackbox"
            assert len(data["items"]) == 1
            assert data["items"][0]["type"] == "activity"

    def test_write_digest_creates_output_dir(self):
        """Test that output directory is created if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "nested" / "dir"
            config = DigestConfig(output_dir=output_dir)
            generator = DigestGenerator(config)
            digest = Digest(
                date="2026-01-20",
                summary="Test",
                items=[],
                flags_for_review=[],
                raw_data_pointers=[],
            )
            filepath = generator.write_digest(digest)
            assert output_dir.exists()
            assert filepath.parent == output_dir
