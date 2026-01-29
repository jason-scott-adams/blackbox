"""Silence Detector - detecting when expected activity stops.

"Negative space" monitoring: what stopped happening is often more
significant than what is happening. This detector monitors activity
patterns and alerts when entities go silent.

Examples:
- A company that regularly filed SEC reports suddenly stops
- A politician who posted daily goes quiet
- Regular court filings from a jurisdiction stop
- A domain that was actively updated goes dormant
"""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from statistics import mean, stdev
from typing import Annotated

from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.models.activity import Activity, ActivitySummary, ActivityType
from blackbox.models.alert import Alert, AlertSeverity, AlertType
from blackbox.models.entity import Entity


class SilenceConfig(BaseModel):
    """Configuration for the Silence Detector."""

    min_activities: Annotated[
        int,
        Field(default=3, description="Minimum activities needed to establish pattern"),
    ]
    min_interval_days: Annotated[
        float,
        Field(default=1.0, description="Minimum expected interval to consider"),
    ]
    overdue_threshold_sigmas: Annotated[
        float,
        Field(default=2.0, description="Standard deviations to consider overdue"),
    ]
    max_lookback_days: Annotated[
        int,
        Field(default=365, description="Maximum days of history to consider"),
    ]
    severity_thresholds: Annotated[
        dict[str, float],
        Field(
            default_factory=lambda: {
                "low": 1.5,  # 1.5 sigma overdue
                "medium": 2.0,  # 2 sigma overdue
                "high": 3.0,  # 3 sigma overdue
                "critical": 4.0,  # 4+ sigma overdue
            }
        ),
    ]


class SilenceDetector(BaseDetector):
    """Detects when expected entity activity stops.

    Uses statistical analysis of activity intervals to detect
    when an entity is "overdue" for expected activity.

    The detector:
    1. Groups activities by entity, type, and source
    2. Computes mean and standard deviation of intervals
    3. Calculates expected next activity date
    4. Alerts when significantly overdue
    """

    def __init__(self, config: SilenceConfig | None = None):
        self.config = config or SilenceConfig()
        self._now: datetime | None = None  # For testing

    @property
    def name(self) -> str:
        return "silence"

    @property
    def description(self) -> str:
        return "Detects when expected entity activity stops (negative space monitoring)"

    def _get_now(self) -> datetime:
        """Get current time (injectable for testing)."""
        return self._now or datetime.now(UTC)

    @staticmethod
    def _ensure_aware(dt: datetime) -> datetime:
        """Ensure a datetime is timezone-aware (assume UTC if naive)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt

    def compute_activity_summary(
        self,
        entity_id: str,
        activities: list[Activity],
        activity_type: ActivityType,
        source: str,
    ) -> ActivitySummary | None:
        """Compute summary statistics for a set of activities.

        Returns None if insufficient data to establish a pattern.
        """
        if len(activities) < self.config.min_activities:
            return None

        # Sort by occurrence time (normalize tz for safe comparison)
        sorted_acts = sorted(activities, key=lambda a: self._ensure_aware(a.occurred_at))

        # Compute intervals between consecutive activities
        intervals: list[float] = []
        for i in range(1, len(sorted_acts)):
            delta = self._ensure_aware(sorted_acts[i].occurred_at) - self._ensure_aware(sorted_acts[i - 1].occurred_at)
            intervals.append(delta.total_seconds() / 86400)  # Convert to days

        if not intervals:
            return None

        mean_interval = mean(intervals)
        std_interval = stdev(intervals) if len(intervals) > 1 else mean_interval * 0.5

        # Don't track patterns with very short intervals
        if mean_interval < self.config.min_interval_days:
            return None

        first_activity = self._ensure_aware(sorted_acts[0].occurred_at)
        last_activity = self._ensure_aware(sorted_acts[-1].occurred_at)

        # Calculate expected next activity
        expected_next = last_activity + timedelta(days=mean_interval)

        # Calculate how overdue we are
        now = self._get_now()
        if now > expected_next:
            days_overdue = (now - expected_next).total_seconds() / 86400
        else:
            days_overdue = None

        return ActivitySummary(
            entity_id=entity_id,
            activity_type=activity_type,
            source=source,
            count=len(activities),
            first_activity=first_activity,
            last_activity=last_activity,
            mean_interval_days=mean_interval,
            std_interval_days=std_interval,
            expected_next=expected_next,
            days_overdue=days_overdue,
        )

    def _calculate_confidence(self, summary: ActivitySummary) -> float:
        """Calculate confidence score for a silence detection.

        Higher confidence when:
        - More historical activities to establish pattern
        - Lower variance in intervals (consistent pattern)
        - More severely overdue
        """
        if summary.days_overdue is None or summary.std_interval_days is None:
            return 0.0

        # Base confidence from sample size (asymptotic to 0.3)
        sample_factor = 0.3 * (1 - 1 / (1 + summary.count / 10))

        # Consistency factor from coefficient of variation (asymptotic to 0.3)
        cv = (
            summary.std_interval_days / summary.mean_interval_days
            if summary.mean_interval_days
            else 1.0
        )
        consistency_factor = 0.3 * (1 - min(cv, 1.0))

        # Overdue factor (sigma-based, asymptotic to 0.4)
        sigmas = (
            summary.days_overdue / summary.std_interval_days if summary.std_interval_days else 0
        )
        overdue_factor = 0.4 * (1 - 1 / (1 + sigmas / 3))

        return min(1.0, sample_factor + consistency_factor + overdue_factor)

    def _calculate_severity(self, summary: ActivitySummary) -> AlertSeverity:
        """Determine alert severity based on how overdue the entity is."""
        if summary.days_overdue is None or summary.std_interval_days is None:
            return AlertSeverity.LOW

        sigmas = summary.days_overdue / summary.std_interval_days

        thresholds = self.config.severity_thresholds
        if sigmas >= thresholds.get("critical", 4.0):
            return AlertSeverity.CRITICAL
        elif sigmas >= thresholds.get("high", 3.0):
            return AlertSeverity.HIGH
        elif sigmas >= thresholds.get("medium", 2.0):
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def detect(
        self,
        entities: list[Entity],
        activities: list[Activity] | None = None,
    ) -> list[Alert]:
        """Run silence detection on entities with their activities.

        Args:
            entities: List of entities to analyze
            activities: List of activities for these entities

        Returns:
            List of silence alerts for entities that are overdue
        """
        if not activities:
            return []

        alerts: list[Alert] = []

        # Build entity lookup
        entity_map = {e.entity_id: e for e in entities}

        # Group activities by (entity_id, activity_type, source)
        grouped: dict[tuple[str, ActivityType, str], list[Activity]] = defaultdict(list)
        for activity in activities:
            key = (activity.entity_id, activity.activity_type, activity.source)
            grouped[key].append(activity)

        # Analyze each group
        for (entity_id, activity_type, source), group_activities in grouped.items():
            summary = self.compute_activity_summary(
                entity_id, group_activities, activity_type, source
            )

            if summary is None:
                continue

            # Check if overdue past threshold
            if summary.days_overdue is None:
                continue

            if summary.std_interval_days:
                sigmas = summary.days_overdue / summary.std_interval_days
            else:
                sigmas = 0

            if sigmas < self.config.overdue_threshold_sigmas:
                continue

            # Get entity for naming
            entity = entity_map.get(entity_id)
            entity_name = entity.name if entity else entity_id

            # Create alert
            confidence = self._calculate_confidence(summary)
            severity = self._calculate_severity(summary)

            alert = Alert(
                alert_type=AlertType.SILENCE,
                title=f"Silence detected: {entity_name} - {source}",
                description=(
                    f"{entity_name} has not had any {activity_type.value} activity "
                    f"from {source} in {summary.days_overdue:.1f} days. "
                    f"Based on {summary.count} previous activities with an average "
                    f"interval of {summary.mean_interval_days:.1f} days, "
                    f"this is {sigmas:.1f} standard deviations overdue."
                ),
                confidence=confidence,
                severity=severity,
                entity_refs=[entity_id],
                detector_name=self.name,
                detector_metadata={
                    "activity_type": activity_type.value,
                    "source": source,
                    "count": summary.count,
                    "mean_interval_days": summary.mean_interval_days,
                    "std_interval_days": summary.std_interval_days,
                    "days_overdue": summary.days_overdue,
                    "sigmas_overdue": sigmas,
                    "last_activity": (
                        summary.last_activity.isoformat() if summary.last_activity else None
                    ),
                    "expected_next": (
                        summary.expected_next.isoformat() if summary.expected_next else None
                    ),
                },
            )
            alerts.append(alert)

        return alerts
