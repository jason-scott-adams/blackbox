"""Activity model for tracking entity events over time.

Activities represent discrete events associated with entities.
The Silence Detector uses these to detect when expected activity stops.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ActivityType(str, Enum):
    """Types of activities that can be tracked."""

    FILING = "filing"  # SEC filing, court filing, etc.
    PUBLICATION = "publication"  # Blog post, press release
    TRANSACTION = "transaction"  # Financial transaction
    COMMUNICATION = "communication"  # Email, social media post
    REGISTRATION = "registration"  # Domain, trademark, etc.
    APPOINTMENT = "appointment"  # Board appointment, role change
    LEGAL = "legal"  # Lawsuit, judgment, settlement
    SECURITY_INCIDENT = "security_incident"  # Security-related events
    DATA_BREACH = "data_breach"  # Data leak, breach notification
    VULNERABILITY = "vulnerability"  # CVE, security advisory
    CERTIFICATE = "certificate"  # SSL/TLS certificate issuance
    REGULATORY_FILING = "regulatory_filing"  # Federal Register, regulatory docs
    CONTRACT_AWARDED = "contract_awarded"  # Government contract awards
    WEATHER_ALERT = "weather_alert"  # NOAA weather alerts
    OTHER = "other"


class Activity(BaseModel):
    """A discrete activity/event associated with an entity.

    Activities track the temporal patterns of entity behavior
    which is used by the Silence Detector to detect when
    expected activity stops.
    """

    id: Annotated[UUID, Field(default_factory=uuid4)]
    entity_id: Annotated[str, Field(description="Entity this activity relates to")]
    activity_type: Annotated[ActivityType, Field(description="Type of activity")]
    source: Annotated[str, Field(description="Source of the activity (SEC, Court, etc.)")]
    description: Annotated[str, Field(default="", description="Activity description")]
    occurred_at: Annotated[datetime, Field(description="When the activity occurred")]
    recorded_at: Annotated[datetime, Field(default_factory=_utc_now)]
    source_refs: Annotated[
        list[str],
        Field(default_factory=list, description="References to provenance records"),
    ]
    metadata: Annotated[
        dict[str, object],
        Field(default_factory=dict, description="Additional activity-specific data"),
    ]

    @property
    def activity_id(self) -> str:
        """Return formatted activity ID."""
        return f"activity:{self.id}"

    model_config = {"frozen": False}


class ActivitySummary(BaseModel):
    """Summary statistics for entity activity.

    Used by the Silence Detector to understand activity patterns.
    """

    entity_id: Annotated[str, Field(description="Entity this summary is for")]
    activity_type: Annotated[ActivityType, Field(description="Type of activity")]
    source: Annotated[str, Field(description="Source of activities")]
    count: Annotated[int, Field(description="Total number of activities")]
    first_activity: Annotated[datetime | None, Field(default=None)]
    last_activity: Annotated[datetime | None, Field(default=None)]
    mean_interval_days: Annotated[
        float | None,
        Field(default=None, description="Average days between activities"),
    ]
    std_interval_days: Annotated[
        float | None,
        Field(default=None, description="Standard deviation of intervals"),
    ]
    expected_next: Annotated[
        datetime | None,
        Field(default=None, description="Expected date of next activity"),
    ]
    days_overdue: Annotated[
        float | None,
        Field(default=None, description="Days past expected activity"),
    ]
