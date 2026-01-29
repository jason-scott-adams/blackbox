"""SQLAlchemy 2.0 ORM models for Black Box.

These models mirror the Pydantic models but are designed for SQLite persistence.
We keep them separate to maintain clear boundaries.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    type_annotation_map = {
        dict[str, Any]: JSON,
        list[str]: JSON,
        list[Any]: JSON,
    }


class EntityModel(Base):
    """SQLAlchemy model for Entity."""

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    properties: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Relationships
    activities: Mapped[list["ActivityModel"]] = relationship(
        "ActivityModel", back_populates="entity", lazy="select"
    )

    def __repr__(self) -> str:
        return f"<EntityModel(id={self.id}, name={self.name}, schema_type={self.schema_type})>"


class ActivityModel(Base):
    """SQLAlchemy model for Activity."""

    __tablename__ = "activities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("entities.id"), nullable=False, index=True
    )
    activity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    # Relationships
    entity: Mapped["EntityModel"] = relationship("EntityModel", back_populates="activities")

    def __repr__(self) -> str:
        return (
            f"<ActivityModel(id={self.id}, type={self.activity_type}, entity_id={self.entity_id})>"
        )


class AlertModel(Base):
    """SQLAlchemy model for Alert."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    entity_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    detector_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detector_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<AlertModel(id={self.id}, title={self.title}, severity={self.severity})>"


class DetectionRunModel(Base):
    """SQLAlchemy model for DetectionRun."""

    __tablename__ = "detection_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detector_name: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    entity_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    entities_processed: Mapped[int] = mapped_column(Integer, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    def __repr__(self) -> str:
        return f"<DetectionRunModel(id={self.id}, detector={self.detector_name}, status={self.status})>"


class SyncConfigModel(Base):
    """SQLAlchemy model for sync service configurations."""

    __tablename__ = "sync_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    service_name: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    schedule_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    def __repr__(self) -> str:
        return f"<SyncConfigModel(id={self.id}, service={self.service_name}, enabled={self.enabled})>"
