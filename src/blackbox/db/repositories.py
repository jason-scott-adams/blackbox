"""SQLite repository implementations for Black Box.

Provides data access layer for Activity, Alert, and Entity models.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from blackbox.db.models import ActivityModel, AlertModel, EntityModel
from blackbox.models.activity import Activity, ActivityType
from blackbox.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from blackbox.models.entity import Entity


# --- Converters: SQLAlchemy Model <-> Pydantic Model ---


def entity_to_model(entity: Entity) -> EntityModel:
    """Convert Pydantic Entity to SQLAlchemy EntityModel."""
    return EntityModel(
        id=str(entity.id),
        schema_type=entity.schema_type,
        name=entity.name,
        aliases=entity.aliases,
        properties=entity.properties,
        source_refs=entity.source_refs,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def model_to_entity(model: EntityModel) -> Entity:
    """Convert SQLAlchemy EntityModel to Pydantic Entity."""
    return Entity(
        id=UUID(model.id),
        schema_type=model.schema_type,
        name=model.name,
        aliases=model.aliases,
        properties=model.properties,
        source_refs=model.source_refs,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def activity_to_model(activity: Activity) -> ActivityModel:
    """Convert Pydantic Activity to SQLAlchemy ActivityModel."""
    return ActivityModel(
        id=str(activity.id),
        entity_id=activity.entity_id,
        activity_type=activity.activity_type.value,
        source=activity.source,
        description=activity.description,
        occurred_at=activity.occurred_at,
        recorded_at=activity.recorded_at,
        source_refs=activity.source_refs,
        metadata_=activity.metadata,
    )


def model_to_activity(model: ActivityModel) -> Activity:
    """Convert SQLAlchemy ActivityModel to Pydantic Activity."""
    return Activity(
        id=UUID(model.id),
        entity_id=model.entity_id,
        activity_type=ActivityType(model.activity_type),
        source=model.source,
        description=model.description,
        occurred_at=model.occurred_at,
        recorded_at=model.recorded_at,
        source_refs=model.source_refs,
        metadata=model.metadata_,
    )


def alert_to_model(alert: Alert) -> AlertModel:
    """Convert Pydantic Alert to SQLAlchemy AlertModel."""
    return AlertModel(
        id=str(alert.id),
        alert_type=alert.alert_type.value,
        title=alert.title,
        description=alert.description,
        confidence=alert.confidence,
        severity=alert.severity.value,
        status=alert.status.value,
        entity_refs=alert.entity_refs,
        source_refs=alert.source_refs,
        detector_name=alert.detector_name,
        detector_metadata=alert.detector_metadata,
        narrative=alert.narrative,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        acknowledged_at=alert.acknowledged_at,
        resolved_at=alert.resolved_at,
    )


def model_to_alert(model: AlertModel) -> Alert:
    """Convert SQLAlchemy AlertModel to Pydantic Alert."""
    return Alert(
        id=UUID(model.id),
        alert_type=AlertType(model.alert_type),
        title=model.title,
        description=model.description,
        confidence=model.confidence,
        severity=AlertSeverity(model.severity),
        status=AlertStatus(model.status),
        entity_refs=model.entity_refs,
        source_refs=model.source_refs,
        detector_name=model.detector_name,
        detector_metadata=model.detector_metadata,
        narrative=model.narrative,
        created_at=model.created_at,
        updated_at=model.updated_at,
        acknowledged_at=model.acknowledged_at,
        resolved_at=model.resolved_at,
    )


# --- SQLite Repository Implementations ---


class SQLiteEntityRepository:
    """SQLite implementation of EntityRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, entity_id: UUID) -> Entity | None:
        result = await self._session.execute(
            select(EntityModel).where(EntityModel.id == str(entity_id))
        )
        model = result.scalar_one_or_none()
        return model_to_entity(model) if model else None

    async def get_by_entity_id(self, entity_id: str) -> Entity | None:
        # entity_id format is "entity:{uuid}"
        if entity_id.startswith("entity:"):
            uuid_str = entity_id[7:]
            return await self.get(UUID(uuid_str))
        return None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        schema_type: str | None = None,
    ) -> list[Entity]:
        query = select(EntityModel).order_by(EntityModel.created_at.desc())
        if schema_type:
            query = query.where(EntityModel.schema_type == schema_type)
        query = query.offset(skip).limit(limit)

        result = await self._session.execute(query)
        return [model_to_entity(m) for m in result.scalars().all()]

    async def create(self, entity: Entity) -> Entity:
        model = entity_to_model(entity)
        self._session.add(model)
        await self._session.flush()
        await self._session.commit()
        return entity

    async def update(self, entity_id: UUID, entity: Entity) -> Entity | None:
        result = await self._session.execute(
            select(EntityModel).where(EntityModel.id == str(entity_id))
        )
        model = result.scalar_one_or_none()
        if not model:
            return None

        model.schema_type = entity.schema_type
        model.name = entity.name
        model.aliases = entity.aliases
        model.properties = entity.properties
        model.source_refs = entity.source_refs
        model.updated_at = entity.updated_at
        await self._session.flush()
        await self._session.commit()
        return entity

    async def delete(self, entity_id: UUID) -> bool:
        result = await self._session.execute(
            delete(EntityModel).where(EntityModel.id == str(entity_id))
        )
        await self._session.commit()
        return result.rowcount > 0

    async def search(self, query: str, limit: int = 10) -> list[Entity]:
        # SQLite JSON search is limited, so we'll do a simple LIKE search
        search_pattern = f"%{query}%"
        stmt = select(EntityModel).where(EntityModel.name.ilike(search_pattern)).limit(limit)
        result = await self._session.execute(stmt)
        return [model_to_entity(m) for m in result.scalars().all()]

    async def count(self, schema_type: str | None = None) -> int:
        query = select(func.count()).select_from(EntityModel)
        if schema_type:
            query = query.where(EntityModel.schema_type == schema_type)
        result = await self._session.execute(query)
        return result.scalar() or 0


class SQLiteActivityRepository:
    """SQLite implementation of ActivityRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, activity_id: UUID) -> Activity | None:
        result = await self._session.execute(
            select(ActivityModel).where(ActivityModel.id == str(activity_id))
        )
        model = result.scalar_one_or_none()
        return model_to_activity(model) if model else None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        entity_id: str | None = None,
        activity_type: str | None = None,
        source: str | None = None,
    ) -> list[Activity]:
        query = select(ActivityModel).order_by(ActivityModel.occurred_at.desc())
        if entity_id:
            query = query.where(ActivityModel.entity_id == entity_id)
        if activity_type:
            query = query.where(ActivityModel.activity_type == activity_type)
        if source:
            query = query.where(ActivityModel.source == source)
        query = query.offset(skip).limit(limit)

        result = await self._session.execute(query)
        return [model_to_activity(m) for m in result.scalars().all()]

    async def create(self, activity: Activity) -> Activity:
        model = activity_to_model(activity)
        self._session.add(model)
        await self._session.flush()
        await self._session.commit()
        return activity

    async def create_many(self, activities: list[Activity]) -> list[Activity]:
        """Create multiple activities in a single transaction."""
        models = [activity_to_model(a) for a in activities]
        self._session.add_all(models)
        await self._session.flush()
        await self._session.commit()
        return activities

    async def delete(self, activity_id: UUID) -> bool:
        result = await self._session.execute(
            delete(ActivityModel).where(ActivityModel.id == str(activity_id))
        )
        await self._session.commit()
        return result.rowcount > 0

    async def get_for_entity(self, entity_id: str) -> list[Activity]:
        query = (
            select(ActivityModel)
            .where(ActivityModel.entity_id == entity_id)
            .order_by(ActivityModel.occurred_at)
        )
        result = await self._session.execute(query)
        return [model_to_activity(m) for m in result.scalars().all()]

    async def count(self, entity_id: str | None = None) -> int:
        query = select(func.count()).select_from(ActivityModel)
        if entity_id:
            query = query.where(ActivityModel.entity_id == entity_id)
        result = await self._session.execute(query)
        return result.scalar() or 0

    async def exists_by_source_ref(self, source_ref: str) -> bool:
        """Check if an activity with this source reference already exists.

        Used for deduplication when syncing.
        """
        # For SQLite, source_refs is stored as JSON array string like '["ref1", "ref2"]'
        # Use LIKE to check if the source_ref appears in the JSON string
        from sqlalchemy import cast, String
        query = select(func.count()).select_from(ActivityModel).where(
            cast(ActivityModel.source_refs, String).like(f'%"{source_ref}"%')
        )
        result = await self._session.execute(query)
        count = result.scalar() or 0
        return count > 0

    async def get_by_source_ref(self, source_ref: str) -> Activity | None:
        """Get activity by source reference."""
        # For SQLite, use LIKE to search within JSON array string
        from sqlalchemy import cast, String
        result = await self._session.execute(
            select(ActivityModel).where(
                cast(ActivityModel.source_refs, String).like(f'%"{source_ref}"%')
            )
        )
        model = result.scalar_one_or_none()
        return model_to_activity(model) if model else None


class SQLiteAlertRepository:
    """SQLite implementation of AlertRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, alert_id: UUID) -> Alert | None:
        result = await self._session.execute(
            select(AlertModel).where(AlertModel.id == str(alert_id))
        )
        model = result.scalar_one_or_none()
        return model_to_alert(model) if model else None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        status: str | None = None,
        severity: str | None = None,
        alert_type: str | None = None,
        entity_id: str | None = None,
    ) -> list[Alert]:
        query = select(AlertModel).order_by(AlertModel.created_at.desc())
        if status:
            query = query.where(AlertModel.status == status)
        if severity:
            query = query.where(AlertModel.severity == severity)
        if alert_type:
            query = query.where(AlertModel.alert_type == alert_type)
        query = query.offset(skip).limit(limit)

        result = await self._session.execute(query)
        alerts = [model_to_alert(m) for m in result.scalars().all()]

        # Filter by entity_id in Python if specified (JSON search)
        if entity_id:
            alerts = [a for a in alerts if entity_id in a.entity_refs]

        return alerts

    async def create(self, alert: Alert) -> Alert:
        model = alert_to_model(alert)
        self._session.add(model)
        await self._session.flush()
        await self._session.commit()
        return alert

    async def update(self, alert_id: UUID, alert: Alert) -> Alert | None:
        result = await self._session.execute(
            select(AlertModel).where(AlertModel.id == str(alert_id))
        )
        model = result.scalar_one_or_none()
        if not model:
            return None

        model.status = alert.status.value
        model.acknowledged_at = alert.acknowledged_at
        model.resolved_at = alert.resolved_at
        model.updated_at = alert.updated_at
        await self._session.flush()
        await self._session.commit()
        return alert

    async def delete(self, alert_id: UUID) -> bool:
        result = await self._session.execute(
            delete(AlertModel).where(AlertModel.id == str(alert_id))
        )
        await self._session.commit()
        return result.rowcount > 0

    async def count(self, status: str | None = None) -> int:
        query = select(func.count()).select_from(AlertModel)
        if status:
            query = query.where(AlertModel.status == status)
        result = await self._session.execute(query)
        return result.scalar() or 0
