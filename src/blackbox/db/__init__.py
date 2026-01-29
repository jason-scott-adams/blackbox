"""Database module for Black Box."""

from blackbox.db.models import (
    ActivityModel,
    AlertModel,
    Base,
    DetectionRunModel,
    EntityModel,
    SyncConfigModel,
)
from blackbox.db.repositories import (
    SQLiteActivityRepository,
    SQLiteAlertRepository,
    SQLiteEntityRepository,
)
from blackbox.db.session import (
    create_all_tables,
    get_session,
    init_db,
    reset_engine,
)

__all__ = [
    "Base",
    "EntityModel",
    "ActivityModel",
    "AlertModel",
    "DetectionRunModel",
    "SyncConfigModel",
    "SQLiteEntityRepository",
    "SQLiteActivityRepository",
    "SQLiteAlertRepository",
    "init_db",
    "get_session",
    "create_all_tables",
    "reset_engine",
]
