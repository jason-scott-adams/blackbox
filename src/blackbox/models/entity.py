"""Entity model following FollowTheMoney patterns.

Entities are the core objects in Black Box - people, companies,
addresses, etc. that we track and analyze.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Entity(BaseModel):
    """A tracked entity in Black Box.

    Follows FollowTheMoney patterns for compatibility with Aleph.
    Entity IDs use the format "entity:{uuid}".
    """

    id: Annotated[UUID, Field(default_factory=uuid4, description="Unique entity identifier")]
    schema_type: Annotated[str, Field(description="Entity type (Person, Company, etc.)")]
    name: Annotated[str, Field(description="Primary name of the entity")]
    aliases: Annotated[list[str], Field(default_factory=list, description="Alternative names")]
    properties: Annotated[
        dict[str, list[str]],
        Field(default_factory=dict, description="Entity properties as key -> values"),
    ]
    created_at: Annotated[datetime, Field(default_factory=_utc_now)]
    updated_at: Annotated[datetime, Field(default_factory=_utc_now)]
    source_refs: Annotated[
        list[str],
        Field(default_factory=list, description="References to provenance records"),
    ]

    @property
    def entity_id(self) -> str:
        """Return the formatted entity ID string."""
        return f"entity:{self.id}"

    def add_alias(self, alias: str) -> None:
        """Add an alias if not already present."""
        if alias not in self.aliases and alias != self.name:
            self.aliases.append(alias)
            self.updated_at = _utc_now()

    def set_property(self, key: str, values: list[str]) -> None:
        """Set a property value."""
        self.properties[key] = values
        self.updated_at = _utc_now()

    def add_property_value(self, key: str, value: str) -> None:
        """Add a value to a property."""
        if key not in self.properties:
            self.properties[key] = []
        if value not in self.properties[key]:
            self.properties[key].append(value)
            self.updated_at = _utc_now()

    model_config = {"frozen": False}
