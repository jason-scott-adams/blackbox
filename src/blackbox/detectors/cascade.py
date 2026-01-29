"""Cascade Detector - detecting temporal chains of events.

Identifies cascading effects: when an event at one entity triggers
events at connected entities in a temporal sequence.

Uses NetworkX for graph analysis to model entity relationships
and detect propagation patterns.

Examples:
- A regulatory action at one company spreading to subsidiaries
- News about one entity causing reactions at related entities
- Legal filings cascading through a corporate network
"""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

import networkx as nx
from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.models.activity import Activity
from blackbox.models.alert import Alert, AlertSeverity, AlertType
from blackbox.models.entity import Entity


class EntityRelation(BaseModel):
    """A relationship between two entities."""

    source_id: Annotated[str, Field(description="Source entity ID")]
    target_id: Annotated[str, Field(description="Target entity ID")]
    relation_type: Annotated[str, Field(description="Type of relationship")]
    weight: Annotated[float, Field(default=1.0, description="Relationship strength")]
    metadata: Annotated[dict[str, object], Field(default_factory=dict)]


class CascadeConfig(BaseModel):
    """Configuration for the Cascade Detector."""

    max_cascade_depth: Annotated[
        int,
        Field(default=5, description="Maximum depth of cascade to track"),
    ]
    time_window_hours: Annotated[
        float,
        Field(default=72, description="Time window for cascade propagation (hours)"),
    ]
    min_cascade_length: Annotated[
        int,
        Field(default=2, description="Minimum events in a cascade"),
    ]
    activity_types_to_track: Annotated[
        list[str] | None,
        Field(default=None, description="Activity types to track (None = all)"),
    ]
    relation_type_weights: Annotated[
        dict[str, float],
        Field(
            default_factory=lambda: {
                "subsidiary": 1.0,
                "parent": 1.0,
                "partner": 0.7,
                "competitor": 0.5,
                "supplier": 0.6,
                "customer": 0.6,
            }
        ),
    ]


class CascadeEvent(BaseModel):
    """An event in a cascade sequence."""

    entity_id: Annotated[str, Field(description="Entity this event occurred at")]
    activity_id: Annotated[str, Field(description="Activity ID")]
    activity_type: Annotated[str, Field(description="Type of activity")]
    occurred_at: Annotated[datetime, Field(description="When the event occurred")]
    depth: Annotated[int, Field(description="Depth in the cascade (0 = origin)")]


class DetectedCascade(BaseModel):
    """A detected cascade of events."""

    origin_entity_id: Annotated[str, Field(description="Entity where cascade started")]
    events: Annotated[list[CascadeEvent], Field(description="Events in the cascade")]
    total_affected: Annotated[int, Field(description="Number of entities affected")]
    max_depth: Annotated[int, Field(description="Maximum depth reached")]
    duration_hours: Annotated[float, Field(description="Total cascade duration")]
    propagation_rate: Annotated[
        float,
        Field(description="Events per hour during cascade"),
    ]


class CascadeDetector(BaseDetector):
    """Detects cascading events across entity networks.

    This detector:
    1. Builds a graph of entity relationships
    2. Monitors activities for temporal patterns
    3. Identifies when activity at one entity propagates to connected entities
    4. Alerts on significant cascade patterns
    """

    def __init__(self, config: CascadeConfig | None = None):
        self.config = config or CascadeConfig()
        self._graph: nx.DiGraph = nx.DiGraph()
        self._now: datetime | None = None  # For testing

    @property
    def name(self) -> str:
        return "cascade"

    @property
    def description(self) -> str:
        return "Detects cascading events across entity networks"

    def _get_now(self) -> datetime:
        """Get current time (injectable for testing)."""
        return self._now or datetime.now(UTC)

    def build_graph(
        self,
        entities: list[Entity],
        relations: list[EntityRelation],
    ) -> nx.DiGraph:
        """Build entity relationship graph."""
        self._graph = nx.DiGraph()

        for entity in entities:
            self._graph.add_node(
                entity.entity_id,
                name=entity.name,
                schema_type=entity.schema_type,
            )

        for relation in relations:
            weight = relation.weight
            type_weight = self.config.relation_type_weights.get(relation.relation_type, 0.5)
            effective_weight = weight * type_weight

            self._graph.add_edge(
                relation.source_id,
                relation.target_id,
                relation_type=relation.relation_type,
                weight=effective_weight,
            )

        return self._graph

    def _find_cascades(
        self,
        activities: list[Activity],
        graph: nx.DiGraph | None = None,
    ) -> list[DetectedCascade]:
        """Find cascade patterns in activities."""
        g = graph or self._graph
        if not g or g.number_of_nodes() == 0:
            return []

        if self.config.activity_types_to_track:
            activities = [
                a
                for a in activities
                if a.activity_type.value in self.config.activity_types_to_track
            ]

        if not activities:
            return []

        sorted_activities = sorted(activities, key=lambda a: a.occurred_at)

        activities_by_entity: dict[str, list[Activity]] = defaultdict(list)
        for act in sorted_activities:
            activities_by_entity[act.entity_id].append(act)

        cascades: list[DetectedCascade] = []
        visited_origins: set[tuple[str, datetime]] = set()
        time_window = timedelta(hours=self.config.time_window_hours)

        for origin_activity in sorted_activities:
            origin_key = (origin_activity.entity_id, origin_activity.occurred_at)
            if origin_key in visited_origins:
                continue

            cascade_events: list[CascadeEvent] = [
                CascadeEvent(
                    entity_id=origin_activity.entity_id,
                    activity_id=origin_activity.activity_id,
                    activity_type=origin_activity.activity_type.value,
                    occurred_at=origin_activity.occurred_at,
                    depth=0,
                )
            ]

            visited_entities = {origin_activity.entity_id}
            current_depth = 0
            frontier = [(origin_activity.entity_id, origin_activity.occurred_at, 0)]

            while frontier and current_depth < self.config.max_cascade_depth:
                next_frontier: list[tuple[str, datetime, int]] = []

                for entity_id, prev_time, depth in frontier:
                    if entity_id not in g:
                        continue

                    for neighbor in g.successors(entity_id):
                        if neighbor in visited_entities:
                            continue

                        neighbor_activities = activities_by_entity.get(neighbor, [])

                        for act in neighbor_activities:
                            if prev_time < act.occurred_at <= prev_time + time_window:
                                cascade_events.append(
                                    CascadeEvent(
                                        entity_id=neighbor,
                                        activity_id=act.activity_id,
                                        activity_type=act.activity_type.value,
                                        occurred_at=act.occurred_at,
                                        depth=depth + 1,
                                    )
                                )
                                visited_entities.add(neighbor)
                                next_frontier.append((neighbor, act.occurred_at, depth + 1))
                                break

                frontier = next_frontier
                current_depth += 1

            if len(cascade_events) >= self.config.min_cascade_length:
                visited_origins.add(origin_key)

                duration = cascade_events[-1].occurred_at - cascade_events[0].occurred_at
                duration_hours = duration.total_seconds() / 3600

                cascade = DetectedCascade(
                    origin_entity_id=origin_activity.entity_id,
                    events=cascade_events,
                    total_affected=len(visited_entities),
                    max_depth=max(e.depth for e in cascade_events),
                    duration_hours=duration_hours if duration_hours > 0 else 0.1,
                    propagation_rate=(
                        len(cascade_events) / duration_hours
                        if duration_hours > 0
                        else len(cascade_events)
                    ),
                )
                cascades.append(cascade)

        return cascades

    def _calculate_confidence(self, cascade: DetectedCascade) -> float:
        """Calculate confidence for a cascade detection."""
        affected_factor = min(0.4, 0.1 * cascade.total_affected)
        rate_factor = min(0.3, 0.1 * cascade.propagation_rate)
        depth_factor = min(0.3, 0.1 * cascade.max_depth)
        return min(1.0, affected_factor + rate_factor + depth_factor)

    def _calculate_severity(self, cascade: DetectedCascade) -> AlertSeverity:
        """Determine severity based on cascade characteristics."""
        if cascade.total_affected >= 10:
            return AlertSeverity.CRITICAL
        elif cascade.total_affected >= 5:
            return AlertSeverity.HIGH
        elif cascade.total_affected >= 3:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def detect(
        self,
        entities: list[Entity],
        activities: list[Activity] | None = None,
        relations: list[EntityRelation] | None = None,
    ) -> list[Alert]:
        """Run cascade detection.

        Args:
            entities: List of entities to analyze
            activities: List of activities for these entities
            relations: List of entity relationships (builds graph if provided)

        Returns:
            List of alerts for detected cascades
        """
        if not activities:
            return []

        if relations:
            self.build_graph(entities, relations)

        if self._graph.number_of_nodes() == 0:
            return []

        cascades = self._find_cascades(activities)

        alerts: list[Alert] = []
        entity_map = {e.entity_id: e for e in entities}

        for cascade in cascades:
            origin_entity = entity_map.get(cascade.origin_entity_id)
            origin_name = origin_entity.name if origin_entity else cascade.origin_entity_id

            confidence = self._calculate_confidence(cascade)
            severity = self._calculate_severity(cascade)

            affected_ids = {e.entity_id for e in cascade.events}
            affected_names = [
                entity_map.get(eid, Entity(schema_type="Unknown", name=eid)).name
                for eid in list(affected_ids)[:5]
            ]
            affected_str = ", ".join(affected_names)
            if len(affected_ids) > 5:
                affected_str += f" and {len(affected_ids) - 5} more"

            event_types = [e.activity_type for e in cascade.events[:5]]
            pattern_str = " → ".join(event_types)

            alert = Alert(
                alert_type=AlertType.CASCADE,
                title=f"Cascade detected from {origin_name}",
                description=(
                    f"A cascade of events originating from {origin_name} affected "
                    f"{cascade.total_affected} entities over {cascade.duration_hours:.1f} hours. "
                    f"Pattern: {pattern_str}. Affected: {affected_str}."
                ),
                confidence=confidence,
                severity=severity,
                entity_refs=list(affected_ids),
                detector_name=self.name,
                detector_metadata={
                    "origin_entity_id": cascade.origin_entity_id,
                    "total_affected": cascade.total_affected,
                    "max_depth": cascade.max_depth,
                    "duration_hours": cascade.duration_hours,
                    "propagation_rate": cascade.propagation_rate,
                    "event_count": len(cascade.events),
                    "events": [
                        {
                            "entity_id": e.entity_id,
                            "activity_type": e.activity_type,
                            "depth": e.depth,
                            "occurred_at": e.occurred_at.isoformat(),
                        }
                        for e in cascade.events[:10]
                    ],
                },
            )
            alerts.append(alert)

        return alerts
