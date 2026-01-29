"""Broker Detector - detecting network centrality brokers and gatekeepers.

Identifies entities with high betweenness centrality in the relationship graph,
which may indicate information brokers, gatekeepers, or bridge nodes.

Examples:
- A person who bridges two otherwise disconnected organizations
- A company that sits between suppliers and customers
- An entity that controls information flow between groups
"""

from typing import Annotated

import networkx as nx
from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.detectors.cascade import EntityRelation
from blackbox.models.alert import Alert, AlertSeverity, AlertType
from blackbox.models.entity import Entity


class BrokerConfig(BaseModel):
    """Configuration for the Broker Detector."""

    centrality_method: Annotated[
        str,
        Field(
            default="betweenness",
            description="Centrality algorithm: betweenness, closeness, eigenvector, pagerank",
        ),
    ]
    score_threshold: Annotated[
        float,
        Field(default=0.3, ge=0.0, le=1.0, description="Minimum centrality score to alert"),
    ]
    min_connections: Annotated[
        int,
        Field(default=3, ge=1, description="Minimum edges for an entity to be considered"),
    ]
    severity_thresholds: Annotated[
        dict[str, float],
        Field(
            default_factory=lambda: {
                "critical": 0.8,
                "high": 0.6,
                "medium": 0.4,
            },
            description="Centrality score thresholds for severity levels",
        ),
    ]


class BrokerDetector(BaseDetector):
    """Detects network centrality brokers and gatekeepers.

    Uses graph analysis to identify entities that occupy central positions
    in the relationship network, potentially acting as information brokers
    or gatekeepers between otherwise disconnected groups.
    """

    def __init__(self, config: BrokerConfig | None = None):
        self.config = config or BrokerConfig()

    @property
    def name(self) -> str:
        return "broker"

    @property
    def description(self) -> str:
        return "Detects network centrality brokers and gatekeepers"

    def _build_graph(
        self, entities: list[Entity], relations: list[EntityRelation]
    ) -> nx.Graph:
        """Build NetworkX graph from entities and relations."""
        graph = nx.Graph()

        for entity in entities:
            graph.add_node(
                entity.entity_id,
                name=entity.name,
                type=entity.schema_type,
            )

        for rel in relations:
            graph.add_edge(
                rel.source_id,
                rel.target_id,
                relationship_type=rel.relation_type,
                weight=rel.weight,
            )

        return graph

    def _calculate_centrality(self, graph: nx.Graph) -> dict[str, float]:
        """Calculate centrality scores using configured method."""
        if len(graph.nodes()) == 0:
            return {}

        method = self.config.centrality_method.lower()

        try:
            if method == "betweenness":
                return nx.betweenness_centrality(graph, weight="weight", normalized=True)
            elif method == "closeness":
                return nx.closeness_centrality(graph)
            elif method == "eigenvector":
                try:
                    return nx.eigenvector_centrality(graph, max_iter=1000, weight="weight")
                except nx.PowerIterationFailedConvergence:
                    return nx.betweenness_centrality(graph, weight="weight", normalized=True)
            elif method == "pagerank":
                return nx.pagerank(graph, weight="weight")
            else:
                return nx.betweenness_centrality(graph, weight="weight", normalized=True)
        except Exception:
            return {}

    def _determine_severity(self, score: float) -> AlertSeverity:
        """Map centrality score to alert severity."""
        thresholds = self.config.severity_thresholds

        if score >= thresholds.get("critical", 0.8):
            return AlertSeverity.CRITICAL
        elif score >= thresholds.get("high", 0.6):
            return AlertSeverity.HIGH
        elif score >= thresholds.get("medium", 0.4):
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _calculate_confidence(
        self, centrality_score: float, neighbor_count: int, total_nodes: int
    ) -> float:
        """Calculate detection confidence."""
        centrality_factor = centrality_score * 0.5

        if total_nodes > 1:
            density_factor = min(neighbor_count / (total_nodes - 1), 1.0) * 0.3
        else:
            density_factor = 0.0

        size_factor = min(total_nodes / 20, 1.0) * 0.2

        return min(1.0, centrality_factor + density_factor + size_factor)

    async def detect(
        self,
        entities: list[Entity],
        activities: list | None = None,
        relations: list[EntityRelation] | None = None,
    ) -> list[Alert]:
        """Run broker detection on entities using relationship graph.

        Args:
            entities: List of entities to analyze
            activities: Unused (kept for base class compatibility)
            relations: List of relationships between entities

        Returns:
            List of alerts for entities with high centrality scores
        """
        if not entities or not relations:
            return []

        graph = self._build_graph(entities, relations)

        if len(graph.nodes()) < 3:
            return []

        centrality_scores = self._calculate_centrality(graph)
        if not centrality_scores:
            return []

        entity_map = {e.entity_id: e for e in entities}
        alerts: list[Alert] = []

        for entity_id, score in centrality_scores.items():
            if score < self.config.score_threshold:
                continue

            neighbor_count = graph.degree(entity_id)
            if neighbor_count < self.config.min_connections:
                continue

            entity = entity_map.get(entity_id)
            if entity is None:
                continue

            confidence = self._calculate_confidence(
                score, neighbor_count, len(graph.nodes())
            )
            severity = self._determine_severity(score)

            alert = Alert(
                alert_type=AlertType.BROKER,
                title=f"High-centrality broker: {entity.name}",
                description=(
                    f"Entity '{entity.name}' ({entity.schema_type}) has "
                    f"{self.config.centrality_method} centrality of {score:.3f} with "
                    f"{neighbor_count} connections in a network of {len(graph.nodes())} "
                    f"entities. This indicates a potential broker or gatekeeper role."
                ),
                confidence=confidence,
                severity=severity,
                entity_refs=[entity.entity_id],
                detector_name=self.name,
                detector_metadata={
                    "centrality_method": self.config.centrality_method,
                    "centrality_score": score,
                    "neighbor_count": neighbor_count,
                    "total_nodes": len(graph.nodes()),
                    "score_threshold": self.config.score_threshold,
                    "min_connections": self.config.min_connections,
                },
            )
            alerts.append(alert)

        alerts.sort(key=lambda a: a.detector_metadata.get("centrality_score", 0), reverse=True)

        return alerts
