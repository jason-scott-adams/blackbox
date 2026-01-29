"""Anomaly Detector - detecting statistical outliers in entity data.

Uses multiple anomaly detection algorithms to identify entities or
data points that deviate significantly from expected patterns.

When PyOD is available, uses:
- Isolation Forest (default, good for high-dimensional data)
- Local Outlier Factor (good for density-based outliers)
- One-Class SVM (good for novelty detection)

Falls back to simple z-score based detection if PyOD unavailable.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any

import numpy as np
from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.models.alert import Alert, AlertSeverity, AlertType
from blackbox.models.entity import Entity

# Optional PyOD import
try:
    from pyod.models.iforest import IForest
    from pyod.models.lof import LOF
    from pyod.models.ocsvm import OCSVM

    PYOD_AVAILABLE = True
except ImportError:
    PYOD_AVAILABLE = False


class AnomalyMethod(str, Enum):
    """Anomaly detection methods."""

    ISOLATION_FOREST = "isolation_forest"
    LOCAL_OUTLIER_FACTOR = "lof"
    ONE_CLASS_SVM = "ocsvm"
    ZSCORE = "zscore"  # Fallback when PyOD not available


class AnomalyConfig(BaseModel):
    """Configuration for the Anomaly Detector."""

    method: Annotated[
        AnomalyMethod,
        Field(default=AnomalyMethod.ISOLATION_FOREST, description="Detection method"),
    ]
    contamination: Annotated[
        float,
        Field(default=0.1, ge=0.01, le=0.5, description="Expected proportion of outliers"),
    ]
    zscore_threshold: Annotated[
        float,
        Field(default=3.0, description="Z-score threshold for fallback detection"),
    ]
    min_samples: Annotated[
        int,
        Field(default=10, description="Minimum samples needed for detection"),
    ]
    feature_weights: Annotated[
        dict[str, float],
        Field(default_factory=dict, description="Weights for different features"),
    ]


class AnomalyResult(BaseModel):
    """Result from anomaly detection for a single entity."""

    entity_id: Annotated[str, Field(description="Entity this result is for")]
    is_anomaly: Annotated[bool, Field(description="Whether entity is anomalous")]
    anomaly_score: Annotated[float, Field(description="Anomaly score (higher = more anomalous)")]
    feature_contributions: Annotated[
        dict[str, float],
        Field(default_factory=dict, description="How much each feature contributed"),
    ]
    method_used: Annotated[str, Field(description="Detection method used")]


class AnomalyDetector(BaseDetector):
    """Detects statistical anomalies in entity data.

    Analyzes numeric features of entities to identify those that
    deviate significantly from the norm. Features analyzed:
    - Activity counts (if provided)
    - Time since last activity
    - Network centrality metrics
    - Custom numeric properties
    """

    def __init__(self, config: AnomalyConfig | None = None):
        self.config = config or AnomalyConfig()
        self._model: Any = None

    @property
    def name(self) -> str:
        return "anomaly"

    @property
    def description(self) -> str:
        return "Detects statistical anomalies in entity data using machine learning"

    def _get_effective_method(self) -> AnomalyMethod:
        """Get the method to use based on availability."""
        if not PYOD_AVAILABLE:
            return AnomalyMethod.ZSCORE
        return self.config.method

    def _create_model(self, method: AnomalyMethod) -> Any:
        """Create a PyOD model for the specified method."""
        if not PYOD_AVAILABLE:
            return None

        contamination = self.config.contamination

        if method == AnomalyMethod.ISOLATION_FOREST:
            return IForest(contamination=contamination, random_state=42)
        elif method == AnomalyMethod.LOCAL_OUTLIER_FACTOR:
            return LOF(contamination=contamination)
        elif method == AnomalyMethod.ONE_CLASS_SVM:
            return OCSVM(contamination=contamination)

        return None

    def _extract_features(
        self,
        entity: Entity,
        activity_counts: dict[str, int] | None = None,
        network_metrics: dict[str, dict[str, float]] | None = None,
    ) -> dict[str, float]:
        """Extract numeric features from an entity."""
        features: dict[str, float] = {}

        # Activity count
        if activity_counts:
            features["activity_count"] = float(activity_counts.get(entity.entity_id, 0))

        # Days since update
        now = datetime.now(UTC)
        days_since_update = (now - entity.updated_at).total_seconds() / 86400
        features["days_since_update"] = days_since_update

        # Network metrics if available
        if network_metrics and entity.entity_id in network_metrics:
            metrics = network_metrics[entity.entity_id]
            for metric_name, value in metrics.items():
                features[f"network_{metric_name}"] = value

        # Extract numeric properties
        for key, values in entity.properties.items():
            for val in values:
                try:
                    features[f"prop_{key}"] = float(val)
                    break  # Only take first numeric value
                except (ValueError, TypeError):
                    continue

        return features

    def _zscore_detect(
        self,
        feature_matrix: np.ndarray,
        feature_names: list[str],
    ) -> tuple[np.ndarray, np.ndarray]:
        """Simple z-score based anomaly detection.

        Returns (labels, scores) where:
        - labels: 1 for anomaly, 0 for normal
        - scores: absolute max z-score for each sample
        """
        if feature_matrix.shape[0] < 2:
            return np.zeros(feature_matrix.shape[0]), np.zeros(feature_matrix.shape[0])

        mean = np.mean(feature_matrix, axis=0)
        std = np.std(feature_matrix, axis=0)
        std = np.where(std == 0, 1, std)

        z_scores = np.abs((feature_matrix - mean) / std)
        max_z = np.max(z_scores, axis=1)

        labels = (max_z > self.config.zscore_threshold).astype(int)
        scores = max_z / (max_z.max() + 1e-10)

        return labels, scores

    def _calculate_confidence(
        self,
        anomaly_score: float,
        sample_size: int,
        method: AnomalyMethod,
    ) -> float:
        """Calculate confidence score for anomaly detection."""
        score_factor = min(0.5, anomaly_score * 0.5)
        sample_factor = 0.3 * (1 - 1 / (1 + sample_size / 50))

        method_weights = {
            AnomalyMethod.ISOLATION_FOREST: 0.2,
            AnomalyMethod.LOCAL_OUTLIER_FACTOR: 0.18,
            AnomalyMethod.ONE_CLASS_SVM: 0.15,
            AnomalyMethod.ZSCORE: 0.1,
        }
        method_factor = method_weights.get(method, 0.1)

        return min(1.0, score_factor + sample_factor + method_factor)

    def _calculate_severity(self, anomaly_score: float) -> AlertSeverity:
        """Determine severity based on anomaly score."""
        if anomaly_score >= 0.9:
            return AlertSeverity.CRITICAL
        elif anomaly_score >= 0.7:
            return AlertSeverity.HIGH
        elif anomaly_score >= 0.5:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def detect(
        self,
        entities: list[Entity],
        activities: list | None = None,
        activity_counts: dict[str, int] | None = None,
        network_metrics: dict[str, dict[str, float]] | None = None,
    ) -> list[Alert]:
        """Run anomaly detection on entities.

        Args:
            entities: List of entities to analyze
            activities: Unused (kept for base class compatibility)
            activity_counts: Optional dict mapping entity_id to activity count
            network_metrics: Optional dict mapping entity_id to network centrality metrics

        Returns:
            List of alerts for anomalous entities
        """
        if len(entities) < self.config.min_samples:
            return []

        # Extract features for all entities
        feature_dicts: list[dict[str, float]] = []
        for entity in entities:
            features = self._extract_features(entity, activity_counts, network_metrics)
            feature_dicts.append(features)

        # Get all unique feature names
        all_features: set[str] = set()
        for fd in feature_dicts:
            all_features.update(fd.keys())

        if not all_features:
            return []

        feature_names = sorted(all_features)

        # Build feature matrix
        feature_matrix = np.zeros((len(entities), len(feature_names)))
        for i, fd in enumerate(feature_dicts):
            for j, fname in enumerate(feature_names):
                feature_matrix[i, j] = fd.get(fname, 0.0)

        # Run detection
        method = self._get_effective_method()

        if method == AnomalyMethod.ZSCORE or not PYOD_AVAILABLE:
            labels, scores = self._zscore_detect(feature_matrix, feature_names)
        else:
            model = self._create_model(method)
            model.fit(feature_matrix)
            labels = model.labels_
            scores = model.decision_scores_
            scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)

        # Generate alerts for anomalies
        alerts: list[Alert] = []

        for i, entity in enumerate(entities):
            if labels[i] == 1:
                anomaly_score = float(scores[i])
                confidence = self._calculate_confidence(anomaly_score, len(entities), method)
                severity = self._calculate_severity(anomaly_score)

                # Determine which features contributed most
                entity_features = feature_dicts[i]
                mean_features = np.mean(feature_matrix, axis=0)
                std_features = np.std(feature_matrix, axis=0)
                std_features = np.where(std_features == 0, 1, std_features)

                contributions: dict[str, float] = {}
                for j, fname in enumerate(feature_names):
                    if fname in entity_features:
                        z = abs((entity_features[fname] - mean_features[j]) / std_features[j])
                        contributions[fname] = float(z)

                top_contributors = sorted(
                    contributions.items(), key=lambda x: x[1], reverse=True
                )[:3]
                contributor_desc = ", ".join(f"{k} (z={v:.1f})" for k, v in top_contributors)

                alert = Alert(
                    alert_type=AlertType.ANOMALY,
                    title=f"Anomaly detected: {entity.name}",
                    description=(
                        f"{entity.name} shows anomalous behavior with score {anomaly_score:.2f}. "
                        f"Top contributing factors: {contributor_desc}. "
                        f"Detection method: {method.value}."
                    ),
                    confidence=confidence,
                    severity=severity,
                    entity_refs=[entity.entity_id],
                    detector_name=self.name,
                    detector_metadata={
                        "method": method.value,
                        "anomaly_score": anomaly_score,
                        "sample_size": len(entities),
                        "feature_contributions": contributions,
                        "features_analyzed": len(feature_names),
                    },
                )
                alerts.append(alert)

        return alerts

    async def validate(self) -> bool:
        """Check if detector is properly configured."""
        return True
