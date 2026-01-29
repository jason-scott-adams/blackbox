"""Pattern detectors for Black Box."""

from blackbox.detectors.anomaly import AnomalyConfig, AnomalyDetector
from blackbox.detectors.base import BaseDetector
from blackbox.detectors.broker import BrokerConfig, BrokerDetector
from blackbox.detectors.cascade import CascadeConfig, CascadeDetector
from blackbox.detectors.earnings_proximity import (
    EarningsProximityConfig,
    EarningsProximityDetector,
    create_earnings_proximity_detector,
)
from blackbox.detectors.rhyme import RhymeConfig, RhymeDetector
from blackbox.detectors.silence import SilenceConfig, SilenceDetector

__all__ = [
    "AnomalyConfig",
    "AnomalyDetector",
    "BaseDetector",
    "BrokerConfig",
    "BrokerDetector",
    "CascadeConfig",
    "CascadeDetector",
    "EarningsProximityConfig",
    "EarningsProximityDetector",
    "create_earnings_proximity_detector",
    "RhymeConfig",
    "RhymeDetector",
    "SilenceConfig",
    "SilenceDetector",
]
