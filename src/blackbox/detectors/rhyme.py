"""Rhyme Detector - detecting patterns that preceded outcomes before.

"History doesn't repeat, but it rhymes" - Mark Twain (attributed)

This detector identifies sequential patterns in entity activities
that have historically preceded specific outcomes. When those patterns
appear again, it alerts that similar outcomes may follow.

Uses PrefixSpan algorithm when available for efficient sequential
pattern mining, with a simpler n-gram based fallback.

Examples:
- Sequence of SEC filings followed by company restructuring
- Social media activity patterns before product launches
- Legal filing patterns before settlements
"""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

from pydantic import BaseModel, Field

from blackbox.detectors.base import BaseDetector
from blackbox.models.activity import Activity
from blackbox.models.alert import Alert, AlertSeverity, AlertType
from blackbox.models.entity import Entity

# Optional PrefixSpan import
try:
    from prefixspan import PrefixSpan

    PREFIXSPAN_AVAILABLE = True
except ImportError:
    PREFIXSPAN_AVAILABLE = False


class Outcome(BaseModel):
    """A labeled outcome for pattern learning.

    Outcomes are the 'endings' we want to predict - the thing
    that a sequence of activities led to.
    """

    id: Annotated[str, Field(description="Unique outcome identifier")]
    entity_id: Annotated[str, Field(description="Entity this outcome relates to")]
    outcome_type: Annotated[
        str, Field(description="Type of outcome (e.g., bankruptcy, acquisition)")
    ]
    description: Annotated[str, Field(default="", description="Outcome description")]
    occurred_at: Annotated[datetime, Field(description="When the outcome occurred")]
    severity: Annotated[AlertSeverity, Field(default=AlertSeverity.MEDIUM)]
    metadata: Annotated[dict[str, object], Field(default_factory=dict)]


class RhymeConfig(BaseModel):
    """Configuration for the Rhyme Detector."""

    min_sequence_length: Annotated[
        int,
        Field(default=2, description="Minimum sequence length to consider"),
    ]
    max_sequence_length: Annotated[
        int,
        Field(default=10, description="Maximum sequence length to consider"),
    ]
    min_support: Annotated[
        float,
        Field(default=0.1, description="Minimum support threshold for patterns"),
    ]
    lookback_days: Annotated[
        int,
        Field(default=90, description="Days before outcome to look for patterns"),
    ]
    similarity_threshold: Annotated[
        float,
        Field(default=0.7, description="Minimum similarity to match a pattern"),
    ]


class LearnedPattern(BaseModel):
    """A sequential pattern learned from historical data."""

    sequence: Annotated[list[str], Field(description="The activity sequence pattern")]
    outcome_type: Annotated[str, Field(description="Type of outcome this preceded")]
    support: Annotated[float, Field(description="How often this pattern appeared")]
    confidence: Annotated[float, Field(description="How often it led to the outcome")]
    examples: Annotated[
        list[str],
        Field(default_factory=list, description="Entity IDs where this pattern occurred"),
    ]


class RhymeDetector(BaseDetector):
    """Detects sequential patterns that have preceded outcomes before.

    This detector:
    1. Learns patterns from historical activities leading to outcomes
    2. Monitors current activities for similar patterns
    3. Alerts when a learned pattern is detected

    The key insight: if activity sequence A->B->C preceded outcome X
    multiple times before, seeing A->B->C again suggests X may follow.
    """

    def __init__(self, config: RhymeConfig | None = None):
        self.config = config or RhymeConfig()
        self._learned_patterns: list[LearnedPattern] = []
        self._now: datetime | None = None  # For testing

    @property
    def name(self) -> str:
        return "rhyme"

    @property
    def description(self) -> str:
        return "Detects patterns that preceded outcomes before (historical rhyming)"

    def _get_now(self) -> datetime:
        """Get current time (injectable for testing)."""
        return self._now or datetime.now(UTC)

    def _activities_to_sequence(
        self,
        activities: list[Activity],
        use_source: bool = True,
    ) -> list[str]:
        """Convert activities to a sequence of tokens.

        Tokens are formatted as "type:source" by default.
        """
        sorted_acts = sorted(activities, key=lambda a: a.occurred_at)

        tokens = []
        for act in sorted_acts:
            if use_source:
                token = f"{act.activity_type.value}:{act.source}"
            else:
                token = act.activity_type.value
            tokens.append(token)

        return tokens

    def _extract_sequences_before_outcomes(
        self,
        activities: list[Activity],
        outcomes: list[Outcome],
    ) -> dict[str, list[list[str]]]:
        """Extract activity sequences that preceded each outcome type.

        Returns a dict mapping outcome_type -> list of sequences.
        """
        sequences_by_outcome: dict[str, list[list[str]]] = defaultdict(list)

        # Group activities by entity
        activities_by_entity: dict[str, list[Activity]] = defaultdict(list)
        for act in activities:
            activities_by_entity[act.entity_id].append(act)

        # For each outcome, extract the preceding sequence
        for outcome in outcomes:
            entity_activities = activities_by_entity.get(outcome.entity_id, [])
            if not entity_activities:
                continue

            # Filter to activities within lookback window before outcome
            lookback_start = outcome.occurred_at - timedelta(days=self.config.lookback_days)

            preceding = [
                a
                for a in entity_activities
                if lookback_start <= a.occurred_at < outcome.occurred_at
            ]

            if len(preceding) >= self.config.min_sequence_length:
                sequence = self._activities_to_sequence(preceding)
                # Limit to max length
                if len(sequence) > self.config.max_sequence_length:
                    sequence = sequence[-self.config.max_sequence_length :]

                sequences_by_outcome[outcome.outcome_type].append(sequence)

        return sequences_by_outcome

    def _mine_patterns_prefixspan(
        self,
        sequences: list[list[str]],
    ) -> list[tuple[list[str], int]]:
        """Mine frequent sequential patterns using PrefixSpan."""
        if not PREFIXSPAN_AVAILABLE or not sequences:
            return []

        min_support_count = max(1, int(len(sequences) * self.config.min_support))

        ps = PrefixSpan(sequences)
        patterns = ps.frequent(min_support_count)

        return [(pattern, count) for count, pattern in patterns]

    def _mine_patterns_simple(
        self,
        sequences: list[list[str]],
    ) -> list[tuple[list[str], int]]:
        """Simple n-gram based pattern mining fallback."""
        if not sequences:
            return []

        pattern_counts: dict[tuple[str, ...], int] = defaultdict(int)

        # Extract all n-grams of varying lengths
        for seq in sequences:
            for n in range(
                self.config.min_sequence_length,
                min(len(seq) + 1, self.config.max_sequence_length + 1),
            ):
                for i in range(len(seq) - n + 1):
                    pattern = tuple(seq[i : i + n])
                    pattern_counts[pattern] += 1

        # Filter by minimum support
        min_count = max(1, int(len(sequences) * self.config.min_support))
        frequent = [
            (list(pattern), count)
            for pattern, count in pattern_counts.items()
            if count >= min_count
        ]

        # Sort by count descending, then by length descending
        frequent.sort(key=lambda x: (-x[1], -len(x[0])))

        return frequent

    def learn_patterns(
        self,
        activities: list[Activity],
        outcomes: list[Outcome],
    ) -> list[LearnedPattern]:
        """Learn sequential patterns from historical data.

        Args:
            activities: Historical activities
            outcomes: Labeled outcomes

        Returns:
            List of learned patterns
        """
        sequences_by_outcome = self._extract_sequences_before_outcomes(activities, outcomes)

        learned: list[LearnedPattern] = []

        for outcome_type, sequences in sequences_by_outcome.items():
            if not sequences:
                continue

            # Mine patterns
            if PREFIXSPAN_AVAILABLE:
                patterns = self._mine_patterns_prefixspan(sequences)
            else:
                patterns = self._mine_patterns_simple(sequences)

            total_sequences = len(sequences)

            for pattern, count in patterns:
                if len(pattern) < self.config.min_sequence_length:
                    continue

                support = count / total_sequences
                # Confidence is how often this pattern led to this outcome
                # For now, we only learn from positive cases, so confidence = support
                confidence = support

                learned.append(
                    LearnedPattern(
                        sequence=pattern,
                        outcome_type=outcome_type,
                        support=support,
                        confidence=confidence,
                    )
                )

        self._learned_patterns = learned
        return learned

    def _sequence_similarity(
        self,
        pattern: list[str],
        sequence: list[str],
    ) -> float:
        """Calculate how well a sequence matches a pattern.

        Returns a score from 0 to 1, where 1 means the pattern
        is fully contained in the sequence in order.
        """
        if not pattern or not sequence:
            return 0.0

        # Check if pattern is a subsequence of sequence
        pattern_idx = 0
        for token in sequence:
            if pattern_idx < len(pattern) and token == pattern[pattern_idx]:
                pattern_idx += 1

        # Return fraction of pattern matched
        return pattern_idx / len(pattern)

    def _calculate_confidence(
        self,
        pattern: LearnedPattern,
        similarity: float,
    ) -> float:
        """Calculate confidence for a rhyme detection.

        Higher confidence when:
        - Pattern has higher historical confidence
        - Pattern has higher support (appeared more often)
        - Current sequence matches pattern better
        """
        # Pattern confidence factor
        pattern_factor = pattern.confidence * 0.4

        # Support factor
        support_factor = min(0.3, pattern.support * 0.3)

        # Similarity factor
        similarity_factor = similarity * 0.3

        return min(1.0, pattern_factor + support_factor + similarity_factor)

    def _calculate_severity(self, confidence: float) -> AlertSeverity:
        """Determine severity based on confidence."""
        if confidence >= 0.7:
            return AlertSeverity.HIGH
        elif confidence >= 0.5:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def detect(
        self,
        entities: list[Entity],
        activities: list[Activity] | None = None,
        patterns: list[LearnedPattern] | None = None,
    ) -> list[Alert]:
        """Detect rhyming patterns in current activities.

        Args:
            entities: Entities to analyze
            activities: Current activities for these entities
            patterns: Optional patterns to use (defaults to learned patterns)

        Returns:
            List of alerts for detected rhymes
        """
        if not activities:
            return []

        use_patterns = patterns or self._learned_patterns
        if not use_patterns:
            return []

        alerts: list[Alert] = []
        entity_map = {e.entity_id: e for e in entities}

        # Group activities by entity
        activities_by_entity: dict[str, list[Activity]] = defaultdict(list)
        for act in activities:
            activities_by_entity[act.entity_id].append(act)

        # Check each entity's recent activity for pattern matches
        now = self._get_now()
        lookback_start = now - timedelta(days=self.config.lookback_days)

        for entity_id, entity_activities in activities_by_entity.items():
            # Filter to recent activities
            recent = [a for a in entity_activities if a.occurred_at >= lookback_start]

            if len(recent) < self.config.min_sequence_length:
                continue

            sequence = self._activities_to_sequence(recent)

            # Check against each learned pattern
            for pattern in use_patterns:
                similarity = self._sequence_similarity(pattern.sequence, sequence)

                if similarity >= self.config.similarity_threshold:
                    entity = entity_map.get(entity_id)
                    entity_name = entity.name if entity else entity_id

                    confidence = self._calculate_confidence(pattern, similarity)
                    severity = self._calculate_severity(confidence)

                    pattern_str = " → ".join(pattern.sequence)

                    alert = Alert(
                        alert_type=AlertType.RHYME,
                        title=f"Pattern match: {entity_name} - {pattern.outcome_type}",
                        description=(
                            f"{entity_name} is exhibiting a pattern that historically "
                            f"preceded {pattern.outcome_type}. Pattern: {pattern_str}. "
                            f"Match similarity: {similarity:.0%}. "
                            f"Historical pattern support: {pattern.support:.0%}."
                        ),
                        confidence=confidence,
                        severity=severity,
                        entity_refs=[entity_id],
                        detector_name=self.name,
                        detector_metadata={
                            "pattern": pattern.sequence,
                            "outcome_type": pattern.outcome_type,
                            "similarity": similarity,
                            "pattern_support": pattern.support,
                            "pattern_confidence": pattern.confidence,
                            "current_sequence": sequence[-10:],  # Last 10 for brevity
                        },
                    )
                    alerts.append(alert)

        return alerts
