"""Evidence model, classifications and confidence scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Classification(StrEnum):
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    CONFIRMED_PATCHED = "CONFIRMED_PATCHED"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


CLASSIFICATION_MEANING: dict[Classification, str] = {
    Classification.CONFIRMED_VULNERABLE: (
        "Direct, verifiable evidence of an affected build that lacks the security fix."
    ),
    Classification.CONFIRMED_PATCHED: "Reliable evidence that the fix is present.",
    Classification.POTENTIALLY_VULNERABLE: (
        "Evidence points to possible exposure, but patch status cannot be established remotely."
    ),
    Classification.INCONCLUSIVE: (
        "Not enough evidence to establish exposure. This does not mean the host is not vulnerable."
    ),
    Classification.NOT_APPLICABLE: (
        "Reliable evidence that the assessed URL is not served by a PHP runtime."
    ),
}


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class EvidenceKind(StrEnum):
    PHP_PRESENCE = "php_presence"
    PHP_VERSION = "php_version"
    PATCH_MARKER = "patch_marker"
    NON_PHP = "non_php"
    ENVIRONMENT = "environment"
    CONFIGURATION = "configuration"
    ANOMALY = "anomaly"


@dataclass(slots=True)
class Evidence:
    kind: EvidenceKind
    method: str
    """Detection method identifier, e.g. 'header.x-powered-by'."""
    description: str
    source_url: str
    observed: str = ""
    """The raw observed value (truncated). Never synthesised."""
    weight: float = 0.0
    """For PHP_PRESENCE / NON_PHP: the strength of the signal, from 0 to 1."""
    validated: bool = False
    """True when the signal was validated against lab builds (see research/)."""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass(slots=True)
class PhpDetection:
    score: float
    confidence: Confidence
    evidence: list[Evidence] = field(default_factory=list)
    non_php_evidence: list[Evidence] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return self.confidence is not Confidence.NONE


def combine_weights(weights: list[float]) -> float:
    """Noisy-OR: independent signals, any of which may indicate PHP."""
    p_absent = 1.0
    for w in weights:
        p_absent *= 1.0 - max(0.0, min(1.0, w))
    return round(1.0 - p_absent, 3)


def score_to_confidence(score: float) -> Confidence:
    if score >= 0.9:
        return Confidence.HIGH
    if score >= 0.6:
        return Confidence.MEDIUM
    if score > 0:
        return Confidence.LOW
    return Confidence.NONE


def assess_php_presence(evidence: list[Evidence]) -> PhpDetection:
    php = [e for e in evidence if e.kind is EvidenceKind.PHP_PRESENCE]
    non_php = [e for e in evidence if e.kind is EvidenceKind.NON_PHP]
    # Only the strongest signal per method counts, so repeated cookies or links
    # on one page cannot inflate the score.
    best: dict[str, float] = {}
    for e in php:
        best[e.method] = max(best.get(e.method, 0.0), e.weight)
    score = combine_weights(list(best.values()))
    return PhpDetection(score=score, confidence=score_to_confidence(score), evidence=php, non_php_evidence=non_php)
