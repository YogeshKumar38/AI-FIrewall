
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SemanticAnalysis:
    """Result produced by the trained semantic security model."""

    label: str
    benign_probability: float
    malicious_probability: float
    threshold: float
    model_name: str
    model_version: str

    @property
    def is_malicious(self) -> bool:
        return self.malicious_probability >= self.threshold


@dataclass
class RuleAnalysis:
    """Evidence produced by the deterministic security layer."""

    matched: bool = False
    severity: str = "NONE"
    categories: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)


@dataclass
class IntentAnalysis:
    """Context and intent information."""

    intent: str = "UNKNOWN"
    category: str = "UNKNOWN"
    confidence: float = 0.0
    reasoning: list[str] = field(default_factory=list)


@dataclass
class HarmfulAnalysis:
    """Evidence from the harmful-instruction analysis layer."""

    detected: bool = False
    category: str = "NONE"
    confidence: float = 0.0
    reasoning: list[str] = field(default_factory=list)


@dataclass
class RetrievalAnalysis:
    """Evidence retrieved from the semantic security knowledge base."""

    matched: bool = False
    similarity: float = 0.0
    matches: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SecurityResult:
    """Unified result passed between firewall components."""

    original_prompt: str
    normalized_prompt: str

    semantic: SemanticAnalysis | None = None
    rules: RuleAnalysis = field(default_factory=RuleAnalysis)
    intent: IntentAnalysis = field(default_factory=IntentAnalysis)
    harmful: HarmfulAnalysis = field(default_factory=HarmfulAnalysis)
    retrieval: RetrievalAnalysis = field(
        default_factory=RetrievalAnalysis
    )

    risk_level: str = "UNKNOWN"
    risk_score: float = 0.0
    decision: str = "PENDING"

    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the complete result into a serializable dictionary."""

        semantic = None

        if self.semantic is not None:
            semantic = {
                "label": self.semantic.label,
                "malicious_probability": self.semantic.malicious_probability,
                "threshold": self.semantic.threshold,
                "model_name": self.semantic.model_name,
                "model_version": self.semantic.model_version,
                "is_malicious": self.semantic.is_malicious,
            }

        return {
            "original_prompt": self.original_prompt,
            "normalized_prompt": self.normalized_prompt,
            "semantic": semantic,
            "rules": {
                "matched": self.rules.matched,
                "severity": self.rules.severity,
                "categories": self.rules.categories,
                "signals": self.rules.signals,
            },
            "intent": {
                "intent": self.intent.intent,
                "category": self.intent.category,
                "confidence": self.intent.confidence,
                "reasoning": self.intent.reasoning,
            },
            "harmful": {
                "detected": self.harmful.detected,
                "category": self.harmful.category,
                "confidence": self.harmful.confidence,
                "reasoning": self.harmful.reasoning,
            },
            "retrieval": {
                "matched": self.retrieval.matched,
                "similarity": self.retrieval.similarity,
                "matches": self.retrieval.matches,
            },
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "reasons": self.reasons,
            "metadata": self.metadata,
        }