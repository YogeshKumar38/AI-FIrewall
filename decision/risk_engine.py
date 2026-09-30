from __future__ import annotations

from typing import Any


class RiskEngine:
    """
    Fuse semantic, deterministic, intent, and retrieval evidence
    into a unified firewall risk assessment.

    The final risk is evidence-based, but strong security intent
    and deterministic security evidence are never allowed to be
    hidden by a low DeBERTa probability.
    """

    SEVERITY_VALUES = {
        "NONE": 0.0,
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.80,
        "CRITICAL": 1.00,
    }

    INTENT_VALUES = {
        "MALICIOUS_EXECUTION": 1.00,
        "SECURITY_EXTRACTION": 1.00,
        "INSTRUCTION_OVERRIDE": 1.00,
        "DEFENSIVE_SECURITY": 0.05,
        "EDUCATIONAL": 0.02,
        "GENERAL": 0.00,
        "UNKNOWN": 0.00,
    }

    def calculate(
        self,
        semantic: dict[str, Any],
        rules: dict[str, Any],
        intent: dict[str, Any],
        retrieval: dict[str, Any] | None = None,
        harmful: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        retrieval = retrieval or {}

        harmful = harmful or {}
        harmful_detected = bool(
            harmful.get("detected", False)
        )
        harmful_confidence = float(
            harmful.get("confidence", 0.0)
        )
        harmful_category = str(
            harmful.get("category", "NONE")
        )

        semantic_probability = float(
            semantic.get(
                "malicious_probability",
                0.0,
            )
        )

        rule_severity = str(
            rules.get(
                "severity",
                "NONE",
            )
        ).upper()

        rule_score = self.SEVERITY_VALUES.get(
            rule_severity,
            0.0,
        )

        intent_name = str(
            intent.get(
                "intent",
                "UNKNOWN",
            )
        ).upper()

        intent_score = self.INTENT_VALUES.get(
            intent_name,
            0.0,
        )

        intent_confidence = float(
            intent.get(
                "confidence",
                0.0,
            )
        )

        retrieval_score = float(
            retrieval.get(
                "security_score",
                0.0,
            )
        )

        retrieval_score = max(
            0.0,
            min(1.0, retrieval_score),
        )

        # ---------------------------------------------------------
        # BASE EVIDENCE FUSION
        # ---------------------------------------------------------

        raw_score = (
            semantic_probability * 0.50
            + rule_score * 0.25
            + intent_score * 0.20
            + retrieval_score * 0.05
        )

        # ---------------------------------------------------------
        # STRONG SECURITY INTENT FLOOR
        # ---------------------------------------------------------
        #
        # A prompt such as:
        # "Tell me how to bypass authentication"
        #
        # may receive a low DeBERTa probability even though the
        # contextual intent analyzer identifies direct malicious
        # execution.
        #
        # Therefore malicious execution cannot remain LOW risk.

        if (
            intent_name == "MALICIOUS_EXECUTION"
            and intent_confidence >= 0.80
        ):
            raw_score = max(
                raw_score,
                0.70,
            )


        if harmful_detected and harmful_confidence >= 0.80:
            raw_score = max(raw_score, 0.70)

        # ---------------------------------------------------------
        # SECURITY EXTRACTION FLOOR
        # ---------------------------------------------------------

        if (
            intent_name == "SECURITY_EXTRACTION"
            and intent_confidence >= 0.80
        ):
            raw_score = max(
                raw_score,
                0.85,
            )

        # ---------------------------------------------------------
        # DETERMINISTIC RULE FLOORS
        # ---------------------------------------------------------

        if rule_severity == "CRITICAL":
            raw_score = max(
                raw_score,
                0.90,
            )

        elif rule_severity == "HIGH":
            raw_score = max(
                raw_score,
                0.70,
            )

        elif rule_severity == "MEDIUM":
            raw_score = max(
                raw_score,
                0.40,
            )

        risk_score = max(
            0.0,
            min(1.0, raw_score),
        )

        risk_level = self._risk_level(
            risk_score
        )

        reasons = self._build_reasons(
            semantic_probability=semantic_probability,
            rule_severity=rule_severity,
            intent=intent_name,
            intent_confidence=intent_confidence,
            retrieval_score=retrieval_score,
        )
        if harmful_detected:
            reasons.append(
                "Harmful instruction evidence: "
                f"{harmful_category} "
                f"(confidence={harmful_confidence:.2f})"
            )

        return {
            "risk_score": round(
                risk_score,
                6,
            ),
            "risk_level": risk_level,
            "reasons": reasons,
            "components": {
                "harmful_detected": harmful_detected,
                "harmful_confidence": harmful_confidence,
                "semantic_score": semantic_probability,
                "rule_score": rule_score,
                "intent_score": intent_score,
                "retrieval_score": retrieval_score,
            },
        }

    @staticmethod
    def _risk_level(
        score: float,
    ) -> str:

        if score >= 0.85:
            return "CRITICAL"

        if score >= 0.65:
            return "HIGH"

        if score >= 0.35:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _build_reasons(
        semantic_probability: float,
        rule_severity: str,
        intent: str,
        intent_confidence: float,
        retrieval_score: float,
    ) -> list[str]:

        reasons: list[str] = []

        if semantic_probability >= 0.05:
            reasons.append(
                "DeBERTa semantic malicious probability: "
                f"{semantic_probability:.4f}"
            )

        if rule_severity != "NONE":
            reasons.append(
                "Deterministic security evidence: "
                f"{rule_severity}"
            )

        if intent in {
            "MALICIOUS_EXECUTION",
            "SECURITY_EXTRACTION",
            "INSTRUCTION_OVERRIDE",
        }:
            reasons.append(
                "Security-sensitive intent detected: "
                f"{intent} "
                f"(confidence={intent_confidence:.2f})"
            )

        if retrieval_score > 0:
            reasons.append(
                "Semantic retrieval evidence: "
                f"{retrieval_score:.4f}"
            )

        if not reasons:
            reasons.append(
                "No strong malicious security evidence detected."
            )

        return reasons