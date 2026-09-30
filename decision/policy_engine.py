from __future__ import annotations

from typing import Any

from config.settings import load_security_policy


class PolicyEngine:
    """Convert risk assessment into a firewall action."""

    VALID_DECISIONS = {
        "ALLOW",
        "REVIEW",
        "BLOCK",
    }

    def __init__(self) -> None:

        policy = load_security_policy()

        self.actions = policy["risk_policy"]["actions"]

        self.firewall_before_llm = bool(
            policy["llm_boundary"]["firewall_before_llm"]
        )

        self.blocked_prompts_reach_llm = bool(
            policy["llm_boundary"]["blocked_prompts_reach_llm"]
        )

        if not self.firewall_before_llm:
            raise ValueError(
                "Security policy violation: firewall must run before LLM."
            )

        if self.blocked_prompts_reach_llm:
            raise ValueError(
                "Security policy violation: blocked prompts "
                "must never reach the LLM."
            )

    def decide(
        self,
        risk: dict[str, Any],
    ) -> dict[str, Any]:

        risk_level = risk["risk_level"]

        if risk_level not in self.actions:
            raise ValueError(
                f"Unknown risk level: {risk_level}"
            )

        decision = self.actions[risk_level]

        if decision not in self.VALID_DECISIONS:
            raise ValueError(
                f"Invalid policy decision for "
                f"{risk_level}: {decision}"
            )

        return {
            "decision": decision,
            "risk_level": risk_level,
            "llm_allowed": decision == "ALLOW",
        }


if __name__ == "__main__":

    print("=" * 70)
    print("AI FIREWALL — POLICY ENGINE TEST")
    print("=" * 70)

    engine = PolicyEngine()

    test_risks = [
        {"risk_level": "LOW"},
        {"risk_level": "MEDIUM"},
        {"risk_level": "HIGH"},
        {"risk_level": "CRITICAL"},
    ]

    for risk in test_risks:

        result = engine.decide(risk)

        print("\nRISK LEVEL :", risk["risk_level"])
        print("DECISION   :", result["decision"])
        print("LLM ALLOWED:", result["llm_allowed"])

    print("\n" + "=" * 70)
    print("POLICY ENGINE TEST COMPLETE")
    print("=" * 70)