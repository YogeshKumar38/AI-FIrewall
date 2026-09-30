from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# Project root:
# AI_Firewall/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

POLICY_PATH = PROJECT_ROOT / "config" / "security_policy.json"


def load_security_policy() -> dict[str, Any]:
    """Load and validate the firewall security policy."""

    if not POLICY_PATH.exists():
        raise FileNotFoundError(
            f"Security policy not found: {POLICY_PATH}"
        )

    with POLICY_PATH.open("r", encoding="utf-8") as file:
        policy = json.load(file)

    required_sections = [
        "project",
        "semantic_model",
        "risk_policy",
        "pipeline",
        "llm_boundary",
    ]

    missing = [
        section
        for section in required_sections
        if section not in policy
    ]

    if missing:
        raise ValueError(
            f"Security policy is missing required sections: {missing}"
        )

    semantic_model = policy["semantic_model"]

    if "path" not in semantic_model:
        raise ValueError("semantic_model.path is required.")

    if "threshold" not in semantic_model:
        raise ValueError("semantic_model.threshold is required.")

    threshold = float(semantic_model["threshold"])

    if not 0.0 < threshold < 1.0:
        raise ValueError(
            f"Semantic threshold must be between 0 and 1. Got: {threshold}"
        )

    labels = semantic_model.get("labels", {})

    if labels.get("0") != "BENIGN":
        raise ValueError("Label 0 must map to BENIGN.")

    if labels.get("1") != "MALICIOUS":
        raise ValueError("Label 1 must map to MALICIOUS.")

    return policy


def get_model_path() -> Path:
    """Return the absolute path of the production semantic model."""

    policy = load_security_policy()

    relative_path = Path(
        policy["semantic_model"]["path"]
    )

    model_path = PROJECT_ROOT / relative_path

    if not model_path.exists():
        raise FileNotFoundError(
            f"Semantic model directory not found: {model_path}"
        )

    return model_path


def get_semantic_threshold() -> float:
    """Return the validated semantic detection threshold."""

    policy = load_security_policy()

    return float(
        policy["semantic_model"]["threshold"]
    )


def get_max_length() -> int:
    """Return the maximum tokenizer sequence length."""

    policy = load_security_policy()

    return int(
        policy["semantic_model"].get("max_length", 256)
    )


if __name__ == "__main__":
    policy = load_security_policy()

    print("=" * 70)
    print("AI FIREWALL — CONFIGURATION CHECK")
    print("=" * 70)

    print("Project       :", policy["project"]["name"])
    print("Version       :", policy["project"]["version"])
    print("Model path    :", get_model_path())
    print("Threshold     :", get_semantic_threshold())
    print("Max length    :", get_max_length())

    print("\n✓ Security policy loaded successfully")