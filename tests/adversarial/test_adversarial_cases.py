from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.pipeline import AIFirewall


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    ROOT
    / "tests"
    / "adversarial"
    / "adversarial_cases.json"
)

REPORT_DIR = ROOT / "evaluation" / "reports"

REPORT_PATH = REPORT_DIR / "adversarial_v1_results.json"


# ---------------------------------------------------------
# DATASET LOADER
# ---------------------------------------------------------

def load_cases():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------
# FIXTURE
# ---------------------------------------------------------

@pytest.fixture(scope="module")
def firewall():
    """
    Create the AI Firewall only once for the complete benchmark.
    """
    return AIFirewall()


# ---------------------------------------------------------
# DATASET INTEGRITY TEST
# ---------------------------------------------------------

def test_dataset_integrity():

    cases = load_cases()

    assert len(cases) == 100, (
        f"Expected 100 cases, found {len(cases)}"
    )

    required_fields = {
        "id",
        "prompt",
        "expected_label",
        "category",
        "severity",
    }

    ids = set()

    for case in cases:

        assert required_fields.issubset(case.keys()), (
            f"Missing field in case {case.get('id')}"
        )

        assert case["id"] not in ids, (
            f"Duplicate case ID: {case['id']}"
        )

        ids.add(case["id"])

        assert case["expected_label"] in {
            "BENIGN",
            "MALICIOUS",
        }

    assert len(ids) == 100


# ---------------------------------------------------------
# METRIC FUNCTIONS
# ---------------------------------------------------------

def calculate_metrics(rows, prediction_field):

    tp = tn = fp = fn = 0

    for row in rows:

        expected = row["expected_label"] == "MALICIOUS"
        predicted = row[prediction_field] == "MALICIOUS"

        if expected and predicted:
            tp += 1

        elif not expected and not predicted:
            tn += 1

        elif not expected and predicted:
            fp += 1

        elif expected and not predicted:
            fn += 1

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    false_negative_rate = (
        fn / (fn + tp)
        if (fn + tp)
        else 0.0
    )

    return {
        "total": total,
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
    }


# ---------------------------------------------------------
# CATEGORY METRICS
# ---------------------------------------------------------

def calculate_category_metrics(rows):

    grouped = defaultdict(list)

    for row in rows:
        grouped[row["category"]].append(row)

    results = {}

    for category, category_rows in sorted(grouped.items()):

        semantic_metrics = calculate_metrics(
            category_rows,
            "semantic_predicted_label",
        )

        firewall_metrics = calculate_metrics(
            category_rows,
            "firewall_predicted_label",
        )

        results[category] = {
            "cases": len(category_rows),
            "semantic_accuracy": semantic_metrics["accuracy"],
            "firewall_behavior_accuracy": firewall_metrics["accuracy"],
            "semantic_false_negatives": semantic_metrics["false_negative"],
            "semantic_false_positives": semantic_metrics["false_positive"],
            "firewall_false_negatives": firewall_metrics["false_negative"],
            "firewall_false_positives": firewall_metrics["false_positive"],
        }

    return results


# ---------------------------------------------------------
# MAIN ADVERSARIAL BENCHMARK
# ---------------------------------------------------------

def test_run_adversarial_benchmark(firewall):

    cases = load_cases()

    results = []
    execution_errors = []

    print("\n")
    print("=" * 90)
    print("AI FIREWALL — ADVERSARIAL BENCHMARK V1")
    print("=" * 90)

    for index, case in enumerate(cases, start=1):

        case_id = case["id"]
        prompt = case["prompt"]
        expected = case["expected_label"]

        try:

            result = firewall.analyze(prompt)

            # ---------------------------------------------
            # SEMANTIC MODEL RESULT
            # ---------------------------------------------

            semantic_label = (
                result.semantic.label.upper()
            )

            # ---------------------------------------------
            # FULL FIREWALL BEHAVIOR
            #
            # ALLOW = BENIGN behavior
            # REVIEW/BLOCK = MALICIOUS/UNSAFE behavior
            # ---------------------------------------------

            if result.decision.upper() == "ALLOW":
                firewall_label = "BENIGN"
            else:
                firewall_label = "MALICIOUS"

            # ---------------------------------------------
            # LAYER INFORMATION
            # ---------------------------------------------

            row = {
                "id": case_id,
                "prompt": prompt,
                "expected_label": expected,
                "category": case["category"],
                "expected_severity": case["severity"],

                # Semantic model
                "semantic_predicted_label": semantic_label,
                "semantic_probability": result.semantic.malicious_probability,

                # Rule layer
                "rule_matched": result.rules.matched,
                "rule_severity": result.rules.severity,
                "rule_categories": result.rules.categories,

                # Intent layer
                "intent": result.intent.intent,
                "intent_category": result.intent.category,
                "intent_confidence": result.intent.confidence,

                # Retrieval layer
                "retrieval_matched": result.retrieval.matched,
                "retrieval_similarity": result.retrieval.similarity,
                "retrieval_matches": result.retrieval.matches,

                # Risk engine
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,

                # Policy engine
                "decision": result.decision,
                "llm_allowed": result.metadata.get(
                    "llm_allowed",
                    False,
                ),

                # Overall firewall behavior
                "firewall_predicted_label": firewall_label,

                # Correctness
                "semantic_correct": (
                    semantic_label == expected
                ),

                "firewall_behavior_correct": (
                    firewall_label == expected
                ),
            }

            results.append(row)

            status = (
                "PASS"
                if row["firewall_behavior_correct"]
                else "FAIL"
            )

            print(
                f"[{index:03d}/100] "
                f"{case_id} | "
                f"EXP={expected:<9} | "
                f"SEM={semantic_label:<9} | "
                f"DEC={result.decision:<6} | "
                f"RISK={result.risk_level:<8} | "
                f"INTENT={result.intent.intent:<24} | "
                f"{status}"
            )

        except Exception as exc:

            error = {
                "id": case_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

            execution_errors.append(error)

            print(
                f"[{index:03d}/100] "
                f"{case_id} | EXECUTION ERROR | "
                f"{type(exc).__name__}: {exc}"
            )

    # -----------------------------------------------------
    # METRICS
    # -----------------------------------------------------

    semantic_metrics = calculate_metrics(
        results,
        "semantic_predicted_label",
    )

    firewall_metrics = calculate_metrics(
        results,
        "firewall_predicted_label",
    )

    category_metrics = calculate_category_metrics(
        results
    )

    # -----------------------------------------------------
    # FAILURE ANALYSIS
    # -----------------------------------------------------

    semantic_false_negatives = [
        row
        for row in results
        if (
            row["expected_label"] == "MALICIOUS"
            and row["semantic_predicted_label"] == "BENIGN"
        )
    ]

    semantic_false_positives = [
        row
        for row in results
        if (
            row["expected_label"] == "BENIGN"
            and row["semantic_predicted_label"] == "MALICIOUS"
        )
    ]

    firewall_false_negatives = [
        row
        for row in results
        if (
            row["expected_label"] == "MALICIOUS"
            and row["firewall_predicted_label"] == "BENIGN"
        )
    ]

    firewall_false_positives = [
        row
        for row in results
        if (
            row["expected_label"] == "BENIGN"
            and row["firewall_predicted_label"] == "MALICIOUS"
        )
    ]

    # -----------------------------------------------------
    # REPORT
    # -----------------------------------------------------

    report = {
        "benchmark": {
            "name": "AI Firewall Adversarial Benchmark V1",
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "dataset": str(DATASET_PATH),
            "total_cases": len(cases),
            "executed_cases": len(results),
            "execution_errors": len(execution_errors),
        },

        "overall_metrics": {
            "semantic_model": semantic_metrics,
            "full_firewall_behavior": firewall_metrics,
        },

        "category_metrics": category_metrics,

        "semantic_false_negatives": semantic_false_negatives,
        "semantic_false_positives": semantic_false_positives,

        "firewall_false_negatives": firewall_false_negatives,
        "firewall_false_positives": firewall_false_positives,

        "execution_errors": execution_errors,

        "cases": results,
    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        REPORT_PATH,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print("\n")
    print("=" * 90)
    print("BENCHMARK SUMMARY")
    print("=" * 90)

    print(
        f"Cases executed       : {len(results)}/100"
    )

    print(
        f"Execution errors     : {len(execution_errors)}"
    )

    print("\nSemantic Model:")
    print(
        f"  Accuracy           : "
        f"{semantic_metrics['accuracy']:.2%}"
    )
    print(
        f"  Precision          : "
        f"{semantic_metrics['precision']:.2%}"
    )
    print(
        f"  Recall             : "
        f"{semantic_metrics['recall']:.2%}"
    )
    print(
        f"  F1                 : "
        f"{semantic_metrics['f1']:.2%}"
    )
    print(
        f"  False Negatives    : "
        f"{semantic_metrics['false_negative']}"
    )
    print(
        f"  False Positives    : "
        f"{semantic_metrics['false_positive']}"
    )

    print("\nFull Firewall Behavior:")
    print(
        f"  Accuracy           : "
        f"{firewall_metrics['accuracy']:.2%}"
    )
    print(
        f"  Precision          : "
        f"{firewall_metrics['precision']:.2%}"
    )
    print(
        f"  Recall             : "
        f"{firewall_metrics['recall']:.2%}"
    )
    print(
        f"  F1                 : "
        f"{firewall_metrics['f1']:.2%}"
    )
    print(
        f"  False Negatives    : "
        f"{firewall_metrics['false_negative']}"
    )
    print(
        f"  False Positives    : "
        f"{firewall_metrics['false_positive']}"
    )

    print("\nCategory Results:")
    for category, metrics in category_metrics.items():

        print(
            f"  {category:<28} "
            f"Semantic={metrics['semantic_accuracy']:.2%} | "
            f"Firewall={metrics['firewall_behavior_accuracy']:.2%}"
        )

    print("\nFailure Analysis:")

    print(
        f"  Semantic false negatives : "
        f"{len(semantic_false_negatives)}"
    )

    print(
        f"  Semantic false positives : "
        f"{len(semantic_false_positives)}"
    )

    print(
        f"  Firewall false negatives : "
        f"{len(firewall_false_negatives)}"
    )

    print(
        f"  Firewall false positives : "
        f"{len(firewall_false_positives)}"
    )

    print("\nReport saved to:")
    print(REPORT_PATH)

    print("=" * 90)

    # Pipeline execution errors are actual test failures.
    # Model mistakes are recorded for analysis and should NOT
    # make pytest fail automatically.
    assert not execution_errors, (
        f"{len(execution_errors)} pipeline execution errors occurred. "
        f"See {REPORT_PATH}"
    )