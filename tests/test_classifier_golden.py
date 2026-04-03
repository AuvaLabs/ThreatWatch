"""Golden dataset classifier regression test.

Runs the keyword classifier against the hand-labeled golden dataset
and asserts minimum accuracy thresholds. This test runs in CI to catch
classifier regressions.

Thresholds:
- Overall accuracy >= 85%
- Cyber relevance accuracy >= 95%
- Macro F1 >= 0.80
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.keyword_classifier import classify_article

GOLDEN_PATH = Path(__file__).parent.parent / "data" / "golden_dataset.json"


@pytest.fixture(scope="module")
def golden_results():
    if not GOLDEN_PATH.exists():
        pytest.skip("Golden dataset not found")

    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    results = []

    for item in golden:
        prediction = classify_article(item["title"], item.get("content", ""))
        pred_cyber = prediction.get("is_cyber_attack", False)
        pred_cat = prediction.get("category", "UNKNOWN")

        if item["expected_category"] == "Noise":
            correct = not pred_cyber
        else:
            correct = pred_cat == item["expected_category"]

        results.append({
            "expected": item["expected_category"],
            "predicted": pred_cat,
            "expected_cyber": item["expected_cyber"],
            "predicted_cyber": pred_cyber,
            "correct": correct,
        })

    return results


def test_overall_accuracy(golden_results):
    correct = sum(1 for r in golden_results if r["correct"])
    accuracy = correct / len(golden_results) * 100
    assert accuracy >= 85.0, f"Overall accuracy {accuracy:.1f}% below 85% threshold"


def test_cyber_relevance_accuracy(golden_results):
    correct = sum(1 for r in golden_results
                  if r["expected_cyber"] == r["predicted_cyber"])
    accuracy = correct / len(golden_results) * 100
    assert accuracy >= 95.0, f"Cyber relevance accuracy {accuracy:.1f}% below 95% threshold"


def test_macro_f1(golden_results):
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)

    for r in golden_results:
        expected = r["expected"]
        predicted = r["predicted"]

        if expected == "Noise":
            if not r["predicted_cyber"]:
                tp["Noise"] += 1
            else:
                fn["Noise"] += 1
                fp[predicted] += 1
        elif r["correct"]:
            tp[expected] += 1
        else:
            fn[expected] += 1
            if predicted != "General Cyber Threat":
                fp[predicted] += 1

    all_cats = set(list(tp.keys()) + list(fp.keys()) + list(fn.keys()))
    f1_scores = []
    for cat in all_cats:
        t = tp.get(cat, 0)
        f_p = fp.get(cat, 0)
        f_n = fn.get(cat, 0)
        precision = t / (t + f_p) if (t + f_p) > 0 else 0
        recall = t / (t + f_n) if (t + f_n) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        if t + f_n > 0:  # Only include categories that have golden samples
            f1_scores.append(f1)

    macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0
    assert macro_f1 >= 0.80, f"Macro F1 {macro_f1:.3f} below 0.80 threshold"


def test_no_category_has_zero_recall(golden_results):
    """Every category with golden samples should have at least some correct predictions."""
    by_cat = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in golden_results:
        cat = r["expected"]
        by_cat[cat]["total"] += 1
        if r["correct"]:
            by_cat[cat]["correct"] += 1

    zero_recall = [cat for cat, stats in by_cat.items()
                   if stats["total"] >= 5 and stats["correct"] == 0]
    assert not zero_recall, f"Categories with zero recall (5+ samples): {zero_recall}"
