"""Test keyword classifier accuracy against golden dataset.

Runs every golden-labeled article through the keyword classifier,
compares predicted vs expected category, and reports precision/recall/F1
per category.

Usage:
    python scripts/test_classifier_accuracy.py [--verbose]
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.keyword_classifier import classify_article


def load_golden(path=None):
    if path is None:
        path = Path(__file__).parent.parent / "data" / "golden_dataset.json"
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_accuracy_test(golden, verbose=False):
    results = []
    for item in golden:
        title = item["title"]
        content = item.get("content", "")
        expected_cat = item["expected_category"]
        expected_cyber = item["expected_cyber"]

        prediction = classify_article(title, content)
        pred_cyber = prediction.get("is_cyber_attack", False)
        pred_cat = prediction.get("category", "UNKNOWN")
        pred_conf = prediction.get("confidence", 0)

        # For noise items, check if classifier correctly rejected
        if expected_cat == "Noise":
            correct = not pred_cyber
        else:
            correct = pred_cat == expected_cat

        results.append({
            "title": title[:100],
            "expected_category": expected_cat,
            "predicted_category": pred_cat,
            "expected_cyber": expected_cyber,
            "predicted_cyber": pred_cyber,
            "confidence": pred_conf,
            "correct": correct,
        })

    return results


def compute_metrics(results):
    """Compute precision, recall, F1 per category."""
    # True positives, false positives, false negatives per category
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)

    for r in results:
        expected = r["expected_category"]
        predicted = r["predicted_category"]

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

    all_cats = sorted(set(list(tp.keys()) + list(fp.keys()) + list(fn.keys())))

    metrics = {}
    for cat in all_cats:
        t = tp.get(cat, 0)
        f_p = fp.get(cat, 0)
        f_n = fn.get(cat, 0)

        precision = t / (t + f_p) if (t + f_p) > 0 else 0
        recall = t / (t + f_n) if (t + f_n) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics[cat] = {
            "true_positives": t,
            "false_positives": f_p,
            "false_negatives": f_n,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }

    # Overall accuracy
    correct = sum(1 for r in results if r["correct"])
    total = len(results)
    overall = {
        "correct": correct,
        "total": total,
        "accuracy": round(correct / total * 100, 1) if total else 0,
    }

    # Cyber relevance accuracy (is_cyber_attack correct?)
    cyber_correct = sum(1 for r in results if r["expected_cyber"] == r["predicted_cyber"])
    overall["cyber_relevance_accuracy"] = round(cyber_correct / total * 100, 1) if total else 0

    return metrics, overall


def print_report(results, metrics, overall, verbose=False):
    sep = "=" * 72

    print(f"\n{sep}")
    print("  CLASSIFIER ACCURACY REPORT")
    print(f"  Golden dataset: {overall['total']} articles")
    print(f"  Overall accuracy: {overall['accuracy']}%")
    print(f"  Cyber relevance accuracy: {overall['cyber_relevance_accuracy']}%")
    print(sep)

    # Per-category metrics
    print(f"\n{'Category':<30} {'Prec':>6} {'Recall':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("─" * 72)
    for cat in sorted(metrics.keys()):
        m = metrics[cat]
        print(f"  {cat:<28} {m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} "
              f"{m['true_positives']:>4} {m['false_positives']:>4} {m['false_negatives']:>4}")

    # Macro-average
    cats_with_data = [m for m in metrics.values() if m["true_positives"] + m["false_negatives"] > 0]
    if cats_with_data:
        macro_p = sum(m["precision"] for m in cats_with_data) / len(cats_with_data)
        macro_r = sum(m["recall"] for m in cats_with_data) / len(cats_with_data)
        macro_f1 = sum(m["f1"] for m in cats_with_data) / len(cats_with_data)
        print("─" * 72)
        print(f"  {'MACRO AVERAGE':<28} {macro_p:>6.3f} {macro_r:>6.3f} {macro_f1:>6.3f}")

    # Misclassified articles
    errors = [r for r in results if not r["correct"]]
    if errors:
        print(f"\n{'─' * 40}")
        print(f"  ERRORS ({len(errors)})")
        print(f"{'─' * 40}")
        for r in errors:
            print(f"  [{r['expected_category']} -> {r['predicted_category']}] "
                  f"(conf={r['confidence']}) {r['title']}")

    print(f"\n{sep}\n")

    return {
        "overall": overall,
        "metrics": metrics,
        "errors": [
            {
                "title": r["title"],
                "expected": r["expected_category"],
                "predicted": r["predicted_category"],
                "confidence": r["confidence"],
            }
            for r in errors
        ],
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--golden", type=str, help="Path to golden dataset JSON")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    golden = load_golden(args.golden)
    results = run_accuracy_test(golden, verbose=args.verbose)
    metrics, overall = compute_metrics(results)
    report = print_report(results, metrics, overall, verbose=args.verbose)

    if args.json:
        print(json.dumps(report, indent=2))
