"""Metrics for flow detectors, chosen for an analyst's queue rather than a leaderboard.

A detector gives every flow a score; higher means more likely an attack. Accuracy is never
reported: with mostly benign traffic it rewards a detector that never alerts. Instead:

* **PR-AUC** (average precision) over the attack class, which does not depend on a threshold
  and, unlike ROC-AUC, is not flattered by a large benign majority. Its chance level is the
  share of attacks (``prevalence``).
* **Operating points.** For each target false-positive rate a threshold is chosen on the
  *validation* split's benign flows, then frozen. The test split is scored once with it, and the
  report gives the false-positive rate actually reached, recall, precision, **false alerts per
  10,000 flows** and **recall per attack class**.
"""

import math
from collections.abc import Sequence
from typing import Any

from prohori.ml import MissingExtraError

try:
    import numpy as np
    from numpy.typing import ArrayLike
    from sklearn.metrics import average_precision_score, roc_auc_score
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.evaluate") from exc

#: Target false-positive rates: 1 in 100 and 1 in 1,000 benign flows.
TARGET_FPRS = (0.01, 0.001)


def point_name(fpr: float) -> str:
    """``0.001`` -> ``"fpr_0.001"``; the key of an operating point in the results."""
    return f"fpr_{fpr:g}"


def threshold_for_fpr(benign_scores: np.ndarray, fpr: float) -> float:
    """The lowest threshold at which at most ``fpr`` of these benign flows score at or above it.

    Alerts are ``score >= threshold``. Ties are never split, so the rate reached can be lower
    than the target, never higher (on the flows the threshold was chosen on).
    """
    if not 0 < fpr < 1:
        msg = f"fpr must be between 0 and 1, got {fpr}"
        raise ValueError(msg)
    scores = np.sort(np.asarray(benign_scores, dtype="float64"))[::-1]
    if scores.size == 0:
        msg = "no benign flows to choose a threshold on"
        raise ValueError(msg)
    allowed = math.floor(fpr * scores.size)
    if allowed >= scores.size:  # pragma: no cover - fpr < 1 makes this impossible
        return float(scores[-1])
    return float(np.nextafter(scores[allowed], np.inf))


def operating_point(
    labels: np.ndarray, scores: np.ndarray, categories: np.ndarray, threshold: float
) -> dict[str, Any]:
    """Counts and rates when alerting on ``score >= threshold``."""
    alerts = scores >= threshold
    attack = labels == 1
    benign = ~attack
    true_alerts = int((alerts & attack).sum())
    false_alerts = int((alerts & benign).sum())
    per_class: dict[str, dict[str, float | int]] = {}
    for name in sorted(set(categories[attack].tolist())):
        rows = categories == name
        per_class[str(name)] = {
            "flows": int(rows.sum()),
            "recall": float(alerts[rows].mean()),
        }
    return {
        "threshold": threshold,
        "alerts": int(alerts.sum()),
        "recall": true_alerts / int(attack.sum()) if attack.any() else None,
        "precision": true_alerts / int(alerts.sum()) if alerts.any() else None,
        "fpr": false_alerts / int(benign.sum()) if benign.any() else None,
        "false_alerts_per_10k": 10_000 * false_alerts / labels.size,
        "per_class_recall": per_class,
    }


def evaluate(
    labels: ArrayLike,
    scores: ArrayLike,
    categories: ArrayLike,
    thresholds: dict[str, float],
) -> dict[str, Any]:
    """Every metric for one split; ``thresholds`` maps operating-point names to thresholds."""
    y = np.asarray(labels, dtype="int64")
    s = np.asarray(scores, dtype="float64")
    c = np.asarray(categories, dtype=object)
    both = 0 < y.sum() < y.size
    return {
        "flows": int(y.size),
        "attacks": int(y.sum()),
        "prevalence": float(y.mean()) if y.size else None,
        "pr_auc": float(average_precision_score(y, s)) if both else None,
        "roc_auc": float(roc_auc_score(y, s)) if both else None,
        "operating_points": {
            name: operating_point(y, s, c, threshold) for name, threshold in thresholds.items()
        },
    }


def summarise(runs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Mean, standard deviation and count of every number across runs (seeds).

    Runs need not have the same keys (a class can be missing from one seed's test split); each
    number is summarised over the runs that have it. ``None`` values are skipped.
    """
    values: dict[tuple[str, ...], list[float]] = {}

    def walk(node: object, path: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, (*path, str(key)))
        elif isinstance(node, bool) or node is None:
            return
        elif isinstance(node, int | float):
            values.setdefault(path, []).append(float(node))

    for run in runs:
        walk(run, ())
    summary: dict[str, Any] = {}
    for path, numbers in sorted(values.items()):
        array = np.asarray(numbers)
        std = float(array.std(ddof=1)) if array.size > 1 else 0.0
        node = summary
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = {"mean": float(array.mean()), "std": std, "n": int(array.size)}
    return summary
