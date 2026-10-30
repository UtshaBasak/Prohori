"""Anomaly detectors over per-IP windows, and the alerts they raise.

Every detector compares a log's windows with each other: "unusual" means unusual for this log.
Nothing is trained in advance and nothing is saved, so no model file is ever loaded.

* ``zscore``: robust z-scores. For each feature, the median and the median absolute deviation
  (MAD) over all windows of the log; a window's score is its largest one-sided z, so only
  higher-than-usual values count. The scale never drops below a floor per feature
  (:data:`SCALE_FLOORS`): in most logs the usual number of failures is 0 with a MAD of 0, and
  without a floor one failed sign-in would be infinitely unusual.
* ``threshold``: fixed limits on a few features, the simplest baseline (evaluation only).
* ``iforest``: an Isolation Forest over the log-scaled features (needs the ``ml`` extra).

A log needs :data:`MIN_WINDOWS` windows before anything is judged unusual. The cut-offs
(:data:`Z_THRESHOLD`, :data:`IFOREST_THRESHOLD`) were chosen on the simulator's default variants
and frozen before the held-out variants were scored (ADR-0022).
"""

import math
import statistics
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from prohori.ml.features import FEATURES, Window
from prohori.schema import Alert, DetectorKind, Severity

ZSCORE_ID = "PRH-ML-ZSCORE"
THRESHOLD_ID = "PRH-ML-THRESHOLD"
IFOREST_ID = "PRH-ML-IFOREST"
#: Detector name -> alert detector id.
DETECTOR_IDS = {"zscore": ZSCORE_ID, "threshold": THRESHOLD_ID, "iforest": IFOREST_ID}
#: Detectors ``prohori detect --models`` runs; the threshold baseline is for evaluation only.
CLI_DETECTORS = ("zscore", "iforest")

MIN_WINDOWS = 20
#: Converts a MAD to the standard deviation of a normal distribution.
MAD_TO_SD = 1.4826
#: Smallest scale per feature: one unit for counts, a tenth for ratios, half a bit of entropy.
SCALE_FLOORS = {
    "events": 1.0,
    "rate_per_minute": 1.0,
    "auth_attempts": 1.0,
    "auth_failures": 1.0,
    "failure_ratio": 0.1,
    "distinct_users": 1.0,
    "http_requests": 1.0,
    "distinct_paths": 1.0,
    "http_4xx_ratio": 0.1,
    "path_entropy": 0.5,
    "distinct_user_agents": 1.0,
    "new_client_ratio": 0.1,
    "night_ratio": 0.1,
}
Z_THRESHOLD = 12.0
IFOREST_THRESHOLD = 0.8
#: Fixed limits of the threshold baseline.
THRESHOLDS = {
    "auth_failures": 10.0,
    "distinct_users": 5.0,
    "distinct_paths": 30.0,
    "rate_per_minute": 30.0,
}
IFOREST_TREES = 200

TITLES = {
    ZSCORE_ID: "Unusual activity from one source IP (robust z-score)",
    THRESHOLD_ID: "Activity over fixed limits from one source IP",
    IFOREST_ID: "Unusual activity from one source IP (Isolation Forest)",
}


@dataclass(frozen=True)
class Scored:
    """A window with its anomaly score and the features that explain it."""

    window: Window
    score: float
    reasons: tuple[tuple[str, float, float], ...]  # (feature, value, usual value)


def _scale(values: Sequence[float], feature: str) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    return median, max(mad * MAD_TO_SD, SCALE_FLOORS[feature])


def zscore(windows: Sequence[Window]) -> list[Scored]:
    """Robust one-sided z-scores; constant features are skipped."""
    if len(windows) < MIN_WINDOWS:
        return []
    columns = {f: [w.features[f] for w in windows] for f in FEATURES}
    stats = {f: _scale(v, f) for f, v in columns.items() if max(v) > min(v)}
    scored = []
    for window in windows:
        zs = []
        for feature, (median, scale) in stats.items():
            value = window.features[feature]
            zs.append(((value - median) / scale, feature, value, median))
        zs.sort(reverse=True)
        top = tuple((f, v, m) for z, f, v, m in zs[:3] if z > 0)
        scored.append(Scored(window, max((z for z, *_ in zs), default=0.0), top))
    return scored


def threshold(windows: Sequence[Window]) -> list[Scored]:
    """Number of fixed limits a window reaches."""
    scored = []
    for window in windows:
        over = tuple(
            (f, window.features[f], limit)
            for f, limit in THRESHOLDS.items()
            if window.features[f] >= limit
        )
        scored.append(Scored(window, float(len(over)), over))
    return scored


def iforest(windows: Sequence[Window], *, seed: int = 0) -> list[Scored]:
    """Isolation Forest anomaly scores in (0, 1]; about 0.5 is ordinary, near 1 is isolated."""
    if len(windows) < MIN_WINDOWS:
        return []
    from prohori.ml import MissingExtraError

    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise MissingExtraError("the iforest detector") from exc
    x = np.log1p(np.array([[w.features[f] for f in FEATURES] for w in windows]))
    model = IsolationForest(n_estimators=IFOREST_TREES, random_state=seed).fit(x)
    scores = -model.score_samples(x)
    medians = np.median(x, axis=0)
    scored = []
    for window, score, row in zip(windows, scores, x, strict=True):
        # Explain with the features furthest above the log's median (on the log scale).
        order = np.argsort(medians - row)[:3]
        reasons = tuple(
            (FEATURES[i], window.features[FEATURES[i]], float(np.expm1(medians[i])))
            for i in order
            if row[i] > medians[i]
        )
        scored.append(Scored(window, float(score), reasons))
    return scored


DETECTORS: dict[str, tuple[Callable[[Sequence[Window]], list[Scored]], float]] = {
    "zscore": (zscore, Z_THRESHOLD),
    "threshold": (threshold, 1.0),
    "iforest": (iforest, IFOREST_THRESHOLD),
}


def explanation(scored: Scored, detector: str) -> str:
    """Feature names and numbers only: nothing a log controls, so redaction never has to act."""
    usual = "limit" if detector == "threshold" else "usual"
    parts = [f"{f} {_number(v)} ({usual} {_number(m)})" for f, v, m in scored.reasons]
    name = {"zscore": "z", "iforest": "anomaly score", "threshold": "limits reached"}[detector]
    return f"{name} {_number(scored.score)}" + (": " + ", ".join(parts) if parts else "")


def _number(value: float) -> str:
    return f"{value:.0f}" if float(value).is_integer() else f"{value:.2f}"


def to_alert(scored: Scored, detector: str) -> Alert:
    detector_id = DETECTOR_IDS[detector]
    window = scored.window
    if detector == "zscore":
        points = min(100.0, scored.score * 5)
    elif detector == "iforest":
        points = min(100.0, scored.score * 100)
    else:
        points = min(100.0, scored.score * 25)
    return Alert(
        detector_id=detector_id,
        detector_kind=DetectorKind.MODEL,
        title=TITLES[detector_id],
        severity=Severity.LOW,
        score=round(points, 1),
        event_ids=window.event_ids,
        entities={"source.ip": window.ip},
        first_seen=window.first_seen,
        last_seen=window.last_seen,
        explanation=explanation(scored, detector),
    )


def flagged(scored: Sequence[Scored], cutoff: float) -> list[Scored]:
    return [s for s in scored if s.score >= cutoff and not math.isnan(s.score)]


def detect(
    windows: Sequence[Window],
    detectors: Sequence[str] = CLI_DETECTORS,
    *,
    seed: int = 0,
    cutoffs: dict[str, float] | None = None,
) -> list[Alert]:
    """Alerts from each detector for the windows over its cut-off, in time order."""
    alerts: list[Alert] = []
    for name in detectors:
        if name not in DETECTORS:
            msg = f"unknown detector {name!r}; known: {', '.join(DETECTORS)}"
            raise ValueError(msg)
        function, cutoff = DETECTORS[name]
        scored = iforest(windows, seed=seed) if name == "iforest" else function(windows)
        limit = (cutoffs or {}).get(name, cutoff)
        alerts.extend(to_alert(s, name) for s in flagged(scored, limit))
    return sorted(alerts, key=lambda a: (a.first_seen, a.detector_id, a.id))
