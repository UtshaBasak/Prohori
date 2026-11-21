# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Domain adaptation for the cross-dataset study (step 30b, pre-registered in ADR-0041).

Every function here works on plain feature matrices: none of them takes a label of the target
dataset, except :func:`few_shot_indices`, which is given the pool's labels on purpose and reads
exactly ``k`` of them. "Per-domain" transforms are fitted on one domain's unlabelled features and
applied to that domain only.

* :func:`signed_log` and :class:`Standardiser`: ``sign(x) log1p(|x|)``, then mean and standard
  deviation of the domain.
* :class:`QuantileMap`: a per-domain uniform quantile transform, optionally per protocol group.
* :func:`coral_matrix`: CORAL (Sun, Feng and Saenko, 2016), the matrix that gives source features
  the target's covariance.
* :func:`importance_weights`: covariate-shift weights from a cross-fitted domain classifier.
* :func:`domain_auc` and :func:`invariant_features`: how well each feature alone tells the
  domains apart, and the features kept by the pre-registered cut-off.
* :func:`few_shot_indices`: k labelled target flows, both classes present.
* :func:`paired_bootstrap`: weighted ROC-AUC and average precision under shared multinomial
  resamples, fast enough for half a million rows.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from prohori.ml import MissingExtraError

try:
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.preprocessing import QuantileTransformer
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.adapt") from exc

#: Pre-registered settings (ADR-0041).
QUANTILES = 1_000
QUANTILE_SUBSAMPLE = 200_000
SMALL_GROUP = 1_000
CORAL_REGULARISATION = 1.0
EIGEN_FLOOR = 1e-6
WEIGHT_CLIP = (0.05, 20.0)
DOMAIN_ITERATIONS = 100
INVARIANCE_CUTOFF = 0.9
MIN_FEATURES = 4
#: Protocol groups for the protocol-aware quantile map: TCP, UDP, everything else.
PROTOCOL_GROUPS = (6.0, 17.0)


def signed_log(x: np.ndarray) -> np.ndarray:
    """``sign(x) * log1p(|x|)``; missing values stay missing."""
    return np.sign(x) * np.log1p(np.abs(x))


def _medians(x: np.ndarray) -> np.ndarray:
    with np.errstate(all="ignore"):
        medians = np.nanmedian(x, axis=0) if len(x) else np.zeros(x.shape[1])
    return np.nan_to_num(medians, nan=0.0)


def impute(x: np.ndarray, medians: np.ndarray) -> np.ndarray:
    """Missing values replaced by the given column medians."""
    return np.where(np.isnan(x), medians, x)


@dataclass
class Standardiser:
    """Signed log, then this domain's mean and standard deviation (median-imputed first)."""

    medians: np.ndarray
    mean: np.ndarray
    scale: np.ndarray

    @classmethod
    def fit(cls, x: np.ndarray) -> "Standardiser":
        logged = signed_log(np.asarray(x, dtype="float64"))
        medians = _medians(logged)
        filled = impute(logged, medians)
        scale = filled.std(axis=0)
        return cls(medians, filled.mean(axis=0), np.where(scale > 0, scale, 1.0))

    def transform(self, x: np.ndarray) -> np.ndarray:
        filled = impute(signed_log(np.asarray(x, dtype="float64")), self.medians)
        return np.asarray((filled - self.mean) / self.scale)


class QuantileMap:
    """A per-domain uniform quantile transform, optionally one per protocol group.

    ``protocol`` is the domain's protocol column (a code, never transformed). A group with fewer
    than ``SMALL_GROUP`` rows uses the all-protocol transform; :meth:`fit_pair` makes that
    decision for both domains together, as pre-registered.
    """

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.medians = np.zeros(0)
        self.overall: QuantileTransformer | None = None
        self.groups: dict[float, QuantileTransformer] = {}

    def _transformer(self, x: np.ndarray) -> QuantileTransformer:
        transformer = QuantileTransformer(
            n_quantiles=min(QUANTILES, len(x)),
            subsample=QUANTILE_SUBSAMPLE,
            random_state=self.seed,
        )
        return transformer.fit(x)

    def fit(
        self, x: np.ndarray, protocol: np.ndarray | None = None, groups: Sequence[float] = ()
    ) -> "QuantileMap":
        x = np.asarray(x, dtype="float64")
        self.medians = _medians(x)
        filled = impute(x, self.medians)
        self.overall = self._transformer(filled)
        self.groups = {}
        if protocol is not None:
            for group in groups:
                rows = _group_rows(protocol, group)
                self.groups[group] = self._transformer(filled[rows])
        return self

    def transform(self, x: np.ndarray, protocol: np.ndarray | None = None) -> np.ndarray:
        if self.overall is None:
            msg = "QuantileMap is not fitted"
            raise ValueError(msg)
        filled = impute(np.asarray(x, dtype="float64"), self.medians)
        out = self.overall.transform(filled)
        if protocol is not None:
            for group, transformer in self.groups.items():
                rows = _group_rows(protocol, group)
                if rows.any():
                    out[rows] = transformer.transform(filled[rows])
        return np.asarray(out)


def _group_rows(protocol: np.ndarray, group: float) -> np.ndarray:
    protocol = np.asarray(protocol, dtype="float64")
    if group in PROTOCOL_GROUPS:
        return np.asarray(protocol == group)
    return ~np.isin(protocol, PROTOCOL_GROUPS)


def shared_groups(source_protocol: np.ndarray, target_protocol: np.ndarray) -> list[float]:
    """Protocol groups with at least ``SMALL_GROUP`` rows in both domains (-1.0: other)."""
    kept = []
    for group in (*PROTOCOL_GROUPS, -1.0):
        if all(
            _group_rows(p, group).sum() >= SMALL_GROUP for p in (source_protocol, target_protocol)
        ):
            kept.append(group)
    return kept


def _power(covariance: np.ndarray, exponent: float) -> np.ndarray:
    values, vectors = np.linalg.eigh(covariance)
    values = np.maximum(values, EIGEN_FLOOR)
    return np.asarray((vectors * values**exponent) @ vectors.T)


def coral_matrix(source: np.ndarray, target: np.ndarray) -> np.ndarray:
    """``Cs^-1/2 Ct^1/2`` with ``C = cov + I``: multiply source rows by it (CORAL)."""
    identity = np.eye(source.shape[1]) * CORAL_REGULARISATION
    cs = np.cov(source, rowvar=False) + identity
    ct = np.cov(target, rowvar=False) + identity
    return np.asarray(_power(cs, -0.5) @ _power(ct, 0.5))


def _domain_sample(source: np.ndarray, target: np.ndarray, seed: int) -> np.ndarray:
    """Pool rows for the domain classifier: as many as the source has, or all of them."""
    if len(target) <= len(source):
        return target
    rng = np.random.default_rng(seed)
    return target[np.sort(rng.choice(len(target), size=len(source), replace=False))]


def domain_probabilities(
    source: np.ndarray, target: np.ndarray, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """Cross-fitted P(target) for every source row and for the sampled pool rows.

    Two folds: each row is scored by the classifier fitted on the other fold, so no row is
    scored by a model that saw it.
    """
    pool = _domain_sample(source, target, seed)
    x = np.vstack([source, pool])
    y = np.r_[np.zeros(len(source)), np.ones(len(pool))]
    fold = np.random.default_rng(seed).permutation(len(x)) % 2
    probability = np.zeros(len(x))
    for k in (0, 1):
        model = HistGradientBoostingClassifier(max_iter=DOMAIN_ITERATIONS, random_state=seed)
        model.fit(x[fold != k], y[fold != k])
        probability[fold == k] = model.predict_proba(x[fold == k])[:, 1]
    return probability[: len(source)], probability[len(source) :]


@dataclass
class Weights:
    """Importance weights and their diagnostics."""

    weights: np.ndarray
    domain_auc: float
    effective_share: float  # (sum w)^2 / sum w^2, over n
    clipped_share: float


def importance_weights(source: np.ndarray, target: np.ndarray, seed: int) -> Weights:
    """Covariate-shift weights for the source rows: ``p / (1 - p)``, clipped, mean 1."""
    p_source, p_pool = domain_probabilities(source, target, seed)
    labels = np.r_[np.zeros(len(p_source)), np.ones(len(p_pool))]
    auc = roc_auc(np.r_[p_source, p_pool], labels)
    with np.errstate(divide="ignore"):
        raw = p_source / (1 - p_source)
    low, high = WEIGHT_CLIP
    clipped = (raw <= low) | (raw >= high)
    weights = np.clip(raw, low, high)
    weights = weights / weights.mean()
    effective = float(weights.sum() ** 2 / (weights**2).sum() / len(weights))
    return Weights(weights, auc, effective, float(clipped.mean()))


def domain_auc(source: np.ndarray, target: np.ndarray) -> np.ndarray:
    """Per feature, ``max(auc, 1 - auc)`` of the raw values as a source-or-target score."""
    found = []
    labels = np.r_[np.zeros(len(source)), np.ones(len(target))]
    for column in range(source.shape[1]):
        values = np.r_[source[:, column], target[:, column]]
        finite = values[np.isfinite(values)]
        lowest = (finite.min() - 1.0) if finite.size else 0.0
        values = np.where(np.isnan(values), lowest, values)  # missing values rank lowest, tied
        auc = roc_auc(values, labels)
        found.append(max(auc, 1 - auc))
    return np.asarray(found)


def invariant_features(aucs: np.ndarray, protocol_column: int | None) -> list[int]:
    """Columns kept: protocol, and every feature with a domain AUC under the cut-off.

    If fewer than ``MIN_FEATURES`` non-protocol features would remain, the ``MIN_FEATURES``
    with the lowest domain AUC are kept instead.
    """
    candidates = [c for c in range(len(aucs)) if c != protocol_column]
    kept = [c for c in candidates if aucs[c] < INVARIANCE_CUTOFF]
    if len(kept) < MIN_FEATURES:
        kept = sorted(candidates, key=lambda c: (aucs[c], c))[:MIN_FEATURES]
    if protocol_column is not None:
        kept.append(protocol_column)
    return sorted(kept)


def few_shot_indices(labels: np.ndarray, k: int, seed: int) -> np.ndarray:
    """``k`` row indices, stratified by label, with at least one of each class.

    Reads the labels of exactly the rows it returns (the class counts aside, which stratifying
    needs).
    """
    labels = np.asarray(labels)
    attacks = np.flatnonzero(labels == 1)
    benign = np.flatnonzero(labels == 0)
    if k < 2 or not len(attacks) or not len(benign):
        msg = "few-shot sampling needs k >= 2 and both classes in the pool"
        raise ValueError(msg)
    n_attack = min(max(round(k * len(attacks) / len(labels)), 1), k - 1)
    rng = np.random.default_rng(seed)
    chosen = np.r_[
        rng.choice(attacks, size=min(n_attack, len(attacks)), replace=False),
        rng.choice(benign, size=min(k - n_attack, len(benign)), replace=False),
    ]
    return np.sort(chosen)


# --------------------------------------------------------------------------- metrics


class _Ranked:
    """Scores sorted once, with tie groups, so weighted metrics cost O(n) per resample."""

    def __init__(self, scores: np.ndarray, labels: np.ndarray) -> None:
        order = np.argsort(np.asarray(scores, dtype="float64"), kind="stable")
        self.order = order
        ranked = np.asarray(scores, dtype="float64")[order]
        self.positive = np.asarray(labels)[order] == 1
        starts = np.r_[0, np.flatnonzero(np.diff(ranked)) + 1]
        self.group = np.zeros(len(ranked), dtype="int64")
        self.group[starts[1:]] = 1
        self.group = np.cumsum(self.group)
        self.groups = len(starts)

    def sums(self, weights: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Positive and negative weight per tie group, groups in ascending score order."""
        w = weights[self.order]
        pos = np.bincount(
            self.group, weights=np.where(self.positive, w, 0.0), minlength=self.groups
        )
        neg = np.bincount(
            self.group, weights=np.where(self.positive, 0.0, w), minlength=self.groups
        )
        return pos, neg

    def both(self, weights: np.ndarray) -> tuple[float, float]:
        """ROC-AUC and average precision from one pass over the tie groups."""
        pos, neg = self.sums(weights)
        return self._auc(pos, neg), self._ap(pos, neg)

    def roc_auc(self, weights: np.ndarray) -> float:
        return self._auc(*self.sums(weights))

    def average_precision(self, weights: np.ndarray) -> float:
        return self._ap(*self.sums(weights))

    @staticmethod
    def _auc(pos: np.ndarray, neg: np.ndarray) -> float:
        total_pos, total_neg = pos.sum(), neg.sum()
        if total_pos == 0 or total_neg == 0:
            return float("nan")
        below = np.cumsum(neg) - neg
        return float((pos * (below + 0.5 * neg)).sum() / (total_pos * total_neg))

    @staticmethod
    def _ap(pos: np.ndarray, neg: np.ndarray) -> float:
        pos, neg = pos[::-1], neg[::-1]  # descending scores
        total_pos = pos.sum()
        if total_pos == 0:
            return float("nan")
        true = np.cumsum(pos)
        alerts = true + np.cumsum(neg)
        with np.errstate(invalid="ignore", divide="ignore"):
            precision = np.where(alerts > 0, true / alerts, 0.0)
        return float((pos / total_pos * precision).sum())


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """ROC-AUC with ties counted half, as scikit-learn does."""
    return _Ranked(scores, labels).roc_auc(np.ones(len(labels)))


def average_precision(scores: np.ndarray, labels: np.ndarray) -> float:
    """Average precision (PR-AUC) as scikit-learn computes it."""
    return _Ranked(scores, labels).average_precision(np.ones(len(labels)))


def paired_bootstrap(
    scores: dict[str, list[np.ndarray]],
    labels: list[np.ndarray],
    seeds: Sequence[int],
    *,
    resamples: int = 1_000,
    baseline: str = "baseline",
) -> dict[str, dict[str, list[float]]]:
    """Bootstrap ROC-AUC, PR-AUC and the ROC-AUC difference to ``baseline``, paired.

    ``scores[arm][i]`` are the arm's target-test scores for seed ``seeds[i]`` and ``labels[i]``
    that seed's target-test labels. Per seed, ``resamples`` multinomial resamples (generator
    seed ``10_000 + seed``) are shared by every arm; each resample's metric is averaged over the
    seeds. Returns, per arm, the resampled means (for percentile intervals).
    """
    found: dict[str, dict[str, list[np.ndarray]]] = {
        arm: {"roc_auc": [], "pr_auc": [], "roc_auc_difference": []} for arm in scores
    }
    for i, seed in enumerate(seeds):
        n = len(labels[i])
        rng = np.random.default_rng(10_000 + seed)
        uniform = np.full(n, 1 / n)
        ranked = {arm: _Ranked(values[i], labels[i]) for arm, values in scores.items()}
        per_arm = {arm: (np.zeros(resamples), np.zeros(resamples)) for arm in scores}
        for r in range(resamples):
            counts = rng.multinomial(n, uniform).astype("float64")
            for arm, rank in ranked.items():
                per_arm[arm][0][r], per_arm[arm][1][r] = rank.both(counts)
        base = per_arm[baseline][0]
        for arm, (auc, ap) in per_arm.items():
            found[arm]["roc_auc"].append(auc)
            found[arm]["pr_auc"].append(ap)
            found[arm]["roc_auc_difference"].append(auc - base)
    return {
        arm: {metric: np.mean(values, axis=0).tolist() for metric, values in metrics.items()}
        for arm, metrics in found.items()
    }


def interval(values: Sequence[float] | np.ndarray, level: float = 0.95) -> tuple[float, float]:
    """The percentile interval of bootstrap values."""
    tail = (1 - level) / 2 * 100
    low, high = np.percentile(np.asarray(values), [tail, 100 - tail])
    return float(low), float(high)
