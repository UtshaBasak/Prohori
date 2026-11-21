# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""prohori.ml.adapt and the cross-dataset study: transforms, metrics and leakage (ADR-0041)."""

import json
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import average_precision_score, roc_auc_score

from prohori.ml import adapt
from scripts import cross_dataset_study as study

RNG = np.random.default_rng(0)


def _domain(n: int, shift: float, seed: int) -> study.Domain:
    rng = np.random.default_rng(seed)

    def part(rows: int) -> tuple[np.ndarray, np.ndarray]:
        y = (rng.random(rows) < 0.3).astype("int64")
        x = rng.lognormal(mean=1 + shift, sigma=1, size=(rows, 12)) + y[:, None] * 2.0
        x[:, study.PROTOCOL] = rng.choice([6.0, 17.0, 1.0], size=rows, p=[0.6, 0.3, 0.1])
        x[rng.random(rows) < 0.02, 9] = np.nan  # a rate over a zero duration
        return x, y

    return study.Domain(*part(n), *part(n // 4), *part(n // 2))


# --------------------------------------------------------------------------- metrics


@pytest.mark.parametrize("ties", [False, True])
def test_metrics_match_scikit_learn_with_and_without_weights(ties: bool) -> None:
    labels = (RNG.random(3000) < 0.2).astype(int)
    scores = RNG.random(3000) + labels * 0.3
    if ties:
        scores = np.round(scores, 1)
    weights = RNG.integers(0, 4, size=3000).astype(float)
    ranked = adapt._Ranked(scores, labels)
    assert ranked.roc_auc(weights) == pytest.approx(
        roc_auc_score(labels, scores, sample_weight=weights)
    )
    assert ranked.average_precision(weights) == pytest.approx(
        average_precision_score(labels, scores, sample_weight=weights)
    )
    assert adapt.roc_auc(scores, labels) == pytest.approx(roc_auc_score(labels, scores))


def test_paired_bootstrap_is_seeded_and_paired() -> None:
    labels = [(RNG.random(500) < 0.3).astype(int) for _ in range(2)]
    base = [RNG.random(500) + y * 0.2 for y in labels]
    scores = {"baseline": base, "same": [b.copy() for b in base]}
    first = adapt.paired_bootstrap(scores, labels, [0, 1], resamples=30)
    again = adapt.paired_bootstrap(scores, labels, [0, 1], resamples=30)
    assert first == again
    assert first["same"]["roc_auc_difference"] == [0.0] * 30  # paired: identical scores
    low, high = adapt.interval(first["baseline"]["roc_auc"])
    assert low < roc_auc_score(labels[0], base[0]) + 0.1
    assert low <= high


# --------------------------------------------------------------------------- transforms


def test_standardiser_and_quantile_map_use_their_own_domain() -> None:
    x = RNG.lognormal(size=(2000, 3))
    x[0, 1] = np.nan
    standardised = adapt.Standardiser.fit(x).transform(x)
    assert not np.isnan(standardised).any()
    assert np.allclose(standardised.mean(axis=0), 0, atol=1e-9)
    protocol = RNG.choice([6.0, 17.0, 1.0], size=2000)
    mapped = adapt.QuantileMap(0).fit(x, protocol, [6.0]).transform(x, protocol)
    assert mapped.min() >= 0
    assert mapped.max() <= 1
    tcp = protocol == 6.0
    # The TCP rows got their own map: their values are spread over [0, 1] on their own.
    assert mapped[tcp, 0].max() > 0.99
    assert mapped[tcp, 0].min() < 0.01
    with pytest.raises(ValueError, match="not fitted"):
        adapt.QuantileMap(0).transform(x)


def test_small_protocol_groups_share_the_overall_map() -> None:
    many = np.full(5000, 6.0)
    few = np.r_[np.full(4500, 6.0), np.full(500, 17.0)]
    assert adapt.shared_groups(many, few) == [6.0]


def test_coral_gives_the_source_the_target_covariance() -> None:
    source = RNG.normal(size=(20000, 3)) @ np.diag([1.0, 2.0, 0.5])
    mix = np.array([[1.0, 0.8, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 3.0]])
    target = RNG.normal(size=(20000, 3)) @ mix
    matrix = adapt.coral_matrix(source, target)
    identity = np.eye(3)
    # With the pre-registered regulariser, A' (Cs + I) A = Ct + I exactly.
    recoloured = matrix.T @ (np.cov(source, rowvar=False) + identity) @ matrix
    assert np.allclose(recoloured, np.cov(target, rowvar=False) + identity)
    assert not np.allclose(np.cov(source, rowvar=False), np.cov(target, rowvar=False), atol=0.5)


def test_importance_weights_favour_target_like_rows() -> None:
    source = RNG.normal(size=(4000, 2))
    target = RNG.normal(loc=1.0, size=(4000, 2))
    weights = adapt.importance_weights(source, target, seed=0)
    assert weights.weights.mean() == pytest.approx(1.0)
    near = source[:, 0] > 1
    assert weights.weights[near].mean() > weights.weights[~near].mean()
    assert 0.5 < weights.domain_auc < 1
    assert 0 < weights.effective_share <= 1
    assert 0 <= weights.clipped_share <= 1


def test_invariant_selection_and_its_fallback() -> None:
    aucs = np.array([0.6, 0.95, 0.7, 0.99, 0.5, 0.8, 0.65])
    assert adapt.invariant_features(aucs, protocol_column=4) == [0, 2, 4, 5, 6]
    # Three would remain: the four lowest are kept instead.
    aucs[5] = 0.91
    assert adapt.invariant_features(aucs, protocol_column=4) == [0, 2, 4, 5, 6]
    aucs[5] = 0.99
    assert adapt.invariant_features(aucs, protocol_column=4) == [0, 1, 2, 4, 6]
    assert adapt.invariant_features(np.full(6, 0.99), protocol_column=None) == [0, 1, 2, 3]
    source, target = RNG.normal(size=(500, 2)), RNG.normal(size=(500, 2))
    target[:, 1] += 10
    found = adapt.domain_auc(source, target)
    assert found[0] < 0.6
    assert found[1] == 1.0


def test_few_shot_draws_have_both_classes() -> None:
    labels = np.r_[np.ones(30), np.zeros(970)].astype(int)
    for seed in range(20):
        chosen = adapt.few_shot_indices(labels, 10, seed)
        assert len(chosen) == 10
        assert set(labels[chosen]) == {0, 1}
    with pytest.raises(ValueError, match="both classes"):
        adapt.few_shot_indices(np.zeros(50, dtype=int), 10, 0)


# --------------------------------------------------------------------------- leakage


def test_pool_labels_reach_only_the_few_shot_and_reference_arms() -> None:
    source, target = _domain(3000, 0.0, 1), _domain(3000, 0.7, 2)
    shuffled = study.Domain(**{**target.__dict__, "train_y": np.roll(target.train_y, 7)})
    for arm in ("baseline", *study.METHODS):
        prepared = study.inputs(arm, source, target, 0, {})
        again = study.inputs(arm, source, shuffled, 0, {})
        for name in ("train", "validation", "test"):
            assert np.array_equal(getattr(prepared, name), getattr(again, name)), (arm, name)
        if prepared.weight is not None:
            assert np.array_equal(prepared.weight, again.weight)
    # The few-shot arm does read pool labels.
    one = study.few_shot_inputs(source, target, 50, 0).train_y
    two = study.few_shot_inputs(source, shuffled, 50, 0).train_y
    assert one is not None
    assert two is not None
    assert not np.array_equal(one, two)


def test_target_test_features_never_change_what_is_fitted() -> None:
    source, target = _domain(3000, 0.0, 1), _domain(3000, 0.7, 2)
    moved = study.Domain(**{**target.__dict__, "test": target.test * 5 + 3})
    for arm in ("baseline", *study.METHODS):
        diag_a: dict[str, object] = {}
        diag_b: dict[str, object] = {}
        prepared = study.inputs(arm, source, target, 0, diag_a)
        again = study.inputs(arm, source, moved, 0, diag_b)
        assert np.array_equal(prepared.train, again.train), arm
        assert np.array_equal(prepared.validation, again.validation), arm
        assert diag_a == diag_b, arm


def test_few_shot_reads_exactly_k_target_rows() -> None:
    source, target = _domain(3000, 0.0, 1), _domain(3000, 0.7, 2)
    prepared = study.few_shot_inputs(source, target, 10, 0)
    assert prepared.train_y is not None
    assert len(prepared.train) == len(source.train) + 10
    assert prepared.weight is not None
    added = prepared.weight[len(source.train) :]
    assert added.sum() == pytest.approx(0.1 * len(source.train))


def test_study_on_synthetic_domains_is_reproducible() -> None:
    source, target = _domain(2000, 0.0, 1), _domain(2000, 0.7, 2)
    found, scores, diag = study.run_direction(source, target, 0, lambda _: None)
    again, _, _ = study.run_direction(source, target, 0, lambda _: None)
    assert found == again
    assert set(found) == set(study.ARMS)
    assert len(scores["few-shot-10"]) == study.DRAWS
    assert 0 <= diag["pool_attack_share"] <= 1
    assert "invariant_dropped" in diag
    assert "effective_sample_share" in diag
    summary = study.summarise([found], [scores], [target.test_y], [0], resamples=10)
    assert summary["baseline"]["roc_auc_difference"] == 0
    assert summary["target-reference"]["mean"]["roc_auc"] > 0.5


def test_committed_results_follow_the_preregistration() -> None:
    path = Path(__file__).resolve().parents[3] / "results" / "ml_adapt.json"
    results = json.loads(path.read_text(encoding="utf-8"))
    assert results["format"] == study.RESULTS_FORMAT
    assert results["seeds"] == [0, 1, 2]
    assert results["sample"] is None
    assert results["resamples"] == study.RESAMPLES
    assert results["arms"] == list(study.ARMS)
    assert "timing" not in json.dumps(results)
    for direction in results["directions"].values():
        assert set(direction["arms"]) == set(study.ARMS)
