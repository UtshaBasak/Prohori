# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The two flow detectors, and saving and loading them.

* ``hgb``: scikit-learn's histogram gradient boosting, supervised on attack and benign labels.
  Text features are passed as categorical; codes unseen in training (-1) count as missing.
* ``iforest``: an Isolation Forest fitted on **benign training flows only**, so it learns what
  normal looks like and never sees an attack label. Its score is the negated
  ``score_samples``: higher is more anomalous.

Saved models are **skops** files (since 1.1): zip files of plain data, read without pickle and
only into the types :mod:`prohori.ml.safety` allows. 1.0 models are joblib (pickle) files; they
still load, through an unpickler that resolves only the classes a Prohori model needs. Each
model has a JSON sidecar with its SHA-256 and the library versions it was fitted with:
:func:`load_model` refuses a file whose hash does not match, and a model made with another
major or minor version of scikit-learn, numpy, pandas or Python unless that is explicitly
allowed. The sidecar catches a corrupted or swapped file, not a deliberate attack: whoever can
replace the model can replace the sidecar. A hash checked out of band (``prohori score
--sha256``) catches that too.
"""

import json
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prohori.ml import MissingExtraError

try:
    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.models") from exc

from prohori.ml import safety

MODELS = ("hgb", "iforest")
#: Sidecar formats: /1 for 1.0 joblib models, /2 for skops models.
MODEL_FORMAT = "prohori.ml-model/2"
LEGACY_FORMAT = "prohori.ml-model/1"
SKOPS = ".skops"
JOBLIB = ".joblib"
UNSAFE_PICKLE_WARNING = (
    "Model files are pickles: loading one runs code from it. Only load models you trained "
    "yourself or got from someone you trust, and never one downloaded from an unknown source."
)
MODEL_FILE_NOTE = (
    "Model files are skops files, read without pickle; 1.0 joblib files load only the classes "
    "a Prohori model needs. Still, only use models you trained yourself or got from someone "
    "you trust, and check the SHA-256 with --sha256 when the file came from elsewhere."
)

#: Hyper-parameters, fixed in advance and not tuned on the test split.
PARAMS: dict[str, dict[str, Any]] = {
    "hgb": {
        "max_iter": 300,
        "learning_rate": 0.1,
        "early_stopping": True,
        "validation_fraction": 0.1,
        "n_iter_no_change": 10,
    },
    "iforest": {"n_estimators": 200, "max_samples": "auto"},  # min(256, rows)
}


class ModelFileError(ValueError):
    """A model file is missing its sidecar, does not match it or cannot be loaded safely."""


@dataclass
class Detector:
    """A fitted model with what it needs to score new flows."""

    name: str
    model: Any
    features: list[str]

    def scores(self, x: pd.DataFrame) -> np.ndarray:
        """Higher means more likely an attack."""
        if self.name == "hgb":
            return np.asarray(self.model.predict_proba(x)[:, 1], dtype="float64")
        return -np.asarray(self.model.score_samples(x), dtype="float64")


def fit(name: str, x: pd.DataFrame, y: pd.Series, *, seed: int, categorical: list[str]) -> Detector:
    """Fit detector ``name`` on the training features ``x`` and labels ``y``."""
    if name == "hgb":
        mask = [column in categorical for column in x.columns]
        model: Any = HistGradientBoostingClassifier(
            **PARAMS["hgb"], categorical_features=mask if any(mask) else None, random_state=seed
        )
        model.fit(x, y.to_numpy())
    elif name == "iforest":
        model = IsolationForest(**PARAMS["iforest"], random_state=seed)
        model.fit(x[y.to_numpy() == 0])
    else:
        msg = f"unknown model {name!r}; known: {', '.join(MODELS)}"
        raise ValueError(msg)
    return Detector(name=name, model=model, features=list(x.columns))


def sidecar_path(path: Path) -> Path:
    """``m.skops`` -> ``m.skops.json``; a 1.0 ``m.joblib`` keeps its ``m.json``."""
    if path.suffix == JOBLIB:
        return path.with_suffix(".json")
    return path.with_name(path.name + ".json")


def _plain(bundle: dict[str, Any]) -> dict[str, Any]:
    """The bundle as plain data for skops: the detector becomes a dict."""
    detector = bundle.get("detector")
    if isinstance(detector, Detector):
        bundle = {
            **bundle,
            "detector": {
                "name": detector.name,
                "model": detector.model,
                "features": detector.features,
            },
        }
    return bundle


def _restored(bundle: dict[str, Any]) -> dict[str, Any]:
    detector = bundle.get("detector")
    if isinstance(detector, dict):
        bundle = {**bundle, "detector": Detector(**detector)}
    return bundle


def save_model(path: Path, bundle: dict[str, Any], meta: dict[str, Any]) -> Path:
    """Write ``bundle`` (skops, or joblib for a ``.joblib`` path) and its JSON sidecar.

    Saving ``m.skops`` removes a 1.0 ``m.joblib`` and its sidecar, so a retrained model never
    sits next to the one it replaces.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == JOBLIB:
        joblib.dump(bundle, path, compress=3)
        sidecar = {**meta, "format": LEGACY_FORMAT, "warning": UNSAFE_PICKLE_WARNING}
    else:
        path.write_bytes(safety.dump_skops(_plain(bundle)))
        sidecar = {**meta, "format": MODEL_FORMAT, "file_format": "skops"}
        old = path.with_suffix(JOBLIB)
        old.unlink(missing_ok=True)
        sidecar_path(old).unlink(missing_ok=True)
    sidecar["versions"] = safety.library_versions()
    sidecar["sha256"] = safety.sha256_hex(path.read_bytes())
    sidecar_path(path).write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    return path


def load_model(
    path: Path,
    *,
    sha256: str | None = None,
    allow_version_mismatch: bool = False,
    warn: Callable[[str], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a model saved by :func:`save_model`, after every check in :mod:`prohori.ml.safety`.

    In order, before any byte of the model is read as objects: the sidecar exists and has a
    known format; the file's SHA-256 matches the sidecar and ``sha256`` when given; the library
    versions match (major and minor) unless ``allow_version_mismatch``, which only warns. Then
    the file is read into allowlisted types only. ``warn`` receives the warnings (default:
    :func:`warnings.warn`).
    """
    say = warn or (lambda message: warnings.warn(message, stacklevel=3))
    sidecar = sidecar_path(path)
    if not sidecar.is_file():
        msg = f"{path} has no {sidecar.name}; refusing to load an unknown model file"
        raise ModelFileError(msg)
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    expected = {SKOPS: MODEL_FORMAT, JOBLIB: LEGACY_FORMAT}.get(path.suffix)
    data = path.read_bytes()  # read once: the bytes checked are the bytes loaded
    digest = safety.sha256_hex(data)
    if expected is None or meta.get("format") != expected or meta.get("sha256") != digest:
        msg = f"{path} does not match {sidecar.name}; refusing to load it"
        raise ModelFileError(msg)
    if sha256 is not None and sha256.strip().lower() != digest:
        msg = f"{path} has SHA-256 {digest}, not the one given; refusing to load it"
        raise ModelFileError(msg)
    recorded, unknown = safety.recorded_versions(meta)
    mismatches = safety.version_mismatches(recorded)
    if mismatches:
        detail = "; ".join(mismatches)
        if not allow_version_mismatch:
            msg = (
                f"{path} was made with other library versions ({detail}); retrain it, or pass "
                "--allow-version-mismatch to load it anyway"
            )
            raise ModelFileError(msg)
        say(f"loading {path.name} despite other library versions: {detail}")
    if unknown and path.suffix == JOBLIB:
        say(f"{path.name} did not record the versions of {', '.join(unknown)}; retrain it")
    try:
        load = safety.load_skops if path.suffix == SKOPS else safety.load_joblib
        bundle = load(data)
    except safety.UnsafeModelError as exc:
        raise ModelFileError(f"{path}: {exc}") from None
    if not isinstance(bundle, dict):
        msg = f"{path} does not hold a Prohori model"
        raise ModelFileError(msg)
    return _restored(bundle), meta
