"""The two flow detectors, and saving and loading them.

* ``hgb``: scikit-learn's histogram gradient boosting, supervised on attack and benign labels.
  Text features are passed as categorical; codes unseen in training (-1) count as missing.
* ``iforest``: an Isolation Forest fitted on **benign training flows only**, so it learns what
  normal looks like and never sees an attack label. Its score is the negated
  ``score_samples``: higher is more anomalous.

Saved models are joblib (pickle) files. **Loading a pickle runs code from the file**: load only
models you trained yourself. Each model has a JSON sidecar with its SHA-256, and
:func:`load_model` refuses a file whose hash does not match it. That catches a corrupted or
swapped file, not a deliberate attack: whoever can replace the model can replace the sidecar.
"""

import hashlib
import json
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

MODELS = ("hgb", "iforest")
MODEL_FORMAT = "prohori.ml-model/1"
UNSAFE_PICKLE_WARNING = (
    "Model files are pickles: loading one runs code from it. Only load models you trained "
    "yourself or got from someone you trust, and never one downloaded from an unknown source."
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
    """A model file is missing its sidecar or does not match it."""


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_model(path: Path, bundle: dict[str, Any], meta: dict[str, Any]) -> Path:
    """Write ``bundle`` with joblib and a ``.json`` sidecar holding ``meta`` and the file hash."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    sidecar = {
        "format": MODEL_FORMAT,
        **meta,
        "sha256": _sha256(path),
        "warning": UNSAFE_PICKLE_WARNING,
    }
    path.with_suffix(".json").write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    return path


def load_model(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a model saved by :func:`save_model` after checking its hash. See the warning above."""
    sidecar = path.with_suffix(".json")
    if not sidecar.is_file():
        msg = f"{path} has no {sidecar.name}; refusing to load an unknown pickle"
        raise ModelFileError(msg)
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    if meta.get("format") != MODEL_FORMAT or meta.get("sha256") != _sha256(path):
        msg = f"{path} does not match {sidecar.name}; refusing to load it"
        raise ModelFileError(msg)
    bundle: dict[str, Any] = joblib.load(path)  # hash checked above; see UNSAFE_PICKLE_WARNING
    return bundle, meta
