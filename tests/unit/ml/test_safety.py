# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""prohori.ml.safety: allowlisted loading, scans and library versions."""

import io
import pickle
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pytest
from joblib import numpy_pickle
from sklearn.ensemble import IsolationForest

from prohori.ml import safety
from prohori.ml.models import Detector


class Payload:
    """Unpickling this would create a file: a stand-in for any code a pickle can run."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self) -> tuple[object, tuple[str, str]]:
        return (open, (str(self.marker), "w"))


class Unknown:
    """A type no allowlist names."""

    def __init__(self) -> None:
        self.value = 1


def _joblib_bytes(value: object) -> bytes:
    buffer = io.BytesIO()
    joblib.dump(value, buffer, compress=3)
    return buffer.getvalue()


def test_a_malicious_joblib_file_is_refused_before_it_runs(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    data = _joblib_bytes({"detector": Payload(marker)})
    with pytest.raises(safety.UnsafeModelError, match=r"asks for \w+\.open, which"):
        safety.load_joblib(data)
    scan = safety.scan_joblib(data)
    assert len(scan.refused) == 1
    assert scan.refused[0].endswith(".open")  # _io.open
    assert scan.refused[0] in scan.globals
    assert not marker.exists()  # neither loading nor scanning ran it


def test_a_payload_inside_an_object_array_is_refused_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """joblib stores object arrays as a nested pickle; it goes through the allowlist as well.

    joblib before 1.6 read that nested pickle with a plain ``pickle.load``; that behaviour is
    put back here to show the allowlist does not depend on joblib's own fix.
    """

    def unguarded(self: object, unpickler: Any, ensure_native_byte_order: bool) -> Any:
        del self, ensure_native_byte_order
        return pickle.load(unpickler.file_handle)  # noqa: S301 - the old, unsafe behaviour

    monkeypatch.setattr(numpy_pickle.NumpyArrayWrapper, "read_array", unguarded)
    marker = tmp_path / "ran"
    payload = np.empty(1, dtype=object)
    payload[0] = Payload(marker)
    data = _joblib_bytes({"categories": payload})
    with pytest.raises(safety.UnsafeModelError, match=r"\.open, which"):
        safety.load_joblib(data)
    scan = safety.scan_joblib(data)
    assert len(scan.refused) == 1
    assert scan.refused[0].endswith(".open")
    assert not marker.exists()
    # Object arrays of plain strings (an encoder's categories) need no global and still load.
    names = np.array(["tcp", "udp", "-"], dtype=object)
    assert safety.load_joblib(_joblib_bytes({"categories": names}))["categories"].tolist() == [
        "tcp",
        "udp",
        "-",
    ]


def test_a_prohori_joblib_model_loads_through_the_allowlist() -> None:
    """Guards the joblib internals the restricted unpickler relies on."""
    x = pd.DataFrame(np.random.default_rng(0).normal(size=(64, 3)), columns=["a", "b", "c"])
    model = IsolationForest(n_estimators=5, random_state=0).fit(x)
    detector = Detector(name="iforest", model=model, features=["a", "b", "c"])
    data = _joblib_bytes({"detector": detector, "thresholds": {"fpr_0.01": 0.5}})
    loaded = safety.load_joblib(data)
    assert np.allclose(loaded["detector"].scores(x), detector.scores(x))
    scan = safety.scan_joblib(data)
    assert scan.complete
    assert scan.refused == []
    assert set(scan.globals) <= safety.JOBLIB_GLOBALS


def test_an_unreadable_file_is_reported_by_the_scan() -> None:
    scan = safety.scan_joblib(b"not a model")
    assert not scan.complete
    assert scan.error


def test_skops_refuses_types_outside_the_allowlist() -> None:
    data = safety.dump_skops({"x": Unknown()})
    refused = safety.untrusted_skops_types(data)
    assert refused == [f"{__name__}.Unknown"]
    with pytest.raises(safety.UnsafeModelError, match="does not trust"):
        safety.load_skops(data)
    assert safety.load_skops(safety.dump_skops({"x": [1, 2]})) == {"x": [1, 2]}


def test_versions_compare_major_and_minor_only() -> None:
    here = {"python": "3.13.1", "scikit-learn": "1.9.1", "numpy": "2.5.4", "pandas": "3.1.0"}
    same = {**here, "scikit-learn": "1.9.7", "python": "3.13.9"}
    assert safety.version_mismatches(same, here) == []
    other = {**here, "numpy": "2.6.0", "pandas": "4.0.0"}
    assert safety.version_mismatches(other, here) == [
        "numpy 2.6.0 (model) vs 2.5.4 (here)",
        "pandas 4.0.0 (model) vs 3.1.0 (here)",
    ]
    assert safety.version_mismatches({}, here) == []
    assert set(safety.library_versions()) == set(safety.LIBRARIES)


def test_legacy_sidecars_record_scikit_learn_only() -> None:
    versions, unknown = safety.recorded_versions({"scikit_learn_version": "1.9.1"})
    assert versions == {"scikit-learn": "1.9.1"}
    assert unknown == ["python", "numpy", "pandas"]
    versions, unknown = safety.recorded_versions({"versions": {"python": "3.13.1"}})
    assert (versions, unknown) == ({"python": "3.13.1"}, ["scikit-learn", "numpy", "pandas"])
