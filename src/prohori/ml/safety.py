# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Checks that run before a model file is turned back into objects.

A model file is only as safe as the code that reads it. These checks are kept apart from the
models so that other commands can reuse them (step 63's ``prohori model scan`` builds on them):

* **Hashes.** :func:`sha256_hex` and the sidecar check in :mod:`prohori.ml.models`; a hash
  given out of band (``prohori score --sha256``) is the only check an attacker who can replace
  both the model and its sidecar cannot pass.
* **Library versions.** :func:`library_versions` is recorded when a model is saved and
  :func:`version_mismatches` compares it with the running versions: a model fitted with
  another major or minor version of scikit-learn, numpy, pandas or Python may load and then
  score differently without any error.
* **skops files** (the default since 1.1) are zip files of plain data, read without pickle.
  :func:`untrusted_skops_types` lists the types a file asks for beyond :data:`SKOPS_TYPES`, and
  :func:`load_skops` refuses such a file instead of trusting whatever it declares.
* **joblib files** (1.0 models) are pickles. :func:`load_joblib` reads them with an unpickler
  that resolves only the classes and functions in :data:`JOBLIB_GLOBALS`, so a file that asks
  for anything else (``os.system``, ``builtins.eval`` and the like) is refused before it can
  run. :func:`scan_joblib` lists what a file asks for without loading what it is refused.
"""

import hashlib
import io
import pickle  # only to restrict joblib's unpickler; nothing is loaded without the allowlist
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

from prohori.ml import MissingExtraError

try:
    from joblib import numpy_pickle
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise MissingExtraError("prohori.ml.safety") from exc

#: Libraries whose versions are recorded with a model and compared when it is loaded.
LIBRARIES = ("python", "scikit-learn", "numpy", "pandas")

#: Every class or function a Prohori joblib model needs, as ``module.name``; measured on the
#: 1.0 models of both datasets and both detectors.
JOBLIB_GLOBALS = frozenset(
    {
        "builtins.slice",
        "functools.partial",
        "joblib.numpy_pickle.NumpyArrayWrapper",
        "numpy.dtype",
        "numpy.float64",
        "numpy.ndarray",
        "numpy._core.multiarray._reconstruct",
        "numpy._core.multiarray.scalar",
        "numpy.random._pcg64.PCG64",
        "numpy.random._pickle.__bit_generator_ctor",
        "numpy.random._pickle.__generator_ctor",
        "numpy.random.bit_generator.SeedSequence",
        "numpy.random.bit_generator.__pyx_unpickle_SeedSequence",
        "prohori.ml.models.Detector",
        "sklearn._loss._loss.CyHalfBinomialLoss",
        "sklearn._loss.link.Interval",
        "sklearn._loss.link.LogitLink",
        "sklearn._loss.loss.HalfBinomialLoss",
        "sklearn.compose._column_transformer.ColumnTransformer",
        "sklearn.ensemble._hist_gradient_boosting.binning._BinMapper",
        "sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingClassifier",
        "sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor",
        "sklearn.ensemble._iforest.IsolationForest",
        "sklearn.impute._base.SimpleImputer",
        "sklearn.preprocessing._encoders.OrdinalEncoder",
        "sklearn.preprocessing._function_transformer.FunctionTransformer",
        "sklearn.preprocessing._label.LabelEncoder",
        "sklearn.tree._classes.ExtraTreeRegressor",
        "sklearn.tree._tree.Tree",
        "sklearn.utils.validation.check_array",
    }
)

#: Types a Prohori skops model may ask for beyond those skops trusts by itself; measured on
#: the models of both datasets and both detectors.
SKOPS_TYPES = frozenset(
    {
        "functools.partial",
        "numpy.dtype",
        "sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor",
        "sklearn.tree._tree.Tree",
        "sklearn.utils.validation.check_array",
    }
)


class UnsafeModelError(ValueError):
    """A model file asks for code outside the allowlist, or was made with other libraries."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def library_versions() -> dict[str, str]:
    """The running versions of :data:`LIBRARIES`."""
    found = {"python": ".".join(str(part) for part in sys.version_info[:3])}
    for name in LIBRARIES[1:]:
        try:
            found[name] = metadata.version(name)
        except metadata.PackageNotFoundError:  # pragma: no cover - the ml extra has them all
            found[name] = "not installed"
    return found


def _major_minor(version: str) -> tuple[str, ...]:
    return tuple(version.split(".")[:2])


def version_mismatches(
    recorded: dict[str, str], current: dict[str, str] | None = None
) -> list[str]:
    """``"scikit-learn 1.9.1 (model) vs 1.10.0 (here)"`` for each major or minor difference.

    Libraries the model did not record are not compared; see :func:`recorded_versions`.
    """
    current = current or library_versions()
    found = []
    for name in LIBRARIES:
        known = name in recorded and name in current
        if known and _major_minor(recorded[name]) != _major_minor(current[name]):
            found.append(f"{name} {recorded[name]} (model) vs {current[name]} (here)")
    return found


def recorded_versions(meta: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """The versions a sidecar recorded, and the libraries it did not record.

    1.0 sidecars recorded scikit-learn only; the other libraries are then reported as unknown
    rather than refused, so those models keep loading.
    """
    versions = dict(meta.get("versions") or {})
    if not versions and meta.get("scikit_learn_version"):
        versions["scikit-learn"] = str(meta["scikit_learn_version"])
    return versions, [name for name in LIBRARIES if name not in versions]


# --------------------------------------------------------------------------- skops


def untrusted_skops_types(data: bytes) -> list[str]:
    """Types the skops file asks for that neither skops nor :data:`SKOPS_TYPES` trusts."""
    from skops.io import get_untrusted_types

    return sorted(set(get_untrusted_types(data=data)) - SKOPS_TYPES)


def load_skops(data: bytes) -> Any:  # noqa: ANN401 - whatever the file holds
    """Read a skops file, trusting only :data:`SKOPS_TYPES` beyond skops's own defaults."""
    from skops.io import get_untrusted_types, loads

    refused = untrusted_skops_types(data)
    if refused:
        msg = f"the model file asks for types Prohori does not trust: {', '.join(refused)}"
        raise UnsafeModelError(msg)
    return loads(data, trusted=sorted(set(get_untrusted_types(data=data))))


def dump_skops(value: Any) -> bytes:  # noqa: ANN401 - any skops-serialisable value
    import zipfile

    from skops.io import dumps

    return bytes(dumps(value, compression=zipfile.ZIP_DEFLATED, compresslevel=6))


# --------------------------------------------------------------------------- joblib


class _Refused:
    """Stands in for a refused global while scanning; accepts anything and does nothing."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def __call__(self, *args: object, **kwargs: object) -> "_Refused":
        return self

    def __setstate__(self, state: object) -> None:
        del state


@dataclass
class JoblibScan:
    """What a joblib file asks for."""

    #: Every ``module.name`` the file asks for, in order of first use.
    globals: list[str] = field(default_factory=list)
    #: Those outside :data:`JOBLIB_GLOBALS`.
    refused: list[str] = field(default_factory=list)
    #: False if the file could not be read to the end (the error is in ``error``).
    complete: bool = True
    error: str = ""


class _Unpickler(numpy_pickle.NumpyUnpickler):  # type: ignore[misc]  # joblib has no types
    """joblib's unpickler, resolving only allowlisted globals."""

    def __init__(self, data: bytes, allowed: Iterable[str], *, scan: JoblibScan | None) -> None:
        self._allowed = frozenset(allowed)
        self._scan = scan
        self._stream = io.BytesIO(data)
        self._context = numpy_pickle._validate_fileobject_and_memmap(self._stream, "", None)
        fobj, _ = self._context.__enter__()
        super().__init__("", fobj, ensure_native_byte_order=True)

    def find_class(self, module: str, name: str) -> Any:  # noqa: ANN401 - a class or function
        full = f"{module}.{name}"
        if self._scan is not None and full not in self._scan.globals:
            self._scan.globals.append(full)
        if full in self._allowed:
            return super().find_class(module, name)
        if self._scan is not None:
            self._scan.refused.append(full)
            return _Refused
        msg = f"the model file asks for {full}, which Prohori does not trust; refusing to load it"
        raise UnsafeModelError(msg)

    def load_build(self) -> None:
        """joblib's BUILD, except that arrays of Python objects go through the allowlist too.

        joblib stores an object array as a nested pickle; before joblib 1.6 it read that with a
        plain ``pickle.load``, which would bypass :meth:`find_class`. Every version is handled
        here, the same way.
        """
        pickle._Unpickler.load_build(self)  # type: ignore[attr-defined]  # not in typeshed
        wrapper = self.stack[-1]
        if isinstance(wrapper, numpy_pickle.NDArrayWrapper):
            msg = "the model file uses joblib's pre-0.10 format; refusing to load it"
            raise UnsafeModelError(msg)
        if not isinstance(wrapper, numpy_pickle.NumpyArrayWrapper):
            return
        self.stack.pop()
        if wrapper.dtype.hasobject:
            inner = pickle._Unpickler(self.file_handle)
            inner.find_class = self.find_class  # type: ignore[method-assign]
            self.stack.append(inner.load())
        else:
            self.stack.append(wrapper.read(self, self.ensure_native_byte_order))

    dispatch = numpy_pickle.NumpyUnpickler.dispatch.copy()
    dispatch[pickle.BUILD[0]] = load_build

    def close(self) -> None:
        self._context.__exit__(None, None, None)


def load_joblib(data: bytes, allowed: Iterable[str] = JOBLIB_GLOBALS) -> Any:  # noqa: ANN401
    """Read a joblib file, refusing any global outside ``allowed`` before it is resolved."""
    unpickler = _Unpickler(data, allowed, scan=None)
    try:
        return unpickler.load()
    finally:
        unpickler.close()


def scan_joblib(data: bytes, allowed: Iterable[str] = JOBLIB_GLOBALS) -> JoblibScan:
    """List the globals a joblib file asks for; refused ones are never resolved or called."""
    scan = JoblibScan()
    try:
        unpickler = _Unpickler(data, allowed, scan=scan)
    except Exception as exc:  # any unreadable file is reported, not raised
        return JoblibScan(complete=False, error=f"{type(exc).__name__}: {exc}")
    try:
        unpickler.load()
    except Exception as exc:  # stand-ins can make later steps fail
        scan.complete = False
        scan.error = f"{type(exc).__name__}: {exc}"
    finally:
        unpickler.close()
    scan.refused = list(dict.fromkeys(scan.refused))
    return scan
