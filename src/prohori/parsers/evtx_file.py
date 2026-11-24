# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Read native Windows ``.evtx`` files as JSON lines for the ``windows_security`` parser.

Needs the optional ``evtx`` extra (``pip install 'prohori[evtx]'``): the ``evtx`` package
(MIT licence, wheels for Windows, macOS and Linux), a Python binding of a Rust EVTX parser. Each
record becomes one compact JSON line in the evtx_dump layout (``{"Event": {"System": ...,
"EventData": ...}}``), so the parser treats an ``.evtx`` file like any other export. A record the
library cannot read becomes a line the parser counts as an error; the rest of the file is still
read.
"""

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

EXTRA_HINT = "reading .evtx files needs the evtx extra: pip install 'prohori[evtx]'"


def evtx_available() -> bool:
    """Whether the optional ``evtx`` package can be imported."""
    try:
        import evtx  # noqa: F401 - optional dependency
    except ImportError:
        return False
    return True


class EvtxLines:
    """A binary stream with ``readline`` over an ``.evtx`` file's records as JSON lines.

    ``hexdigest()`` and ``bytes`` describe the ``.evtx`` file itself, not the JSON lines, so a
    report names the file that was read.
    """

    def __init__(self, path: Path) -> None:
        from evtx import PyEvtxParser

        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        self._digest = digest.hexdigest()
        self.bytes = path.stat().st_size
        self._records: Iterator[bytes] = _lines(PyEvtxParser(str(path)))
        self._pending = b""

    def hexdigest(self) -> str:
        return self._digest

    def readline(self, size: int = -1, /) -> bytes:
        if not self._pending:
            self._pending = next(self._records, b"")
        if size < 0 or len(self._pending) <= size:
            line, self._pending = self._pending, b""
        else:
            line, self._pending = self._pending[:size], self._pending[size:]
        return line


def _lines(parser: Any) -> Iterator[bytes]:  # noqa: ANN401 - the library ships no types
    records = parser.records_json()
    while True:
        try:
            record = next(records)
        except StopIteration:
            return
        except Exception as exc:
            yield _error_line(f"unreadable record: {type(exc).__name__}")
            continue
        try:
            data = json.loads(record["data"])
        except (KeyError, TypeError, ValueError):
            yield _error_line("record without JSON data")
            continue
        yield json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def _error_line(reason: str) -> bytes:
    return json.dumps({"evtx_error": reason}).encode() + b"\n"
