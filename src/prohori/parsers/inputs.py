# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Open a log file (or a binary stream) as lines, whatever form it is stored in.

* ``.evtx``: Windows event log files, record by record (needs the ``evtx`` extra);
* UTF-16 with a byte-order mark: what Windows PowerShell 5.1 writes, re-encoded as UTF-8;
* gzip (recognised by its first two bytes, not by the file name): decompressed as it is read;
* CloudTrail files (``{"Records": [...]}``, ``{"Events": [...]}`` or CloudTrail JSON Lines),
  compressed or not: one record per line (:mod:`prohori.parsers.cloudtrail_file`);
* anything else: the bytes as they are.

Everything is read as a stream with bounded memory. A converted input reports the size and the
SHA-256 of the input as stored (:class:`ConvertedInput`).
"""

import contextlib
import gzip
import hashlib
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from prohori.parsers.base import ConvertedInput, LineSource, Utf16Lines, is_utf16
from prohori.parsers.cloudtrail_file import CHUNK, JsonRecordLines, Readable, sniff
from prohori.parsers.evtx_file import EXTRA_HINT, EvtxLines, evtx_available

#: Bytes looked at to recognise a format.
HEAD = 1 << 16
GZIP_MAGIC = b"\x1f\x8b"


class InputError(ValueError):
    """An input that cannot be read: a missing extra, corrupt compressed data."""


class _Stream(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class _Tee:
    """Reads a stream and counts and hashes every byte read."""

    def __init__(self, stream: _Stream) -> None:
        self._stream = stream
        self._hash = hashlib.sha256()
        self.count = 0

    def read(self, size: int = -1, /) -> bytes:
        data = self._stream.read(size)
        self._hash.update(data)
        self.count += len(data)
        return data

    def readline(self, size: int = -1, /) -> bytes:
        readline = getattr(self._stream, "readline", None)
        data: bytes = readline(size) if readline is not None else self._stream.read(size)
        self._hash.update(data)
        self.count += len(data)
        return data

    def read1(self, size: int = -1, /) -> bytes:
        read1 = getattr(self._stream, "read1", None)
        data: bytes = read1(size) if read1 is not None else self._stream.read(size)
        self._hash.update(data)
        self.count += len(data)
        return data

    def hexdigest(self) -> str:
        return self._hash.hexdigest()

    def drain(self) -> None:
        while self.read(CHUNK):
            pass


class _Prefixed:
    """``head`` (bytes already read), then the rest of ``stream``."""

    def __init__(self, head: bytes, stream: Readable) -> None:
        self._head = head
        self._stream = stream

    def read(self, size: int = -1, /) -> bytes:
        if self._head:
            if size < 0:
                data, self._head = self._head + self._stream.read(), b""
                return data
            data, self._head = self._head[:size], self._head[size:]
            return data
        return self._stream.read(size)

    def readline(self, size: int = -1, /) -> bytes:
        line = bytearray()
        while size < 0 or len(line) < size:
            if self._head:
                newline = self._head.find(b"\n")
                take = len(self._head) if newline < 0 else newline + 1
                if size >= 0:
                    take = min(take, size - len(line))
                line += self._head[:take]
                self._head = self._head[take:]
                if line.endswith(b"\n"):
                    break
                continue
            readline = getattr(self._stream, "readline", None)
            if readline is None:  # pragma: no cover - every stream used here has readline
                break
            line += readline(size - len(line) if size >= 0 else -1)
            break
        return bytes(line)


class _Gunzip:
    """A gzip stream whose corrupt or truncated data raises :class:`InputError`."""

    def __init__(self, stream: Readable) -> None:
        self._file = gzip.GzipFile(fileobj=cast("BinaryIO", stream), mode="rb")

    def read(self, size: int = -1, /) -> bytes:
        try:
            data: bytes = self._file.read(size)
        except (OSError, EOFError, zlib.error) as exc:
            raise InputError(f"corrupt or truncated gzip data: {exc}"[:200]) from None
        return data

    def readline(self, size: int = -1, /) -> bytes:
        try:
            line: bytes = self._file.readline(size)
        except (OSError, EOFError, zlib.error) as exc:
            raise InputError(f"corrupt or truncated gzip data: {exc}"[:200]) from None
        return line


class _GzipLines(ConvertedInput):
    """The lines of a gzip-compressed text file."""

    def __init__(self, stream: _Prefixed, digest: _Tee) -> None:
        self._stream = stream
        self._digest = digest

    def stored_size(self) -> int:
        return self._digest.count

    def hexdigest(self) -> str:
        return self._digest.hexdigest()

    def readline(self, size: int = -1, /) -> bytes:
        line = self._stream.readline(size)
        if not line:
            self._digest.drain()
        return line


def _head(stream: Readable, *, partial: bool) -> bytes:
    """Up to :data:`HEAD` bytes; with ``partial``, what one read returns (a pipe may be slow)."""
    head = b""
    while len(head) < HEAD:
        reader = getattr(stream, "read1", None) if partial else None
        chunk = reader(HEAD - len(head)) if reader is not None else stream.read(HEAD - len(head))
        if not chunk:
            break
        head += chunk
        if partial and len(head) >= 64:
            break
    return head


def convert(stream: BinaryIO, *, partial: bool = False) -> LineSource:
    """``stream`` as lines: decompressed, and CloudTrail files one record per line.

    Args:
        stream: A binary stream.
        partial: Look at what is already available instead of waiting for :data:`HEAD` bytes
            (standard input, which may be a slow pipe).
    """
    tee = _Tee(stream)
    head = _head(tee, partial=partial)
    source: Readable = _Prefixed(head, tee)
    compressed = head.startswith(GZIP_MAGIC)
    if compressed:
        unzipped = _Gunzip(source)
        head = _head(unzipped, partial=False)
        source = _Prefixed(head, unzipped)
    kind = sniff(head)
    if kind != "lines":
        return JsonRecordLines(source, tee, array=kind == "records")
    if compressed:
        return _GzipLines(source, tee)  # type: ignore[arg-type]
    return source  # type: ignore[return-value]


@contextlib.contextmanager
def open_log(path: Path) -> Iterator[LineSource]:
    """Open the file ``path`` as lines (see the module documentation).

    Raises:
        InputError: for an ``.evtx`` file without the ``evtx`` extra.
    """
    if path.suffix.lower() == ".evtx":
        if not evtx_available():
            raise InputError(EXTRA_HINT)
        yield EvtxLines(path)
        return
    if is_utf16(path):  # Windows PowerShell 5.1 writes UTF-16 by default
        text = Utf16Lines(path)
        try:
            yield text
        finally:
            text.close()
        return
    with path.open("rb") as stream:
        yield convert(stream)
