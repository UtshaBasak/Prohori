"""Producers: put log lines on the ``raw-logs`` topic.

- :func:`replay` reads whole files (for example the simulator's labelled logs) once.
- :class:`FileTailer` follows a growing file, like ``tail -F``: it survives rotation by rename
  (``auth.log`` -> ``auth.log.1`` and a new ``auth.log``) and by truncation (copytruncate), and
  checkpoints its position so a restart continues where it stopped.

Lines keep their line number in the file, which is part of the event id: a line read twice yields
the same event and is stored once.
"""

import hashlib
import io
import json
import os
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import chain, islice
from pathlib import Path
from typing import BinaryIO

from prohori.parsers import RawLine, available, detect_format, read_lines
from prohori.pipeline.messages import RawLog, Topic
from prohori.pipeline.transport import Transport

#: Lines read for format detection.
DETECT_LINES = 50
#: Bytes a tailer reads from the start of a file to detect its format.
DETECT_BYTES = 64 * 1024
#: Most bytes a tailer reads per poll and file.
READ_CHUNK = 1024 * 1024


class ProducerError(ValueError):
    """A file cannot be produced (missing, unknown format, bad parser name)."""


def choose_parser(lines: Sequence[RawLine], requested: str, *, has_mapping: bool) -> str:
    """Return the parser for a file: ``requested``, or the detected format for ``auto``."""
    if requested != "auto":
        if requested not in available():
            msg = f"unknown parser {requested!r}; choose from auto, {', '.join(available())}"
            raise ProducerError(msg)
        return requested
    detected = detect_format(lines)
    if detected is None:
        msg = "could not detect the log format; choose one with --parser"
        raise ProducerError(msg)
    if detected == "generic_json" and not has_mapping:
        msg = (
            "JSON Lines in an unknown layout: use --parser app_json, or generic_json with --mapping"
        )
        raise ProducerError(msg)
    return detected


def _message(
    transport: Transport, source: str, raw: RawLine, parser: str, read_at: datetime
) -> None:
    message = RawLog(
        source=source,
        line=raw.number,
        text=raw.text,
        parser=parser,
        read_at=read_at,
        too_long=raw.too_long,
        decode_error=raw.decode_error,
    )
    transport.publish(Topic.RAW_LOGS, source, message.model_dump(mode="json"))


def replay(
    path: Path, transport: Transport, *, parser: str = "auto", has_mapping: bool = False
) -> int:
    """Publish every line of ``path``; return the number of lines.

    ``read_at`` is the file's modification time, as in the batch commands, so a replay produces
    the same events as ``prohori incidents`` on the same file.
    """
    if not path.is_file():
        msg = f"file not found: {path}"
        raise ProducerError(msg)
    read_at = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    count = 0
    with path.open("rb") as stream:
        lines: Iterator[RawLine] = read_lines(stream)
        head = list(islice(lines, DETECT_LINES))
        name = choose_parser(head, parser, has_mapping=has_mapping)
        for raw in chain(head, lines):
            _message(transport, path.name, raw, name, read_at)
            count += 1
    transport.flush()
    return count


# ---------------------------------------------------------------------- tailing


def open_shared(path: Path) -> BinaryIO:
    """Open ``path`` for reading without stopping other programs from renaming or deleting it.

    On Windows a file opened by Python's ``open`` cannot be renamed, which would break the log
    rotation of the program writing it; this opens it with every sharing flag instead.
    """
    if sys.platform != "win32":
        return path.open("rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    generic_read = 0x80000000
    share_all = 0x1 | 0x2 | 0x4  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    open_existing = 3
    normal = 0x80
    handle = create_file(str(path), generic_read, share_all, None, open_existing, normal, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb")


def _identity(stat: os.stat_result) -> tuple[int, int]:
    return (stat.st_dev, stat.st_ino)


@dataclass
class _Checkpoint:
    identity: tuple[int, int]
    position: int
    line: int


class FileTailer:
    """Follow ``path`` and publish each complete new line.

    A line is published once it ends with a newline. When ``path`` is replaced (rotation by
    rename), the rest of the old file is read first, then the new file from its start; when the
    file shrinks (truncation), reading restarts at its start. With a ``state_dir``, the position
    is saved after each poll and restored on the next start if the file is still the same one.

    Args:
        path: The file to follow. It may not exist yet.
        parser: Parser name, or ``auto`` to detect the format from the first lines.
        now: Clock for ``read_at`` (tests pass a fixed one).
    """

    def __init__(
        self,
        path: Path,
        transport: Transport,
        *,
        parser: str = "auto",
        has_mapping: bool = False,
        state_dir: Path | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.path = path
        self.transport = transport
        self.requested = parser
        self.has_mapping = has_mapping
        self.now = now
        self.parser = None if parser == "auto" else choose_parser([], parser, has_mapping=False)
        self.source = path.name
        self.state_file = (
            state_dir / f"{hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:16]}.json"
            if state_dir is not None
            else None
        )
        self.rotations = 0
        self._handle: BinaryIO | None = None
        self._identity: tuple[int, int] | None = None
        self._position = 0
        self._line = 0

    # ------------------------------------------------------------------ state

    def _load(self) -> _Checkpoint | None:
        if self.state_file is None:
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            identity = (int(data["dev"]), int(data["ino"]))
            return _Checkpoint(identity, int(data["position"]), int(data["line"]))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _save(self) -> None:
        if self.state_file is None or self._identity is None:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "path": str(self.path),
            "dev": self._identity[0],
            "ino": self._identity[1],
            "position": self._position,
            "line": self._line,
            "parser": self.parser,
        }
        temp = self.state_file.with_name(self.state_file.name + ".tmp")
        temp.write_text(json.dumps(data), encoding="utf-8")
        temp.replace(self.state_file)

    # ------------------------------------------------------------------ files

    def _open(self, *, resume: bool) -> bool:
        try:
            handle = open_shared(self.path)
        except OSError:
            return False
        identity = _identity(os.fstat(handle.fileno()))
        self._handle, self._identity = handle, identity
        self._position, self._line = 0, 0
        checkpoint = self._load() if resume else None
        if (
            checkpoint is not None
            and checkpoint.identity == identity
            and checkpoint.position <= os.fstat(handle.fileno()).st_size
        ):
            self._position, self._line = checkpoint.position, checkpoint.line
        handle.seek(self._position)
        return True

    def _close_handle(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = None

    def close(self) -> None:
        self._close_handle()

    # ------------------------------------------------------------------ polling

    def poll(self, *, final: bool = False) -> int:
        """Publish the complete lines added since the last poll; return how many were published.

        ``final`` also publishes a last line without a newline (used at shutdown and when a
        rotated file is finished).
        """
        if self._handle is None and not self._open(resume=True):
            return 0
        if not self._detect():
            return 0
        count = self._read(final=final)
        rotated = self._rotated()
        if rotated:
            count += self._read(final=True)  # the rest of the old file
            self._close_handle()
            self.rotations += 1
            if self._open(resume=False):
                count += self._read(final=final)
        self.transport.flush()
        self._save()
        return count

    def _rotated(self) -> bool:
        assert self._handle is not None  # noqa: S101 - poll opened it
        try:
            current = self.path.stat()
        except OSError:
            return False  # renamed away and not yet re-created: keep reading the old file
        opened = os.fstat(self._handle.fileno())
        if _identity(current) != _identity(opened):
            return True
        if opened.st_size < self._position:  # truncated in place
            self._handle.seek(0)
            self._position, self._line = 0, 0
        return False

    def _read(self, *, final: bool) -> int:
        assert self._handle is not None  # noqa: S101 - poll opened it
        handle = self._handle
        handle.seek(self._position)
        data = handle.read(READ_CHUNK)
        if not data:
            return 0
        end = data.rfind(b"\n") + 1
        if end == 0 and not final and len(data) < READ_CHUNK:
            return 0  # only an unfinished line so far
        if end == 0 or (final and end < len(data)):
            end = len(data)
        count = 0
        for raw in read_lines(io.BytesIO(data[:end])):
            self._line += 1
            line = RawLine(self._line, raw.text, raw.too_long, raw.decode_error)
            _message(self.transport, self.source, line, self.parser or "", self.now())
            count += 1
        self._position += end
        return count

    def _detect(self) -> bool:
        """Choose the parser from the first lines of the file, once there are enough of them."""
        if self.parser is not None:
            return True
        assert self._handle is not None  # noqa: S101 - poll opened it
        self._handle.seek(0)
        data = self._handle.read(DETECT_BYTES)
        complete = data[: data.rfind(b"\n") + 1]
        head = list(islice(read_lines(io.BytesIO(complete)), DETECT_LINES))
        if not head:
            return False
        try:
            self.parser = choose_parser(head, self.requested, has_mapping=self.has_mapping)
        except ProducerError:
            if len(head) < DETECT_LINES and len(data) < DETECT_BYTES:
                return False  # wait for more lines before deciding
            raise
        return True
