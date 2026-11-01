"""Producers: replay and the rotation-aware tailer (run on Linux and Windows in CI)."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.pipeline.messages import RawLog, Topic
from prohori.pipeline.producers import (
    DETECT_LINES,
    FileTailer,
    ProducerError,
    choose_parser,
    open_shared,
    replay,
)
from prohori.pipeline.transport import MemoryTransport

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
APP_LINE = (
    '{"time": "2026-10-01T12:00:00Z", "event": {"action": "auth.signin.failure", '
    '"category": "authentication"}, "source": {"ip": "203.0.113.9"}, "user": {"name": "%s"}}'
)


def _lines(transport: MemoryTransport) -> list[RawLog]:
    return [
        RawLog.model_validate(r.value)
        for r in transport.poll(Topic.RAW_LOGS, "check", 100_000)
        if r.value is not None
    ]


def _write(path: Path, text: str, mode: str = "a") -> None:
    with path.open(mode + "b") as handle:
        handle.write(text.encode())


def _parser(tailer: FileTailer) -> str | None:
    return tailer.parser  # a call, so mypy does not keep a narrowed type across polls


def _tailer(path: Path, transport: MemoryTransport, **options: object) -> FileTailer:
    return FileTailer(path, transport, parser="app_json", now=lambda: T0, **options)  # type: ignore[arg-type]


class TestReplay:
    def test_publishes_every_line_with_the_file_time(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        _write(log, "\n".join(APP_LINE % n for n in range(3)) + "\n\n", "w")
        os.utime(log, (T0.timestamp(), T0.timestamp()))
        transport = MemoryTransport()
        assert replay(log, transport) == 4
        lines = _lines(transport)
        assert [m.line for m in lines] == [1, 2, 3, 4]
        assert {m.parser for m in lines} == {"app_json"}
        assert {m.read_at for m in lines} == {T0}
        assert {m.source for m in lines} == {"app.jsonl"}

    def test_errors(self, tmp_path: Path) -> None:
        transport = MemoryTransport()
        with pytest.raises(ProducerError, match="not found"):
            replay(tmp_path / "missing.log", transport)
        text = tmp_path / "notes.txt"
        _write(text, "hello\nworld\n", "w")
        with pytest.raises(ProducerError, match="could not detect"):
            replay(text, transport)
        with pytest.raises(ProducerError, match="unknown parser"):
            replay(text, transport, parser="nope")
        generic = tmp_path / "x.jsonl"
        _write(generic, '{"a": 1}\n', "w")
        with pytest.raises(ProducerError, match="unknown layout"):
            replay(generic, transport)
        assert choose_parser([], "auth_log", has_mapping=False) == "auth_log"


class TestTailer:
    def test_follows_a_growing_file_and_waits_for_complete_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        transport = MemoryTransport()
        tailer = _tailer(log, transport)
        assert tailer.poll() == 0  # the file does not exist yet
        _write(log, APP_LINE % "a" + "\n" + APP_LINE % "b")
        assert tailer.poll() == 1  # the second line is not finished
        _write(log, "\n")
        assert tailer.poll() == 1
        assert tailer.poll() == 0
        lines = _lines(transport)
        assert [(m.line, json.loads(m.text)["user"]["name"]) for m in lines] == [(1, "a"), (2, "b")]
        assert {m.read_at for m in lines} == {T0}
        tailer.close()

    def test_final_poll_publishes_an_unfinished_last_line(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        _write(log, APP_LINE % "a")
        transport = MemoryTransport()
        tailer = _tailer(log, transport)
        assert tailer.poll() == 0
        assert tailer.poll(final=True) == 1
        tailer.close()

    def test_rotation_by_rename_reads_the_old_file_to_the_end(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        _write(log, APP_LINE % "a" + "\n")
        transport = MemoryTransport()
        tailer = _tailer(log, transport)
        assert tailer.poll() == 1
        _write(log, APP_LINE % "b" + "\n")  # written just before rotation, not yet read
        log.replace(tmp_path / "app.jsonl.1")  # works on Windows too: the tailer shares delete
        _write(log, APP_LINE % "c" + "\n", "w")
        assert tailer.poll() == 2
        assert tailer.rotations == 1
        names = [json.loads(m.text)["user"]["name"] for m in _lines(transport)]
        assert names == ["a", "b", "c"]
        tailer.close()

    def test_rotation_keeps_reading_while_the_new_file_is_missing(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        _write(log, APP_LINE % "a" + "\n")
        transport = MemoryTransport()
        tailer = _tailer(log, transport)
        tailer.poll()
        log.replace(tmp_path / "old.jsonl")
        assert tailer.poll() == 0
        _write(log, APP_LINE % "b" + "\n", "w")
        assert tailer.poll() == 1
        assert tailer.rotations == 1
        tailer.close()

    def test_truncation_restarts_at_the_beginning(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        _write(log, "\n".join(APP_LINE % n for n in range(3)) + "\n")
        transport = MemoryTransport()
        tailer = _tailer(log, transport)
        assert tailer.poll() == 3
        with log.open("r+b") as handle:  # copytruncate: same file, emptied in place
            handle.truncate(0)
        assert tailer.poll() == 0
        _write(log, APP_LINE % "z" + "\n")
        assert tailer.poll() == 1
        last = _lines(transport)[-1]
        assert (last.line, json.loads(last.text)["user"]["name"]) == (1, "z")
        tailer.close()

    def test_checkpoint_resumes_after_a_restart(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        state = tmp_path / "state"
        _write(log, APP_LINE % "a" + "\n")
        transport = MemoryTransport()
        first = _tailer(log, transport, state_dir=state)
        assert first.poll() == 1
        first.close()
        _write(log, APP_LINE % "b" + "\n")
        second = _tailer(log, transport, state_dir=state)
        assert second.poll() == 1
        second.close()
        assert [m.line for m in _lines(transport)] == [1, 2]

    def test_checkpoint_of_a_replaced_file_is_ignored(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        state = tmp_path / "state"
        _write(log, "\n".join(APP_LINE % n for n in range(3)) + "\n")
        first = _tailer(log, MemoryTransport(), state_dir=state)
        assert first.poll() == 3
        first.close()
        log.unlink()
        _write(log, APP_LINE % "new" + "\n", "w")  # shorter than the saved position
        transport = MemoryTransport()
        second = _tailer(log, transport, state_dir=state)
        assert second.poll() == 1
        second.close()
        assert [m.line for m in _lines(transport)] == [1]

    def test_corrupt_checkpoint_starts_from_the_beginning(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        state = tmp_path / "state"
        _write(log, APP_LINE % "a" + "\n")
        tailer = _tailer(log, MemoryTransport(), state_dir=state)
        tailer.poll()
        tailer.close()
        checkpoint = next(iter(state.glob("*.json")))
        checkpoint.write_text("{broken", encoding="utf-8")
        again = _tailer(log, MemoryTransport(), state_dir=state)
        assert again.poll() == 1
        again.close()

    def test_auto_detection_waits_for_lines_then_decides(self, tmp_path: Path) -> None:
        log = tmp_path / "app.jsonl"
        transport = MemoryTransport()
        tailer = FileTailer(log, transport, now=lambda: T0)
        _write(log, '{"time": "2026-')
        assert tailer.poll() == 0
        assert _parser(tailer) is None
        _write(log, '10-01T12:00:00Z", "event": {"action": "a.b", "category": "web"}}\n')
        assert tailer.poll() == 1
        assert _parser(tailer) == "app_json"
        tailer.close()

    def test_undetectable_file_fails_once_there_are_enough_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "notes.txt"
        transport = MemoryTransport()
        tailer = FileTailer(log, transport)
        _write(log, "hello\n")
        assert tailer.poll() == 0  # a few unknown lines: wait
        _write(log, "hello\n" * DETECT_LINES)
        with pytest.raises(ProducerError, match="could not detect"):
            tailer.poll()
        tailer.close()


def test_open_shared_allows_rename_and_delete_while_open(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_bytes(b"x\n")
    with open_shared(log) as handle:
        log.replace(tmp_path / "b.log")
        (tmp_path / "b.log").unlink()
        assert handle.read() == b"x\n"


def test_open_shared_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):  # noqa: PT011 - the error class differs by platform
        open_shared(tmp_path / "missing.log")
