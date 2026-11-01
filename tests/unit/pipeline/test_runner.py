"""The lite-mode runner: following files, idle flushing, graceful stop."""

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from prohori.pipeline.producers import FileTailer, replay
from prohori.pipeline.runner import LitePipeline, LiteSettings, make_stage, serve
from prohori.pipeline.stages import IncidentStage
from prohori.pipeline.transport import FileTransport, MemoryTransport
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write

RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


@pytest.fixture(scope="module")
def web_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    write(simulate("web-scanning", seed=1), out)
    return out / "web-scanning.log"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 5.0  # every look at the clock is five seconds later
        return self.now


@pytest.fixture
def pipeline(tmp_path: Path) -> Iterator[LitePipeline]:
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb", follow=True)
    lite = LitePipeline(MemoryTransport(), settings, clock=FakeClock())
    yield lite
    lite.close()


def test_follow_tails_until_max_rounds_and_writes_everything(
    pipeline: LitePipeline, web_log: Path, tmp_path: Path
) -> None:
    live = tmp_path / "live.log"
    live.write_bytes(web_log.read_bytes())
    tailer = FileTailer(live, pipeline.transport, parser="access_log")
    metrics = pipeline.follow([tailer], threading.Event(), poll_interval=0, max_rounds=3)
    lines = web_log.read_bytes().count(b"\n")
    assert metrics["lines_tailed"] == lines
    assert metrics["tables"]["events"] == lines
    assert metrics["tables"]["incidents"] >= 1
    assert metrics["stages"]["normalise"]["dead_letters"] == 0


def test_follow_flushes_the_engine_when_the_logs_go_quiet(
    pipeline: LitePipeline, web_log: Path, tmp_path: Path
) -> None:
    live = tmp_path / "live.log"
    live.write_bytes(web_log.read_bytes())
    tailer = FileTailer(live, pipeline.transport, parser="access_log")
    calls: list[int] = []
    original = pipeline.detector.idle

    def counting_idle() -> None:
        calls.append(1)
        original()

    pipeline.detector.idle = counting_idle  # type: ignore[method-assign]
    pipeline.follow([tailer], threading.Event(), poll_interval=0, idle_flush=10, max_rounds=6)
    assert calls  # quiet rounds released the engine's reorder buffer


def test_follow_stops_when_the_event_is_set(pipeline: LitePipeline, tmp_path: Path) -> None:
    stop = threading.Event()
    stop.set()
    tailer = FileTailer(tmp_path / "missing.log", pipeline.transport, parser="access_log")
    metrics = pipeline.follow([tailer], stop, poll_interval=0)
    assert metrics["rounds"] >= 1
    assert metrics["lines_tailed"] == 0


def test_replay_state_survives_a_restart(web_log: Path, tmp_path: Path) -> None:
    state = tmp_path / "state"
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb")
    first = LitePipeline(FileTransport(state, fsync=False), settings)
    replay(web_log, first.transport, parser="access_log")
    before = first.run()["tables"]
    first.close()

    second = LitePipeline(FileTransport(state, fsync=False), settings)
    replay(web_log, second.transport, parser="access_log")  # the same file again
    after = second.run()
    second.close()
    assert after["tables"] == before
    assert after["stages"]["detect"]["duplicates"] > 0


def test_serve_finishes_the_stages_when_stopped(tmp_path: Path) -> None:
    transport = MemoryTransport()
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb")
    detector = make_stage("detect", transport, settings)
    finished: list[str] = []
    detector.finish = lambda: finished.append("detect")  # type: ignore[method-assign]
    stop = threading.Event()
    stop.set()
    assert serve([detector], stop, poll_interval=0) == 0
    assert finished == ["detect"]


def test_make_stage_choices(tmp_path: Path) -> None:
    transport = MemoryTransport()
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb", follow=True)
    incidents = make_stage("incidents", transport, settings)
    assert isinstance(incidents, IncidentStage)
    assert incidents.idle_close == incidents.hold.total_seconds()
    quick = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb", idle_close=5.0)
    assert make_stage("incidents", transport, quick).idle_close == 5.0  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="unknown stage"):
        make_stage("nope", transport, settings)
