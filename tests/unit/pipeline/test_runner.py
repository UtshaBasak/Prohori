"""The lite-mode runner: following files, idle flushing, graceful stop."""

import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from prohori.pipeline.messages import RawLog, Topic
from prohori.pipeline.producers import FileTailer, replay
from prohori.pipeline.runner import LitePipeline, LiteSettings, make_stage, serve
from prohori.pipeline.stages import IncidentStage
from prohori.pipeline.transport import FileTransport, MemoryTransport
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write

RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


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


def test_serve_finishes_only_stateless_stages_when_stopped(tmp_path: Path) -> None:
    transport = MemoryTransport()
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb")
    stages = [make_stage(name, transport, settings) for name in ("normalise", "detect")]
    finished: list[str] = []
    for stage in stages:
        stage.finish = lambda name=stage.name: finished.append(name)  # type: ignore[method-assign,misc]
    stop = threading.Event()
    stop.set()
    assert serve(stages, stop, poll_interval=0) == 0
    assert finished == ["normalise"]  # the detector rebuilds its state on the next start


def _failed_sign_ins(transport: MemoryTransport, minutes: list[int], first_line: int) -> None:
    for i, minute in enumerate(minutes):
        when = (T0 + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")
        text = json.dumps(
            {
                "time": when,
                "event": {"action": "auth.signin.failure", "category": "authentication"},
                "source": {"ip": "203.0.113.9"},
                "user": {"name": "alice"},
            }
        )
        raw = RawLog(
            source="app.jsonl", line=first_line + i, text=text, parser="app_json", read_at=T0
        )
        transport.publish(Topic.RAW_LOGS, "app.jsonl", raw.model_dump(mode="json"))


def _incidents(transport: MemoryTransport) -> dict[str, int]:
    records = transport.poll(Topic.INCIDENTS, "t", 10**6)
    return {str(r.key): len(r.value["alerts"]) for r in records if r.value is not None}


def test_serve_never_writes_a_partial_incident_on_shutdown(tmp_path: Path) -> None:
    # Two bursts 20 minutes apart are one incident. A stack stopped between them (SIGTERM, then
    # a restart in which the stateful stages rebuild from their topics) must not also write the
    # first burst as an incident of its own.
    settings = LiteSettings(rules=RULES, database=tmp_path / "p.duckdb", lateness=timedelta(0))
    first, second = [m // 3 for m in range(15)], [20 + m // 3 for m in range(15)]

    uninterrupted = MemoryTransport()
    _failed_sign_ins(uninterrupted, first + second, 1)
    LitePipeline(uninterrupted, settings).run()
    expected = _incidents(uninterrupted)
    assert len(expected) == 1

    transport = MemoryTransport()
    names = ("normalise", "detect", "incidents")
    _failed_sign_ins(transport, first, 1)
    stop = threading.Event()
    serve([make_stage(n, transport, settings) for n in names], stop, max_rounds=3)
    stop.set()
    serve([make_stage(n, transport, settings) for n in names], stop)  # stopped at once
    _failed_sign_ins(transport, second, len(first) + 1)
    LitePipeline(transport, settings).run()  # restarted, then the end of the input
    assert _incidents(transport) == expected


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
