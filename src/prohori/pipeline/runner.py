"""The lite-mode runner: every stage in one process, taking turns.

Each round, the producers publish new lines and every stage processes one batch, in pipeline
order. :meth:`LitePipeline.drain` repeats rounds until nothing moves; :meth:`LitePipeline.finish`
then lets each stage release what it still holds (the rule engine's reorder buffer, open
incidents) and drains again, stage by stage, so the last incidents reach the database.

Shutdown is graceful: :meth:`LitePipeline.follow` stops between rounds when its ``stop`` event is
set (the command sets it on Ctrl+C or SIGTERM), finishes the stages and commits.
"""

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from prohori.enrich import Enricher
from prohori.incidents import IncidentSettings
from prohori.pipeline.producers import FileTailer
from prohori.pipeline.sink import DuckDBSink
from prohori.pipeline.stages import Detector, IncidentStage, Normaliser, ParserSettings, Stage
from prohori.pipeline.transport import Transport
from prohori.rules import CompiledRule

#: Messages each stage reads per input and round.
BATCH_SIZE = 500


@dataclass(frozen=True)
class LiteSettings:
    """Everything that shapes a lite-mode run."""

    rules: Sequence[CompiledRule]
    database: Path
    parsers: ParserSettings = field(default_factory=ParserSettings)
    incidents: IncidentSettings = field(default_factory=IncidentSettings)
    lateness: timedelta = timedelta(minutes=5)
    enricher: Enricher | None = None
    enrichment: str = "none"
    follow: bool = False  # live logs: close incidents after a quiet spell too


class LitePipeline:
    """The four consumers over one transport.

    Args:
        transport: Where the topics live (a :class:`~prohori.pipeline.transport.FileTransport`
            for runs that survive restarts).
        settings: Rules, database path and options.
        clock: Monotonic clock in seconds (tests pass a fake one).
    """

    def __init__(
        self,
        transport: Transport,
        settings: LiteSettings,
        *,
        clock: Callable[[], float] = time.monotonic,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        self.transport = transport
        self.settings = settings
        self.clock = clock
        self.batch_size = batch_size
        reference = datetime.now(UTC) if settings.follow else None
        self.normaliser = Normaliser(transport, settings.parsers)
        self.detector = Detector(
            transport, settings.rules, lateness=settings.lateness, reference_time=reference
        )
        self.incidents = IncidentStage(
            transport,
            settings.rules,
            settings=settings.incidents,
            lateness=settings.lateness,
            enricher=settings.enricher,
            enrichment=settings.enrichment,
            clock=clock,
            idle_close=settings.follow,
        )
        self.sink = DuckDBSink(transport, settings.database)
        self.stages: tuple[Stage, ...] = (self.normaliser, self.detector, self.incidents, self.sink)
        self.rounds = 0
        self.lines = 0
        self.started = False

    def start(self) -> None:
        """Prepare the stages (stateful ones rebuild their state from the start of the topics)."""
        for stage in self.stages:
            stage.start()
        self.started = True

    def round(self) -> int:
        """One batch per stage; return the number of messages read."""
        self.rounds += 1
        return sum(stage.step(self.batch_size) for stage in self.stages)

    def drain(self) -> int:
        """Run rounds until a round reads nothing; return the messages read."""
        total = 0
        while moved := self.round():
            total += moved
        return total

    def finish(self) -> None:
        """Release held state stage by stage, draining after each, so everything is written."""
        self.drain()
        for stage in self.stages:
            stage.finish()
            self.drain()

    def run(self) -> dict[str, Any]:
        """Process everything already published (a replay) and return the metrics."""
        if not self.started:
            self.start()
        self.finish()
        return self.metrics()

    def follow(
        self,
        tailers: Sequence[FileTailer],
        stop: threading.Event,
        *,
        poll_interval: float = 1.0,
        idle_flush: float = 10.0,
        max_rounds: int | None = None,
    ) -> dict[str, Any]:
        """Tail files until ``stop`` is set, then finish and return the metrics.

        After ``idle_flush`` seconds without new lines the rule engine releases the events it is
        holding for reordering, so the last alerts of a quiet log are not delayed indefinitely.
        """
        if not self.started:
            self.start()
        quiet_since: float | None = None
        rounds = 0
        while not stop.is_set() and (max_rounds is None or rounds < max_rounds):
            rounds += 1
            produced = sum(tailer.poll() for tailer in tailers)
            self.lines += produced
            moved = self.drain()
            if produced or moved:
                quiet_since = None
                continue
            now = self.clock()
            if quiet_since is None:
                quiet_since = now
            elif now - quiet_since >= idle_flush:
                self.detector.finish()
                self.drain()
                quiet_since = None
            stop.wait(poll_interval)
        self.finish()
        for tailer in tailers:
            tailer.close()
        return self.metrics()

    def metrics(self) -> dict[str, Any]:
        """Counters for every stage, the parser and rule engine totals and the table sizes."""
        stages = {stage.name: stage.metrics.as_dict() for stage in self.stages}
        return {
            "rounds": self.rounds,
            "lines_tailed": self.lines,
            "stages": stages,
            "parse": self.normaliser.parse_counts(),
            "engine": self.detector.engine_counts,
            "tables": self.sink.counts(),
        }

    def close(self) -> None:
        self.sink.close()
        self.transport.close()
        if self.settings.enricher is not None:
            self.settings.enricher.close()
