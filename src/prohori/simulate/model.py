"""Building blocks of a simulation: parameters, attacks and the line recorder.

A scenario writes log lines through a :class:`Recorder`, marking each line as benign background
or as part of a named :class:`Attack`. Lines are sorted by time at the end (ties keep the order
they were written in), numbered from 1 like the parsers number them, and labelled.

Randomness comes only from the :class:`random.Random` the run passes in, seeded from the
scenario, variant and seed, and only through methods whose output is the same on every supported
Python version (``random``, ``randrange``, ``choice``, ``uniform``, ``shuffle``). Nothing reads
the clock.
"""

import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

#: Most lines one run may write.
MAX_LINES = 200_000


class SimulationError(ValueError):
    """Invalid scenario, variant or parameter."""


@dataclass(frozen=True)
class ParamSpec:
    """A tunable scenario parameter: its type, bounds and meaning."""

    kind: type
    low: float
    high: float
    help: str

    def coerce(self, name: str, text: str) -> int | float:
        try:
            value: int | float = int(text) if self.kind is int else float(text)
        except ValueError:
            msg = f"{name} must be {'an integer' if self.kind is int else 'a number'}"
            raise SimulationError(msg) from None
        if not self.low <= value <= self.high:
            msg = f"{name} must be between {self.low:g} and {self.high:g}"
            raise SimulationError(msg)
        return value


#: Every parameter a scenario may expose.
PARAMS: Mapping[str, ParamSpec] = {
    "duration": ParamSpec(int, 10, 1440, "minutes of background activity"),
    "users": ParamSpec(int, 5, 500, "accounts in the background population"),
    "noise": ParamSpec(float, 0, 60, "background events per minute"),
    "attack_at": ParamSpec(int, 0, 1440, "minutes after the start when the attack begins"),
    "rate": ParamSpec(float, 0.1, 600, "attack attempts per minute (per source)"),
    "attempts": ParamSpec(int, 1, 10_000, "attack attempts"),
    "sources": ParamSpec(int, 1, 50, "attacker IP addresses"),
}


@dataclass(frozen=True)
class Attack:
    """One labelled attack instance and the rules expected to detect it."""

    id: str
    kind: str
    description: str
    expected_rules: tuple[str, ...]
    sources: tuple[str, ...] = ()
    accounts: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
            "expected_rules": list(self.expected_rules),
            "sources": list(self.sources),
            "accounts": list(self.accounts),
        }


@dataclass(order=True)
class _Line:
    timestamp: datetime
    order: int
    text: str = field(compare=False)
    attack: str | None = field(compare=False)


class Recorder:
    """Collects timestamped lines and attack definitions for one simulated log file."""

    def __init__(self, rng: random.Random, start: datetime) -> None:
        self.rng = rng
        self.start = start
        self.attacks: list[Attack] = []
        self._lines: list[_Line] = []

    def at(self, minutes: float) -> datetime:
        """The time ``minutes`` after the start, to the microsecond."""
        return self.start + timedelta(microseconds=round(minutes * 60_000_000))

    def add(self, timestamp: datetime, text: str, attack: Attack | None = None) -> None:
        if len(self._lines) >= MAX_LINES:
            msg = f"the scenario would write more than {MAX_LINES} lines; lower its parameters"
            raise SimulationError(msg)
        self._lines.append(_Line(timestamp, len(self._lines), text, attack.id if attack else None))

    def attack(self, attack: Attack) -> Attack:
        self.attacks.append(attack)
        return attack

    def lines(self) -> list[tuple[str, str | None]]:
        """Lines in time order (stable for equal times), with the attack id or None."""
        return [(line.text, line.attack) for line in sorted(self._lines)]


def parse_start(text: str) -> datetime:
    """Parse an ISO 8601 start time with an offset (``2026-10-24T08:00:00Z``)."""
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise SimulationError(f"invalid start time {text!r}; use ISO 8601 with Z") from None
    if value.tzinfo is None:
        raise SimulationError("the start time needs a timezone, such as Z")
    return value.astimezone(UTC)
