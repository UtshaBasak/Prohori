# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Measure how far the benign background goes, to set the evasion-resistant rules' thresholds.

ADR-0036 sets each threshold of PRH-AUTH-005 to PRH-AUTH-010 at twice the largest value the
benign lines of the **default** variants reach (seeds 1 to 5), rounded up. This script computes
those maxima with the rule engine's window semantics (an event is inside a window at time ``t``
when ``t - event time < window``) and says which scenario, seed and log length they came from.
It reads only the default variants, never a held-out one.

    uv run python scripts/benign_maxima.py
"""

import argparse
import ipaddress
import json
import math
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from prohori.schema import Event
from prohori.simulate import SCENARIOS, simulate
from prohori.simulate.evaluate import detect

FAILURES = frozenset({"auth.signin.failure", "ssh.login.failure"})
HOUR = timedelta(hours=1)
DAY = timedelta(hours=24)
SEEDS = range(1, 6)


def account(event: Event) -> str | None:
    """The account a rule counts: ``user.id``, else ``user.name``, else ``user.email_hash``."""
    return event.user.id or event.user.name or event.user.email_hash


def address(event: Event) -> str | None:
    if event.source.ip is not None:
        return str(event.source.ip)
    return event.source.host


def network(event: Event) -> str | None:
    if event.source.ip is None:
        return None
    bits = 24 if event.source.ip.version == 4 else 48
    return str(ipaddress.ip_network((event.source.ip, bits), strict=False))


def existing(event: Event) -> bool:
    return event.event.action in FAILURES and event.event.reason != "unknown_user"


def unknown(event: Event) -> bool:
    return event.event.action == "auth.signin.failure" and event.event.reason == "unknown_user"


@dataclass(frozen=True)
class Measure:
    """One benign quantity: the largest number of distinct ``value``s per ``key`` in a window."""

    name: str
    rule: str
    window: timedelta
    select: Callable[[Event], bool]
    key: Callable[[Event], str | None]
    value: Callable[[Event], str | None]


MEASURES = (
    Measure("addresses per existing account", "PRH-AUTH-005", HOUR, existing, account, address),
    Measure(
        "failures per existing account", "PRH-AUTH-006", DAY, existing, account, lambda e: e.id
    ),
    Measure("existing accounts per network", "PRH-AUTH-007", HOUR, existing, network, account),
    Measure(
        "existing accounts per log", "PRH-AUTH-008", HOUR, existing, lambda e: e.log_source, account
    ),
    Measure("addresses per log", "PRH-AUTH-008", HOUR, existing, lambda e: e.log_source, address),
    Measure(
        "addresses with unknown-account failures per log",
        "PRH-AUTH-009",
        HOUR,
        unknown,
        lambda e: e.log_source,
        address,
    ),
    Measure(
        "failures per account",
        "PRH-AUTH-010",
        HOUR,
        lambda e: e.event.action in FAILURES,
        account,
        lambda e: e.id,
    ),
)


def largest_window(points: Iterable[tuple[datetime, str, str]], window: timedelta) -> int:
    """The most distinct values one key has within any window."""
    by_key: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for when, key, value in points:
        by_key[key].append((when, value))
    best = 0
    for items in by_key.values():
        items.sort()
        start = 0
        for end in range(len(items)):
            while items[end][0] - items[start][0] >= window:
                start += 1
            best = max(best, len({value for _, value in items[start : end + 1]}))
    return best


def measure() -> dict[str, Any]:
    """The benign maxima of every measure over the default variants."""
    found: dict[str, dict[str, Any]] = {
        m.name: {"rule": m.rule, "window_hours": m.window / HOUR, "max": 0, "where": None}
        for m in MEASURES
    }
    for name in sorted(SCENARIOS):
        for seed in SEEDS:
            simulation = simulate(name, seed=seed, variant="default")
            events: list[Event] = []
            detection = detect(simulation, [], events=events)
            labels = [attack for _, attack in simulation.lines]
            benign = [e for e in events if labels[detection.line_of[e.id] - 1] is None]
            minutes = int(simulation.params.get("duration", 0))
            for m in MEASURES:
                points = [
                    (e.timestamp, k, v)
                    for e in benign
                    if m.select(e) and (k := m.key(e)) and (v := m.value(e))
                ]
                value = largest_window(points, m.window)
                if value > found[m.name]["max"]:
                    found[m.name].update(
                        max=value,
                        where={"scenario": name, "seed": seed, "log_minutes": minutes},
                    )
    return {
        "variant": "default",
        "seeds": list(SEEDS),
        "rule": "threshold = ceil(2 x max)",
        "measures": found,
    }


def threshold(maximum: int) -> int:
    """ADR-0036's margin rule."""
    return math.ceil(2 * maximum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args(argv)
    print(json.dumps(measure(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
