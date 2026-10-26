"""The simulator: determinism, documentation addresses, labels, parameters and output files."""

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path

import pytest

from prohori.parsers import ParseStats, get_parser, iter_text_lines
from prohori.simulate import (
    SCENARIOS,
    VARIANTS,
    AddressPool,
    SimulationError,
    is_documentation,
    resolve_params,
    simulate,
    write,
)
from prohori.simulate import model as model_module

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "golden" / "simulate"
#: Set PROHORI_UPDATE_GOLDEN=1 to rewrite the golden files after an intended output change.
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"
RUNS = [(name, variant) for name in sorted(SCENARIOS) for variant in VARIANTS]

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])")


@pytest.mark.parametrize(("name", "variant"), RUNS)
def test_same_seed_gives_identical_output(name: str, variant: str) -> None:
    first = simulate(name, seed=3, variant=variant)
    second = simulate(name, seed=3, variant=variant)
    assert first.log_text() == second.log_text()
    assert first.labels_text() == second.labels_text()
    assert simulate(name, seed=4, variant=variant).log_text() != first.log_text()


def test_output_matches_golden_hashes() -> None:
    """Catches changes in the generated logs, including across Python versions."""
    hashes = {
        f"{name}/{variant}": hashlib.sha256(
            simulate(name, seed=1, variant=variant).log_text().encode()
        ).hexdigest()
        for name, variant in RUNS
    }
    path = GOLDEN / "hashes.json"
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8", newline="\n")
    assert hashes == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(("name", "variant"), RUNS)
def test_every_address_is_a_documentation_address(name: str, variant: str) -> None:
    for seed in (1, 2):
        simulation = simulate(name, seed=seed, variant=variant)
        text = simulation.log_text()
        found = set(_IPV4.findall(text))
        for candidate in _IPV6.findall(text):
            try:
                found.add(str(ipaddress.IPv6Address(candidate)))
            except ValueError:
                continue
        assert found, name
        outside = sorted(ip for ip in found if not is_documentation(ip))
        assert outside == [], (name, variant, seed)


@pytest.mark.parametrize(("name", "variant"), RUNS)
def test_logs_parse_cleanly_and_labels_line_up(name: str, variant: str) -> None:
    simulation = simulate(name, seed=1, variant=variant)
    scenario = simulation.scenario
    options = {"year": simulation.year} if scenario.parser == "auth_log" else {}
    stats = ParseStats()
    lines = simulation.log_text().splitlines()
    events = list(get_parser(scenario.parser, **options).parse(iter_text_lines(lines), stats=stats))
    assert stats.errors == 0, stats.error_examples
    assert events
    assert all(e.source.ip is None or is_documentation(str(e.source.ip)) for e in events)
    labels = [json.loads(line) for line in simulation.labels_text().splitlines()]
    assert [label["line"] for label in labels] == list(range(1, len(lines) + 1))
    attack_ids = {a.id for a in simulation.attacks}
    assert {label["attack"] for label in labels} == attack_ids | {None}
    times = [e.timestamp for e in events]
    assert times == sorted(times)  # written in time order


def test_expected_rules_are_built_in_rules() -> None:
    from prohori.rules import builtin_rules_dir, load_rules

    ids = {r.rule.id for r in load_rules([builtin_rules_dir()]) if r.rule}
    for name, variant in RUNS:
        for attack in simulate(name, seed=0, variant=variant).attacks:
            assert set(attack.expected_rules) <= ids, attack.id
            assert attack.expected_rules == simulate(name, seed=0).attacks[0].expected_rules


def test_parameters_are_validated() -> None:
    scenario = SCENARIOS["ssh-bruteforce"]
    params, start = resolve_params(scenario, "default", {"rate": "5", "attempts": "10"})
    assert (params["rate"], params["attempts"], start) == (5.0, 10, "2026-10-24T08:00:00Z")
    assert isinstance(params["attempts"], int)
    _, start = resolve_params(scenario, "default", {"start": "2026-01-02T03:04:05+06:00"})
    assert start == "2026-01-02T03:04:05+06:00"
    for overrides, message in [
        ({"rate": "fast"}, "must be a number"),
        ({"attempts": "1.5"}, "must be an integer"),
        ({"sources": "0"}, "between 1 and 50"),
        ({"users": "10"}, "has no parameter 'users'"),
        ({"start": "yesterday"}, "invalid start time"),
        ({"start": "2026-10-24T08:00:00"}, "needs a timezone"),
    ]:
        with pytest.raises(SimulationError, match=message):
            resolve_params(scenario, "default", overrides)
    with pytest.raises(SimulationError, match="unknown variant"):
        resolve_params(scenario, "evil", {})
    with pytest.raises(SimulationError, match="unknown scenario 'nope'"):
        simulate("nope", seed=1)


def test_parameters_change_the_attack() -> None:
    small = simulate("account-takeover", seed=1, overrides={"attempts": "3"})
    large = simulate("account-takeover", seed=1, overrides={"attempts": "30"})
    attack_lines = [sum(1 for _, a in run.lines if a) for run in (small, large)]
    assert attack_lines[1] - attack_lines[0] == 27


def test_line_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model_module, "MAX_LINES", 100)
    with pytest.raises(SimulationError, match="more than 100 lines"):
        simulate("web-scanning", seed=1)


def test_write_creates_log_labels_and_manifest(tmp_path: Path) -> None:
    simulation = simulate("ssh-bruteforce", seed=1)
    manifest = write(simulation, tmp_path / "out")
    files = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert files == ["manifest.json", "ssh-bruteforce.labels.jsonl", "ssh-bruteforce.log"]
    stored = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert stored == manifest
    log = (tmp_path / "out" / "ssh-bruteforce.log").read_bytes()
    assert stored["files"]["log"]["sha256"] == hashlib.sha256(log).hexdigest()
    assert b"\r\n" not in log
    assert stored["year"] == 2026
    assert stored["parser"] == "auth_log"
    assert stored["attacks"][0]["expected_rules"] == ["PRH-AUTH-001", "PRH-SSH-001"]
    assert str(tmp_path) not in json.dumps(stored)  # no absolute paths


def test_address_pool_only_hands_out_documentation_addresses() -> None:
    import random

    pool = AddressPool(random.Random(1))  # noqa: S311 - test of reproducible simulation
    addresses = [pool.take("203.0.113.0/24") for _ in range(50)] + [pool.take("2001:db8::/32")]
    assert len(set(addresses)) == len(addresses)
    assert all(is_documentation(a) for a in addresses)
    with pytest.raises(ValueError, match="not a documentation range"):
        pool.take("10.0.0.0/8")
    tiny = AddressPool(random.Random(1))  # noqa: S311
    with pytest.raises(ValueError, match="no free address"):
        tiny.take_many("192.0.2.0/24", 300)
    assert not is_documentation("8.8.8.8")
    assert not is_documentation("2001:db9::1")
