"""End to end: simulator -> triage -> incidents, checked against the simulator's ground truth."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.schema import Incident
from prohori.simulate import SCENARIOS, simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

runner = CliRunner(env={"COLUMNS": "120", "NO_COLOR": "1"})


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_expected_rule_lands_in_an_incident_about_the_attacker(
    name: str, tmp_path: Path
) -> None:
    simulation = simulate(name, seed=1)
    write(simulation, tmp_path / "logs")
    scenario = simulation.scenario
    args = [
        "triage",
        str(tmp_path / "logs" / scenario.filename),
        "-o",
        str(tmp_path / "out"),
        "-f",
        "md",
        "--parser",
        scenario.parser,
    ]
    if scenario.parser == "auth_log":
        args += ["--year", str(simulation.year)]
    result = runner.invoke(app, args)
    assert result.exit_code == 3, result.output
    incidents = [
        Incident.model_validate_json(line)
        for line in (tmp_path / "out" / "incidents.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    for attack in simulation.attacks:
        attackers = set(attack.sources)
        about_attacker = [i for i in incidents if attackers & set(i.entities.get("source.ip", ()))]
        assert about_attacker, f"{name}: no incident involves {sorted(attackers)}"
        fired = {a.detector_id for i in about_attacker for a in i.alerts}
        assert set(attack.expected_rules) <= fired, (name, sorted(fired))
        # Each incident about the attacker has a report; the most severe is medium or above.
        assert all((tmp_path / "out" / f"{i.id}.md").is_file() for i in about_attacker)
        top = max(about_attacker, key=lambda i: i.score)
        assert top.severity.rank >= 2


def test_benign_background_alone_raises_no_attack_rules(tmp_path: Path) -> None:
    """Without the attack, the SSH background raises nothing (the attack causes the alerts)."""
    simulation = simulate("ssh-bruteforce", seed=1, overrides={"attempts": "1"})
    write(simulation, tmp_path)
    result = runner.invoke(
        app,
        [
            "triage", str(tmp_path / "ssh-bruteforce.log"), "--parser", "auth_log",
            "--year", "2026", "-o", str(tmp_path / "out"), "--exit-zero",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert (tmp_path / "out" / "incidents.jsonl").read_text(encoding="utf-8") == ""
