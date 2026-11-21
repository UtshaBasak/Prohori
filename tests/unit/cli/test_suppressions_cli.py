# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""``--suppressions`` on detect, incidents, triage and ``rules validate``."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.simulate import simulate, write

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "samples" / "suppressions.yml"
AUTH_LOG = ROOT / "samples" / "logs" / "auth.log"

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

EVERYTHING = """
suppressions:
  - id: lab-network
    rule: "*"
    match:
      - {source.ip|cidr: 0.0.0.0/0}
      - {source.ip|cidr: "::/0"}
    reason: a lab where every source is ours
    owner: lab
    expires: 2099-12-31
"""


def run(*args: str) -> tuple[int, str, str]:
    result = runner.invoke(app, list(args))
    return result.exit_code, _ANSI.sub("", result.stdout), _ANSI.sub("", result.stderr)


@pytest.fixture(scope="module")
def admin_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    simulation = simulate("admin-misuse", seed=1)
    write(simulation, out)
    return out / simulation.scenario.filename


def _file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "suppressions.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_detect_table_counts_and_lists_suppressed_alerts(admin_log: Path) -> None:
    code, out, err = run("detect", str(admin_log), "--suppressions", str(EXAMPLE))
    assert code == ExitCode.ALERTS_FOUND
    assert "Suppressed alerts (1)" in out
    assert "planned-admin-onboarding" in out
    assert re.search(r"alerts suppressed\s+.\s+1", out)
    # The attacker's grant (u-0002) is still an alert.
    assert re.search(r"PRH-ADMIN-001.*user\.id=u-0002", out.replace("\n", " "))
    assert "warning" not in err


def test_detect_json_writes_suppressed_alerts_marked(admin_log: Path) -> None:
    plain_code, plain, _ = run("detect", str(admin_log), "-f", "json")
    code, out, err = run("detect", str(admin_log), "-f", "json", "--suppressions", str(EXAMPLE))
    assert plain_code == code == ExitCode.ALERTS_FOUND
    alerts = [json.loads(line) for line in out.splitlines()]
    marked = [a for a in alerts if "suppression" in a]
    assert len(marked) == 1
    assert marked[0]["detector_id"] == "PRH-ADMIN-001"
    assert marked[0]["suppression"]["id"] == "planned-admin-onboarding"
    # Same alerts, same ids: the file only marks.
    assert [a["id"] for a in alerts] == [json.loads(line)["id"] for line in plain.splitlines()]
    summary = json.loads(err.strip().splitlines()[-1])
    assert summary["alerts"] == len(alerts) - 1
    assert summary["suppressed"] == 1
    assert summary["suppressed_by_entry"] == {"planned-admin-onboarding": {"PRH-ADMIN-001": 1}}
    plain_summary = run("detect", str(admin_log), "-f", "json")[2].strip().splitlines()[-1]
    assert "suppressed" not in json.loads(plain_summary)


def test_detect_exits_zero_when_every_alert_is_suppressed(tmp_path: Path) -> None:
    path = _file(tmp_path, EVERYTHING)
    code, out, _ = run("detect", str(AUTH_LOG), "--year", "2026", "--suppressions", str(path))
    assert code == ExitCode.OK
    assert "No alerts." in out
    assert "Suppressed alerts" in out


def test_an_invalid_file_stops_the_run_with_exit_2(tmp_path: Path) -> None:
    path = _file(tmp_path, "suppressions:\n  - id: x\n    rule: nope\n")
    for command in ("detect", "incidents"):
        code, out, err = run(command, str(AUTH_LOG), "--suppressions", str(path))
        assert code == ExitCode.USAGE
        assert out == ""
        assert "INVALID" in err
        assert "invalid rule id 'nope'" in err
    code, _, err = run("detect", str(AUTH_LOG), "--suppressions", str(tmp_path / "missing.yml"))
    assert code == ExitCode.USAGE
    assert "not found" in err


def test_expired_entries_and_unknown_rules_warn(tmp_path: Path, admin_log: Path) -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace("2027-06-30", "2020-01-01")
    text += (
        "  - id: typo\n    rule: PRH-ADMN-001\n    match: {user.id: u-1}\n"
        "    reason: a typo\n    owner: me\n    expires: 2099-01-01\n"
    )
    code, out, err = run("detect", str(admin_log), "--suppressions", str(_file(tmp_path, text)))
    assert code == ExitCode.ALERTS_FOUND
    assert "warning: suppression 'planned-admin-onboarding' expired on 2020-01-01" in err
    assert "names rule 'PRH-ADMN-001', which is not loaded" in err
    # Expired before the simulated grant (2026): it does not apply.
    assert "Suppressed alerts" not in out


def test_incidents_keep_suppressed_alerts_out(admin_log: Path) -> None:
    _, _, plain_err = run("incidents", str(admin_log), "-f", "json", "--no-enrich")
    code, out, err = run(
        "incidents", str(admin_log), "-f", "json", "--no-enrich", "--suppressions", str(EXAMPLE)
    )
    assert code == ExitCode.ALERTS_FOUND
    plain = json.loads(plain_err.strip().splitlines()[-1])
    summary = json.loads(err.strip().splitlines()[-1])
    assert summary["suppressed"] == 1
    assert summary["alerts"] == plain["alerts"] - 1
    assert summary["incidents"] == plain["incidents"] - 1
    incidents = [json.loads(line) for line in out.splitlines()]
    assert not any("suppression" in a for i in incidents for a in i["alerts"])
    # The attack's grant is still in an incident.
    assert any(
        a["detector_id"] == "PRH-ADMIN-001" and a["entities"].get("user.id") == "u-0002"
        for i in incidents
        for a in i["alerts"]
    )


def test_triage_summary_lists_suppressions_without_entities(
    admin_log: Path, tmp_path: Path
) -> None:
    out_dir = tmp_path / "triage"
    code, out, _ = run(
        "triage",
        str(admin_log),
        "--out",
        str(out_dir),
        "--no-enrich",
        "--redact",
        "--suppressions",
        str(EXAMPLE),
    )
    assert code == ExitCode.ALERTS_FOUND
    assert "1 suppressed" in out
    summary = (out_dir / "summary.md").read_text(encoding="utf-8")
    assert "1 alert(s) were suppressed and kept out of the incidents" in summary
    assert "| `planned-admin-onboarding` | `PRH-ADMIN-001` | 1 | 2027-06-30 |\n" in summary
    assert "u-0001" not in summary  # the reason names the account; a redacted run leaves it out
    code, _, _ = run(
        "triage",
        str(admin_log),
        "--out",
        str(out_dir),
        "--no-enrich",
        "--suppressions",
        str(EXAMPLE),
    )
    summary = (out_dir / "summary.md").read_text(encoding="utf-8")
    assert "Planned onboarding of administrators by u-0001" in summary
    assert "| security-team |" in summary


def test_rules_validate_checks_the_suppressions_file(tmp_path: Path) -> None:
    code, out, _ = run("rules", "validate", "--suppressions", str(EXAMPLE))
    assert code == ExitCode.OK
    assert "(suppressions)" in out
    assert "OK" in out.splitlines()[-1]
    bad = _file(tmp_path, "suppressions:\n  - id: x\n")
    code, out, _ = run("rules", "validate", "--suppressions", str(bad))
    assert code == ExitCode.USAGE
    assert "INVALID" in out
    assert "reason: Field required" in out
    code, out, _ = run("rules", "validate", "-f", "json", "--suppressions", str(bad))
    assert code == ExitCode.USAGE
    rows = json.loads(out)
    assert rows[-1]["kind"] == "suppressions"
    assert rows[-1]["valid"] is False


def test_rules_validate_warns_about_rules_it_did_not_validate(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "one.yml").write_text(
        (ROOT / "src/prohori/rules/builtin/brute-force.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    code, out, _ = run("rules", "validate", str(rules), "--suppressions", str(EXAMPLE))
    assert code == ExitCode.OK
    assert "names rule 'PRH-ADMIN-001', which is not loaded" in out
