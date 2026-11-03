"""The Airflow DAG files, checked without Airflow: they call commands and scenarios that exist.

The import and cycle checks need Airflow and run in CI on Linux (tests/dags).
"""

import ast
import re
from pathlib import Path

import pytest
import yaml

from prohori.cli.pipeline import pipeline_app
from prohori.simulate import SCENARIOS

ROOT = Path(__file__).resolve().parents[3]
DAGS = ROOT / "pipeline" / "airflow" / "dags"
FILES = sorted(DAGS.glob("prohori_*.py"))


def _strings(path: Path) -> list[str]:
    return [
        node.value
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_dag_files() -> None:
    assert [p.stem for p in FILES] == [
        "prohori_backfill",
        "prohori_common",
        "prohori_data_quality",
        "prohori_enrichment_refresh",
        "prohori_incident_digest",
        "prohori_nightly_evaluation",
    ]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_commands_exist(path: Path) -> None:
    commands = {c.name for c in pipeline_app.registered_commands}
    for text in _strings(path):
        for used in re.findall(r"prohori pipeline ([a-z-]+)", text):
            assert used in commands, f"{path.name}: prohori pipeline {used}"


def test_backfill_covers_every_scenario() -> None:
    tree = ast.parse((DAGS / "prohori_backfill.py").read_text(encoding="utf-8"))
    names = next(
        ast.literal_eval(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "SCENARIOS" for t in node.targets)
    )
    assert list(names) == sorted(SCENARIOS)


def test_paths_match_the_compose_file() -> None:
    airflow = yaml.safe_load((ROOT / "pipeline" / "docker-compose.yml").read_text("utf-8"))[
        "services"
    ]["airflow"]
    mounts = {v.split(":")[1] for v in airflow["volumes"]}
    common = "\n".join(_strings(DAGS / "prohori_common.py"))
    for path in ("/opt/prohori-output", "/opt/prohori-data", "/opt/prohori-dbt"):
        assert path in mounts
        assert path in common
    assert airflow["environment"]["DBT_PROFILES_DIR"] == "/opt/prohori-dbt"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_parameters_never_reach_a_script(path: Path) -> None:
    # Run parameters are typed by whoever triggers the DAG; pasted into a bash script, a string
    # parameter could inject commands. They go through env= and are quoted as "$NAME" instead.
    for text in _strings(path):
        if "\n" in text or text.startswith(("prohori ", "dbt ")):
            assert "params." not in text, path.name
            assert "xcom_pull" not in text, path.name
