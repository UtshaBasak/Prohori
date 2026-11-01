"""DAG integrity: every DAG in pipeline/airflow/dags imports, has no cycle and is configured.

Needs Apache Airflow, which is not a Prohori dependency (and does not run on Windows), so the
module is skipped without it. CI runs it on Linux in the "Airflow DAGs" job (see ci.yml for the
install command): Airflow 3.3.2 with its constraints file in a separate environment, then

    python -m pytest tests/dags -p no:cacheprovider -o addopts= --confcutdir tests/dags
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DAGS = ROOT / "pipeline" / "airflow" / "dags"

os.environ["AIRFLOW__CORE__LOAD_EXAMPLES"] = "False"  # before Airflow reads its configuration
pytest.importorskip("airflow", reason="Apache Airflow is not installed (Linux CI job only)")

EXPECTED = {
    "prohori_backfill": None,
    "prohori_nightly_evaluation": "0 2 * * *",
    "prohori_incident_digest": "0 6 * * *",
    "prohori_data_quality": "@hourly",
    "prohori_enrichment_refresh": "30 3 * * *",
}


@pytest.fixture(scope="module")
def dagbag() -> Iterator[Any]:
    sys.path.insert(0, str(DAGS))  # Airflow puts the DAG folder on the path the same way
    try:
        from airflow.dag_processing.dagbag import DagBag
    except ImportError:  # older layout
        from airflow.models.dagbag import DagBag
    try:
        yield DagBag(dag_folder=str(DAGS))
    finally:
        sys.path.remove(str(DAGS))


def _has_cycle(dag: Any) -> bool:
    state: dict[str, int] = {}

    def visit(task_id: str) -> bool:
        if state.get(task_id) == 1:
            return True
        if state.get(task_id) == 2:  # visited
            return False
        state[task_id] = 1
        found = any(visit(n) for n in dag.get_task(task_id).downstream_task_ids)
        state[task_id] = 2
        return found

    return any(visit(task_id) for task_id in dag.task_ids)


def test_every_dag_imports(dagbag: Any) -> None:
    assert dagbag.import_errors == {}
    assert set(dagbag.dag_ids) == set(EXPECTED)


@pytest.mark.parametrize("dag_id", sorted(EXPECTED))
def test_dag_settings(dagbag: Any, dag_id: str) -> None:
    dag = dagbag.dags[dag_id]
    assert not _has_cycle(dag)
    assert dag.schedule == EXPECTED[dag_id]
    assert dag.catchup is False
    assert dag.max_active_runs == 1
    assert "prohori" in dag.tags
    assert dag.doc_md
    for task in dag.tasks:
        command = task.bash_command
        assert command.strip()
        assert "prohori" in command or command.startswith("dbt ")


def test_pipeline_shapes(dagbag: Any) -> None:
    backfill = dagbag.dags["prohori_backfill"]
    assert len(backfill.tasks) == 10  # eight scenarios, the wait and the dbt build
    assert backfill.get_task("build_marts").upstream_task_ids == {"wait_for_the_pipeline"}
    nightly = dagbag.dags["prohori_nightly_evaluation"]
    assert nightly.get_task("train").skip_on_exit_code == [99]
    assert nightly.get_task("check_recall").upstream_task_ids == {"load_results"}
    quality = dagbag.dags["prohori_data_quality"]
    assert quality.get_task("source_freshness").upstream_task_ids == {"dbt_build"}
