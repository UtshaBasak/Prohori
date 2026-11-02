"""Daily incident digest: what the pipeline stored in the last 24 hours, as Markdown and JSON.

Writes ``digests/incidents-YYYY-MM-DD.md`` and ``.json`` to the airflow-output volume; copy them
out with ``docker compose ... cp airflow:/opt/prohori-output/digests .`` (docs/ORCHESTRATION.md).
"""

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG
from prohori_common import DEFAULT_ARGS, OUTPUT, START, TAGS

DIGEST = f"""set -euo pipefail
name={OUTPUT}/digests/incidents-$(date -u +%Y-%m-%d)
prohori pipeline digest --hours 24 --postgres "$PROHORI_POSTGRES_DSN" --out "$name.md"
prohori pipeline digest --hours 24 --postgres "$PROHORI_POSTGRES_DSN" -f json --out "$name.json"
"""

with DAG(
    dag_id="prohori_incident_digest",
    description="Write a digest of the last day's incidents",
    doc_md=__doc__,
    schedule="0 6 * * *",
    start_date=START,
    catchup=False,
    max_active_runs=1,
    default_args=DEFAULT_ARGS,
    tags=[*TAGS, "report"],
) as dag:
    BashOperator(task_id="write_digest", bash_command=DIGEST)
