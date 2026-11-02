"""Enrichment refresh: keep the incident stage's enrichment cache current.

Daily: removes expired answers from the cache the incident stage reads (a volume both
containers mount) and looks up again the public addresses seen in the last week. Online lookups
happen only when ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY is set for the stack; otherwise nothing
leaves the machine.
"""

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG
from prohori_common import DEFAULT_ARGS, START, TAGS

REFRESH = """set -euo pipefail
mode=()
if [ -n "${ABUSEIPDB_API_KEY:-}${VIRUSTOTAL_API_KEY:-}" ]; then mode=(--online); fi
prohori pipeline refresh-enrichment --days 7 --postgres "$PROHORI_POSTGRES_DSN" "${mode[@]}"
"""

with DAG(
    dag_id="prohori_enrichment_refresh",
    description="Refresh the enrichment cache for recently seen addresses",
    doc_md=__doc__,
    schedule="30 3 * * *",
    start_date=START,
    catchup=False,
    max_active_runs=1,
    default_args=DEFAULT_ARGS,
    tags=[*TAGS, "enrichment"],
) as dag:
    BashOperator(task_id="refresh_cache", bash_command=REFRESH)
