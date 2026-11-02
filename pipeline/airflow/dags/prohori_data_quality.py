"""Data quality: rebuild the dbt models with their checks, then check the inputs are fresh.

Every hour: ``dbt build`` on the stack's warehouse (the marts behind the "Detection quality"
dashboard, and the 68 checks), then ``dbt source freshness`` on the events, which fails when no
new event arrived for 7 days (and warns after 1). An empty warehouse skips the freshness check:
nothing has been published yet, which is not stale data.
"""

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG, chain
from prohori_common import COUNT_EVENTS, DBT, DEFAULT_ARGS, SKIP, START, TAGS

FRESHNESS = f"""set -euo pipefail
if [ "$({COUNT_EVENTS})" = 0 ]; then
    echo "no events stored yet (skipping)"
    exit {SKIP}
fi
{DBT.format(command="source freshness --select source:prohori.events")}
"""

with DAG(
    dag_id="prohori_data_quality",
    description="Build the dbt models and run the data-quality and freshness checks",
    doc_md=__doc__,
    schedule="@hourly",
    start_date=START,
    catchup=False,
    max_active_runs=1,
    default_args=DEFAULT_ARGS,
    tags=[*TAGS, "dbt"],
) as dag:
    build = BashOperator(task_id="dbt_build", bash_command=DBT.format(command="build"))
    fresh = BashOperator(task_id="source_freshness", bash_command=FRESHNESS, retries=0)
    chain(build, fresh)
