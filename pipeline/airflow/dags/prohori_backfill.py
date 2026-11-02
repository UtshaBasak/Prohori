"""Backfill: simulate every scenario one day apart, replay them, then build the marts.

Run it by hand on an empty stack (Trigger DAG). Each scenario is simulated with the run's seed,
starting ``start`` plus one day per scenario (default: eight days ago), replayed through the
broker, and its labels are loaded so the marts can measure precision and time to detect. Older
logs replayed after newer ones arrive late (see "One timeline" in docs/PIPELINE.md), so use it
on a stack without newer events.
"""

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG, Param, chain
from prohori_common import DBT, DEFAULT_ARGS, PYTHON, START, TAGS, WAIT_FOR_QUIET_WAREHOUSE

SCENARIOS = (
    "account-takeover",
    "admin-misuse",
    "credential-stuffing",
    "injection",
    "password-spraying",
    "ssh-bruteforce",
    "token-reuse",
    "web-scanning",
)

# Simulates one scenario, replays it into the broker and loads its labels, with the parser and
# year the simulator recorded in manifest.json.
REPLAY = """set -euo pipefail
when=$({python} -c '
import sys
from datetime import UTC, datetime, timedelta
start = sys.argv[1] or (datetime.now(UTC) - timedelta(days=8)).strftime("%Y-%m-%dT06:00:00Z")
moment = datetime.fromisoformat(start.replace("Z", "+00:00")) + timedelta(days=int(sys.argv[2]))
print(moment.strftime("%Y-%m-%dT%H:%M:%SZ"))
' "{{{{ params.start }}}}" {day})
dir="$(mktemp -d)/{scenario}"
prohori simulate {scenario} --seed {{{{ params.seed }}}} --set start="$when" --out "$dir"
read -r name parser year < <({python} -c '
import json, sys
m = json.load(open(sys.argv[1]))
print(m["files"]["log"]["name"], m["parser"], m["year"])
' "$dir/manifest.json")
options=(--parser "$parser" --year "$year")
prohori pipeline replay "$dir/$name" "${{options[@]}}" --bootstrap "$PROHORI_KAFKA_BOOTSTRAP"
prohori pipeline load-labels "$dir/$name" "${{options[@]}}" --postgres "$PROHORI_POSTGRES_DSN"
rm -rf "$dir"
"""

with DAG(
    dag_id="prohori_backfill",
    description="Simulate every scenario one day apart and replay them into the stack",
    doc_md=__doc__,
    schedule=None,
    start_date=START,
    catchup=False,
    max_active_runs=1,
    default_args=DEFAULT_ARGS,
    tags=[*TAGS, "backfill"],
    params={
        "start": Param(
            "",
            type="string",
            description="First scenario's start, such as 2026-10-25T06:00:00Z (empty: 8 days ago)",
        ),
        "seed": Param(1, type="integer", minimum=0, description="Simulator seed"),
    },
) as dag:
    replays = [
        BashOperator(
            task_id=f"replay_{scenario.replace('-', '_')}",
            bash_command=REPLAY.format(python=PYTHON, scenario=scenario, day=day),
        )
        for day, scenario in enumerate(SCENARIOS)
    ]
    settle = BashOperator(task_id="wait_for_the_pipeline", bash_command=WAIT_FOR_QUIET_WAREHOUSE)
    build = BashOperator(task_id="build_marts", bash_command=DBT.format(command="build"))
    chain(*replays, settle, build)
