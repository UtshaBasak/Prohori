"""Nightly evaluation: retrain the flow models, record the results and fail if recall dropped.

Trains the cleaned UNSW-NB15 models with one seed (``prohori.ml.train``), loads the results into
the warehouse (the "Flow models" panels and ``marts.model_performance``), then runs
``prohori pipeline check-recall``: the run fails when the gradient-boosting model's mean recall at
a 1 % false-positive rate falls below ``min_recall``. The dataset is not part of the repository;
without data/raw/unsw-nb15/ (scripts/download_datasets.py) the run is skipped.
"""

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG, Param, chain
from prohori_common import DATA, DEFAULT_ARGS, OUTPUT, PYTHON, SKIP, START, TAGS

# The results file's path is the task's last line of output, which later tasks read from XCom.
TRAIN = f"""set -euo pipefail
if [ ! -d {DATA}/raw/unsw-nb15 ]; then
    echo "{DATA}/raw/unsw-nb15 not found: download the dataset to evaluate (skipping)"
    exit {SKIP}
fi
out={OUTPUT}/results/ml_unsw-nb15-$(date -u +%Y%m%dT%H%M%SZ).json
{PYTHON} -m prohori.ml.train --dataset unsw-nb15 --variants cleaned \\
    --seeds {{{{ params.seed }}}} --data-dir {DATA} --no-cache \\
    --models-dir {OUTPUT}/models --out "$out" >&2
echo "$out"
"""
RESULTS = "{{ ti.xcom_pull(task_ids='train') }}"

with DAG(
    dag_id="prohori_nightly_evaluation",
    description="Retrain and evaluate the flow models; fail if recall drops",
    doc_md=__doc__,
    schedule="0 2 * * *",
    start_date=START,
    catchup=False,
    max_active_runs=1,
    default_args=DEFAULT_ARGS,
    tags=[*TAGS, "ml"],
    params={
        "seed": Param(0, type="integer", minimum=0, description="Training seed"),
        "min_recall": Param(
            0.75,
            type="number",
            minimum=0,
            maximum=1,
            description="Fail below this mean recall (hgb, cleaned, 1 % false-positive rate)",
        ),
    },
) as dag:
    train = BashOperator(
        task_id="train", bash_command=TRAIN, skip_on_exit_code=SKIP, do_xcom_push=True
    )
    record = BashOperator(
        task_id="load_results",
        bash_command=(
            f'prohori pipeline load-results "{RESULTS}" --postgres "$PROHORI_POSTGRES_DSN"'
        ),
    )
    gate = BashOperator(
        task_id="check_recall",
        bash_command=(
            f'prohori pipeline check-recall "{RESULTS}" '
            "--min-recall {{ params.min_recall }} --model hgb --variant cleaned "
            "--operating-point fpr_0.01"
        ),
        retries=0,
    )
    chain(train, record, gate)
