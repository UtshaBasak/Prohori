"""Settings and shell snippets shared by the Prohori DAGs.

Every task runs a ``prohori`` or ``dbt`` command from the image's /opt/prohori environment. The
broker, the warehouse and the paths come from the airflow service in pipeline/docker-compose.yml
(PROHORI_KAFKA_BOOTSTRAP, PROHORI_POSTGRES_DSN and the dbt variables), so nothing here is secret.
"""

from datetime import UTC, datetime, timedelta

#: Where jobs write what they produce (a named volume): digests, results, saved models.
OUTPUT = "/opt/prohori-output"
#: The datasets for the nightly evaluation, mounted read-only from the repository's data/.
DATA = "/opt/prohori-data"
#: The interpreter of Prohori's environment (for python -m and inline scripts).
PYTHON = "/opt/prohori/bin/python"

START = datetime(2026, 11, 1, tzinfo=UTC)
DEFAULT_ARGS = {"owner": "prohori", "retries": 1, "retry_delay": timedelta(minutes=2)}
TAGS = ["prohori"]

#: A dbt command on the stack's warehouse; format with command="build" and the like.
DBT = "dbt --no-use-colors {command} --project-dir /opt/prohori-dbt --target postgres"

#: Exit code that makes BashOperator mark a task skipped (its default skip_on_exit_code).
SKIP = 99

# Prints how many events the warehouse holds.
COUNT_EVENTS = (
    f"{PYTHON} -c 'import os, psycopg; "  # noqa: S608 - a fixed query
    'print(psycopg.connect(os.environ["PROHORI_POSTGRES_DSN"])'
    '.execute("SELECT count(*) FROM raw.events").fetchone()[0])'
    "'"
)

# Waits until the warehouse stops changing: the event, alert and incident counts stay the same
# for 90 seconds, which is longer than the incident stage's 60-second idle close.
WAIT_FOR_QUIET_WAREHOUSE = f"""{PYTHON} - <<'PY'
import os, time
import psycopg

def counts():
    with psycopg.connect(os.environ["PROHORI_POSTGRES_DSN"], connect_timeout=10) as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM raw.{{table}}").fetchone()[0]
            for table in ("events", "alerts", "incidents")
        )

last, since, deadline = None, time.monotonic(), time.monotonic() + 1800
while time.monotonic() < deadline:
    now = counts()
    if now != last:
        last, since = now, time.monotonic()
    elif time.monotonic() - since >= 90:
        print("warehouse quiet: events %d, alerts %d, incidents %d" % now)
        break
    time.sleep(10)
else:
    raise SystemExit("the warehouse kept changing for 30 minutes")
PY"""  # noqa: S608 - fixed table names
