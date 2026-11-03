# Airflow for the Docker stack's orchestration profile, with Prohori and dbt in their own
# environment (/opt/prohori) so Airflow's dependencies and Prohori's never mix. The DAGs and the
# dbt project are mounted at run time. Build context: the repository root.
#   docker compose -p prohori -f pipeline/docker-compose.yml --profile orchestration build airflow

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM apache/airflow:slim-3.3.2-python3.13@sha256:881c35bfb1f6b76d233dd402b7228b5c37003702068b865db5db76061458b2bd

# The PostgreSQL drivers for Airflow's own database, at the versions in Airflow 3.3.2's
# constraints file, pinned by hash and installed without dependencies (they have none).
COPY pipeline/airflow/requirements.txt /tmp/airflow-requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes -r /tmp/airflow-requirements.txt

USER root
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/prohori
WORKDIR /tmp/prohori-src
COPY pyproject.toml uv.lock README.md LICENSE CHANGELOG.md ./
COPY src ./src
# The pipeline extra (Kafka, PostgreSQL), the ml extra (nightly evaluation) and dbt.
RUN uv sync --frozen --no-dev --extra pipeline --extra ml --group dbt --no-editable \
        --python /usr/local/bin/python \
    && rm -rf /tmp/prohori-src /root/.cache \
    # Job output and the enrichment cache shared with the incidents stage (uid 10001, group 0).
    && mkdir -p /opt/prohori-output /opt/prohori-cache \
    && chown 10001:0 /opt/prohori-output /opt/prohori-cache \
    && chmod 2775 /opt/prohori-output /opt/prohori-cache

ENV PATH=$PATH:/opt/prohori/bin
WORKDIR /opt/airflow
# Runs as the stage containers' uid with group 0, which the Airflow image supports, so both can
# write the shared volumes.
USER 10001:0
