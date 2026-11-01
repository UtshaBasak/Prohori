# The Prohori image for the Docker stack: the package with the pipeline extra, installed from
# this checkout with the versions pinned in uv.lock. Build context: the repository root.
#   docker build -f pipeline/Dockerfile -t prohori:local .

FROM ghcr.io/astral-sh/uv:0.11.6@sha256:b1e699368d24c57cda93c338a57a8c5a119009ba809305cc8e86986d4a006754 AS uv

FROM python:3.13.18-slim@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/prohori
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE CHANGELOG.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra pipeline --no-editable

FROM python:3.13.18-slim@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5
RUN useradd --create-home --uid 10001 prohori
COPY --from=build /opt/prohori /opt/prohori
ENV PATH=/opt/prohori/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PROHORI_CACHE_PATH=/home/prohori/.cache/prohori/enrichment.sqlite
USER prohori
WORKDIR /home/prohori
ENTRYPOINT ["prohori"]
CMD ["--help"]
