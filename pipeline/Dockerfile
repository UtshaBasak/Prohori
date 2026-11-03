# The Prohori image for the Docker stack: the package with the pipeline extra, installed from
# this checkout with the versions pinned in uv.lock. Build context: the repository root.
#   docker build -f pipeline/Dockerfile -t prohori:local .

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM python:3.15.0-slim@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/prohori
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE CHANGELOG.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra pipeline --no-editable

FROM python:3.15.0-slim@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58
# The enrichment cache directory exists in the image so a volume mounted on it is owned by prohori.
RUN useradd --create-home --uid 10001 prohori \
    && install -d -o prohori -g prohori /home/prohori/.cache/prohori
COPY --from=build /opt/prohori /opt/prohori
ENV PATH=/opt/prohori/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PROHORI_CACHE_PATH=/home/prohori/.cache/prohori/enrichment.sqlite
USER prohori
WORKDIR /home/prohori
ENTRYPOINT ["prohori"]
CMD ["--help"]
