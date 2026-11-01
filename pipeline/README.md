# Pipeline

The Docker stack for pipeline mode and what it is built from. A file-based "lite mode" runs the
same stages without Docker.

| Path | What it is | Docs |
|------|------------|------|
| `docker-compose.yml` | Redpanda, PostgreSQL, one container per stage, Grafana | [PIPELINE.md](../docs/PIPELINE.md) |
| `Dockerfile` | The `prohori:local` image the stage containers run | [PIPELINE.md](../docs/PIPELINE.md) |
| `postgres/` | Schemas and Grafana's read-only role, set up on every start | [DASHBOARD.md](../docs/DASHBOARD.md) |
| `grafana/` | Provisioned data source and dashboards | [DASHBOARD.md](../docs/DASHBOARD.md) |
| `dbt/` | Warehouse models and data-quality checks | [WAREHOUSE.md](../docs/WAREHOUSE.md) |

```bash
uv run prohori pipeline up        # then open http://127.0.0.1:13000
```
