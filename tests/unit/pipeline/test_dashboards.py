"""The provisioned Grafana dashboards: valid, on the provisioned data source, on real tables."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from prohori.pipeline.tables import TABLES

ROOT = Path(__file__).resolve().parents[3]
GRAFANA = ROOT / "pipeline" / "grafana"
DASHBOARDS = sorted((GRAFANA / "dashboards").glob("*.json"))
MARTS = {p.stem for p in (ROOT / "pipeline" / "dbt" / "models" / "marts").glob("*.sql")}
COMPOSE = ROOT / "pipeline" / "docker-compose.yml"


def _datasource() -> dict[str, Any]:
    path = GRAFANA / "provisioning" / "datasources" / "prohori.yml"
    sources: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8"))["datasources"]
    assert len(sources) == 1
    return sources[0]


def _load(path: Path) -> dict[str, Any]:
    board: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return board


def test_there_are_three_dashboards_with_unique_uids() -> None:
    names = [p.name for p in DASHBOARDS]
    assert names == ["detection-quality.json", "overview.json", "pipeline-health.json"]
    uids = [_load(p)["uid"] for p in DASHBOARDS]
    assert len(set(uids)) == len(uids)
    assert all(u.startswith("prohori-") for u in uids)


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.stem)
def test_dashboard_panels(path: Path) -> None:
    board = _load(path)
    source = _datasource()
    assert board["timezone"] == "utc"
    assert board["editable"] is False
    panels = board["panels"]
    assert len({p["id"] for p in panels}) == len(panels)
    for panel in panels:
        grid = panel["gridPos"]
        assert grid["x"] + grid["w"] <= 24, panel["title"]
        assert panel.get("description") or panel["type"] == "text", panel["title"]
        for target in panel.get("targets", []):
            assert target["datasource"] == {"type": source["type"], "uid": source["uid"]}
            assert target["rawQuery"] is True
            assert target["rawSql"].strip(), panel["title"]


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.stem)
def test_queries_read_existing_tables_only(path: Path) -> None:
    for panel in _load(path)["panels"]:
        for target in panel.get("targets", []):
            sql = target["rawSql"]
            tables = re.findall(r"\b(raw|marts)\.([a-z_]+)\b", sql)
            assert tables, panel["title"]
            for schema, name in tables:
                assert name in (TABLES if schema == "raw" else MARTS), f"{schema}.{name}"
            # Read-only, and no statement chaining.
            assert ";" not in sql
            assert not re.search(r"\b(insert|update|delete|drop|alter|create|grant)\b", sql, re.I)


def test_compose_mounts_the_provisioning_and_reader_role() -> None:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    grafana = services["grafana"]
    assert "./grafana/provisioning:/etc/grafana/provisioning:ro" in grafana["volumes"]
    assert "./grafana/dashboards:/etc/grafana/dashboards:ro" in grafana["volumes"]
    home = grafana["environment"]["GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH"]
    assert (GRAFANA / "dashboards" / Path(home).name).is_file()
    assert grafana["environment"]["GF_ANALYTICS_REPORTING_ENABLED"] == "false"
    assert _datasource()["user"] == "grafana"
    init = (ROOT / "pipeline" / "postgres" / "warehouse-init.sql").read_text(encoding="utf-8")
    assert "GRANT SELECT ON TABLES TO grafana" in init
    assert "superuser" not in init.lower().replace("nosuperuser", "")
