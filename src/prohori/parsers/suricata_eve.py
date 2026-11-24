# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Parser for Suricata EVE JSON (``eve.json``), one record per line.

The layout follows the Suricata 7.0 EVE documentation and the 8.0 changes to the same fields
(DNS logging version 3 with a ``queries`` list). Records of the types ``alert``, ``http``,
``dns``, ``tls``, ``ssh`` and ``flow`` become events; other types (``stats``, ``fileinfo``,
``anomaly``, ``netflow``, ...) are counted as skipped.

=========  ===================  ==========  ===============================================
Type       ``event.action``     Category    Notes
=========  ===================  ==========  ===============================================
alert      ``ids.alert``        network     severity 1 -> high, 2 -> medium, 3+ -> low
http       ``web.request``      web         the same fields as ``access_log``, so web rules apply
dns        ``network.dns``      network     query name, type and response code
tls        ``network.tls``      network     SNI, version, subject, issuer, JA3/JA3S hashes
ssh        ``network.ssh``      network     client and server software banners
flow       ``network.flow``     network     bytes, packets and duration per direction
=========  ===================  ==========  ===============================================

Every event carries the connection fields in ``extra`` with the same keys as ``zeek_conn``
(see :mod:`prohori.parsers.network`). A ``flow`` event is dated at its last packet
(``flow.end``), like Zeek connections, because the record is written when the flow ends.
"""

from datetime import datetime
from typing import Any

from prohori.parsers.base import LineParser, ParseError
from prohori.parsers.network import (
    address,
    as_count,
    as_float,
    as_port,
    checked_duration,
    compact,
    iso_utc,
    parse_iso,
    transport,
)
from prohori.parsers.registry import register
from prohori.parsers.util import as_text, load_json_object, normalise_host
from prohori.schema import Event, event_id

#: Suricata alert severity (1 is the most severe) -> event severity.
SEVERITY = {1: "high", 2: "medium"}
#: Severity for 3 and above (Suricata's priority scale goes to 255 in custom classifications).
LOW_SEVERITY = "low"

_ACTIONS = {
    "alert": ("ids.alert", "network"),
    "http": ("web.request", "web"),
    "dns": ("network.dns", "network"),
    "tls": ("network.tls", "network"),
    "ssh": ("network.ssh", "network"),
    "flow": ("network.flow", "network"),
}
#: Signature metadata keys copied to ``extra`` (lists are joined with commas).
_METADATA_KEYS = ("mitre_technique_id", "mitre_tactic_id", "signature_severity")


def _section(record: dict[str, Any], key: str) -> dict[str, Any]:
    value = record.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ParseError(f"'{key}' is not an object")
    return value


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _joined(value: object) -> str | None:
    if isinstance(value, list):
        items = [as_text(item) for item in value[:16] if not isinstance(item, dict | list)]
        text = ",".join(item for item in items if item)
        return text or None
    if isinstance(value, dict):
        return None
    return as_text(value)


@register
class SuricataEveParser(LineParser):
    """Parse Suricata ``eve.json`` records into events.

    Args:
        log_source: Value for ``log_source``.
        keep_query: Keep the query string in ``http.path`` (as ``access_log --keep-query``).
    """

    name = "suricata_eve"

    def __init__(self, *, log_source: str = "suricata", keep_query: bool = False) -> None:
        self.log_source = log_source
        self.keep_query = keep_query

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        record = load_json_object(line)
        kind = record.get("event_type")
        if not isinstance(kind, str):
            raise ParseError("missing event_type")
        if kind not in _ACTIONS:
            return None
        action, category = _ACTIONS[kind]
        timestamp = parse_iso(record.get("timestamp"))
        extra: dict[str, object] = {
            "destination_ip": address(record.get("dest_ip"), "dest_ip"),
            "destination_port": as_port(record.get("dest_port"), "dest_port"),
            "source_port": as_port(record.get("src_port"), "src_port"),
            "transport": transport(record.get("proto")),
            "app_protocol": as_text(record.get("app_proto")),
            "flow_id": as_text(record.get("flow_id")),
            "interface": as_text(record.get("in_iface")),
        }
        fields: dict[str, Any] = {"outcome": "unknown", "severity": None, "reason": None}
        http: dict[str, Any] = {}
        user_agent: str | None = None
        if kind == "alert":
            fields.update(self._alert(_section(record, "alert"), extra))
        elif kind == "dns":
            self._dns(_section(record, "dns"), extra)
        elif kind == "tls":
            self._tls(_section(record, "tls"), extra)
        elif kind == "ssh":
            self._ssh(_section(record, "ssh"), extra)
        elif kind == "flow":
            timestamp = self._flow(_section(record, "flow"), extra) or timestamp
        if "http" in record and kind in {"http", "alert"}:
            http, user_agent = self._http(_section(record, "http"), extra)
            if kind == "http":
                status = http.get("status")
                if status is not None:
                    fields["outcome"] = "failure" if status >= 400 else "success"
        domain = extra.pop("tls_domain", None) or normalise_host(_str(extra.get("http_host")))
        destination = {
            "ip": extra.pop("destination_ip"),
            "port": extra.pop("destination_port"),
            "domain": domain,
        }
        question = extra.pop("dns_question", None)
        return Event.model_validate(
            {
                "id": event_id(self.log_source, timestamp, line, f"{source}:{number}"),
                "timestamp": timestamp,
                "log_source": self.log_source,
                "event": {"action": action, "category": category, **fields},
                "source": {"ip": address(record.get("src_ip"), "src_ip")},
                "http": http,
                "user_agent": user_agent,
                "host": as_text(record.get("host")),
                "destination": destination,
                "dns": {"question": question} if question is not None else None,
                "raw": line,
                "extra": compact(extra),
            }
        )

    # ------------------------------------------------------------------ event types

    def _alert(self, alert: dict[str, Any], extra: dict[str, object]) -> dict[str, Any]:
        signature = as_text(alert.get("signature"))
        if signature is None:
            raise ParseError("alert without a signature")
        severity = as_count(alert.get("severity"), "alert.severity", maximum=255)
        extra.update(
            {
                "signature": signature,
                "signature_id": as_count(alert.get("signature_id"), "alert.signature_id"),
                "signature_rev": as_count(alert.get("rev"), "alert.rev"),
                "alert_gid": as_count(alert.get("gid"), "alert.gid"),
                "alert_category": as_text(alert.get("category")),
                "alert_action": as_text(alert.get("action")),
                "alert_severity": severity,
            }
        )
        metadata = alert.get("metadata")
        if isinstance(metadata, dict):
            for key in _METADATA_KEYS:
                extra[key] = _joined(metadata.get(key))
        return {
            "severity": LOW_SEVERITY if severity is None else SEVERITY.get(severity, LOW_SEVERITY),
            "reason": signature,
        }

    def _http(
        self, section: dict[str, Any], extra: dict[str, object]
    ) -> tuple[dict[str, Any], str | None]:
        url = as_text(section.get("url"))
        path, query = url, None
        if url is not None and "?" in url and not self.keep_query:
            path, query = url.split("?", 1)
        status = as_count(section.get("status"), "http.status", maximum=999)
        extra.update(
            {
                "query": query or None,
                "http_host": as_text(section.get("hostname")),
                "protocol": as_text(section.get("protocol")),
                "referer": as_text(section.get("http_refer")),
                "content_type": as_text(section.get("http_content_type")),
            }
        )
        http = {
            "method": as_text(section.get("http_method")),
            "path": path,
            "status": status if status is not None and 100 <= status <= 599 else None,
            "bytes": as_count(section.get("length"), "http.length"),
        }
        return http, as_text(section.get("http_user_agent"))

    def _dns(self, section: dict[str, Any], extra: dict[str, object]) -> None:
        name, kind = section.get("rrname"), section.get("rrtype")
        queries = section.get("queries")  # version 3 (Suricata 8)
        if name is None and isinstance(queries, list) and queries and isinstance(queries[0], dict):
            name, kind = queries[0].get("rrname"), queries[0].get("rrtype")
        question = as_text(name)
        extra.update(
            {
                "dns_question": question,
                "dns_type": as_text(kind),
                "dns_rcode": as_text(section.get("rcode")),
                "dns_message": as_text(section.get("type")),
            }
        )

    def _tls(self, section: dict[str, Any], extra: dict[str, object]) -> None:
        sni = as_text(section.get("sni"))
        extra.update(
            {
                "tls_sni": sni,
                "tls_domain": normalise_host(sni),
                "tls_version": as_text(section.get("version")),
                "tls_subject": as_text(section.get("subject")),
                "tls_issuer": as_text(section.get("issuerdn")),
                "ja3_hash": as_text(_section(section, "ja3").get("hash")),
                "ja3s_hash": as_text(_section(section, "ja3s").get("hash")),
            }
        )

    def _ssh(self, section: dict[str, Any], extra: dict[str, object]) -> None:
        for side in ("client", "server"):
            part = _section(section, side)
            extra[f"ssh_{side}_software"] = as_text(part.get("software_version"))
            extra[f"ssh_{side}_protocol"] = as_text(part.get("proto_version"))

    def _flow(self, section: dict[str, Any], extra: dict[str, object]) -> datetime | None:
        start = parse_iso(section["start"], "flow.start") if section.get("start") else None
        end = parse_iso(section["end"], "flow.end") if section.get("end") else None
        if start is not None and end is not None and end >= start:
            duration: float | None = (end - start).total_seconds()
        else:
            duration = as_float(section.get("age"), "flow.age")
        extra.update(
            {
                "bytes_out": as_count(section.get("bytes_toserver"), "flow.bytes_toserver"),
                "bytes_in": as_count(section.get("bytes_toclient"), "flow.bytes_toclient"),
                "packets_out": as_count(section.get("pkts_toserver"), "flow.pkts_toserver"),
                "packets_in": as_count(section.get("pkts_toclient"), "flow.pkts_toclient"),
                "duration": checked_duration(duration),
                "start_time": iso_utc(start) if start is not None else None,
                "flow_state": as_text(section.get("state")),
                "flow_reason": as_text(section.get("reason")),
            }
        )
        return end
