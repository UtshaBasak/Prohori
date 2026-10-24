# Event Schema

Every parser turns its input into the same typed record, an `Event`. Detections produce `Alert`s,
and the incident builder groups alerts into `Incident`s. All three are immutable
[Pydantic v2](https://docs.pydantic.dev/) models in `prohori.schema`.

The schema is "ECS-lite": field names follow the spirit of the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html), but it is much
smaller and is not ECS-compatible.

## Conventions

- **Timestamps are UTC.** Timezone-aware values are converted to UTC. Naive values (no timezone)
  are **rejected**, so a parser must decide the timezone explicitly (for example from a
  `--timezone` option) instead of the schema guessing. JSON output uses ISO-8601 with `Z`.
- **Models are immutable** (`frozen`) and **reject unknown fields**.
- **Log content is untrusted.** Free-text fields are **truncated** to a fixed maximum length rather
  than rejected, so a hostile value cannot make an event disappear. Values are stored as data and
  are never interpreted; escaping happens at output time (reports, HTML).
- **Ids are deterministic** content hashes, so re-processing the same input gives the same ids.
- **Dotted paths.** Models are nested (`event.event.action` in Python), and every field also has a
  flat dotted name (`event.action`) used by rules and features. See [Field access](#field-access).

## Event

| Field | Type | Notes |
|-------|------|-------|
| `id` | str | `evt-` + 24 hex characters. Derived from `log_source`, `timestamp` and `raw` when not given |
| `timestamp` | datetime (UTC) | Required |
| `log_source` | str (1-64) | For example `sshd`, `nginx`, `app-security` |
| `event.action` | str | Required. Dotted lower-case name matching `^[a-z0-9_]+(\.[a-z0-9_]+)*$`, max 128, for example `auth.signin.failure` |
| `event.category` | enum | Required. `authentication`, `web`, `session`, `account`, `authorization`, `abuse`, `admin`, `network` |
| `event.outcome` | enum | `success`, `failure`, `unknown` (default) |
| `event.severity` | enum, optional | Source-provided severity: `low`, `medium`, `high` |
| `event.reason` | str, optional | For example `bad_password`, `unknown_user`, `locked` |
| `source.ip` | IPv4 or IPv6, optional | Invalid addresses are rejected |
| `user.name` | str, optional | Attacker-controllable; treat as untrusted |
| `user.id` | str, optional | |
| `user.email_hash` | str, optional | Already hashed upstream; never un-hashed |
| `http.method` | str (max 16), optional | Upper-cased |
| `http.path` | str, optional | Stored without the query string unless a parser needs it |
| `http.status` | int 100-599, optional | |
| `http.bytes` | int >= 0, optional | |
| `user_agent` | str, optional | Untrusted |
| `client` | str, optional | For example `web` or `android/10203` |
| `host` | str, optional | |
| `request_id` | str, optional | Correlation id when present |
| `raw` | str | Required. The original line, truncated at 8,192 characters |
| `extra` | map of str to scalar | Up to 64 source-specific safe fields; values are string, number, boolean or null |

### Length limits

| Fields | Maximum characters |
|--------|--------------------|
| `raw` | 8,192 |
| `user_agent`, `http.path`, `extra` string values, free-text descriptions | 1,024 |
| `user.*`, `client`, `host`, `request_id`, `event.reason`, `extra` keys | 256 |

### Example

```json
{
  "id": "evt-9c489e007319128a1731d89e",
  "timestamp": "2026-10-24T13:50:12.345000Z",
  "log_source": "app-security",
  "event": {"action": "auth.signin.failure", "category": "authentication",
            "outcome": "failure", "severity": "low", "reason": "bad_password"},
  "source": {"ip": "203.0.113.7"},
  "user": {"name": null, "id": "665f1c", "email_hash": "3a91d0"},
  "http": {"method": "POST", "path": "/api/auth/signin", "status": null, "bytes": null},
  "user_agent": "Mozilla/5.0",
  "client": "web",
  "host": null,
  "request_id": "9f3c0a",
  "raw": "{\"time\": \"2026-10-24T13:50:12.345Z\", ...}",
  "extra": {}
}
```

### Event ids and duplicates

`event_id(log_source, timestamp, raw, discriminator="")` hashes its inputs with SHA-256. Two
identical lines with the same timestamp from the same source therefore share an id. Parsers that
must keep such lines apart (for example two identical failures within one second) pass a
`discriminator` such as `"auth.log:1042"` and set the `id` explicitly.

## Alert

| Field | Type | Notes |
|-------|------|-------|
| `id` | str | `alr-` + 24 hex characters, derived from `detector_id` and the sorted `event_ids` when not given |
| `detector_id` | str | Rule id (`PRH-AUTH-001`) or model name |
| `detector_kind` | enum | `rule` (default) or `model` |
| `title` | str | |
| `severity` | enum | `low`, `medium`, `high`, `critical` |
| `score` | float 0-100 | Detector confidence or anomaly score; default 0 |
| `event_ids` | list of str | At least one |
| `entities` | map of str to str | Grouping fields and values, for example `{"source.ip": "203.0.113.7"}` |
| `first_seen`, `last_seen` | datetime (UTC) | `last_seen` must not precede `first_seen` |
| `attack` | list of str | ATT&CK tags: `attack.t1110`, `attack.t1110.003` or `attack.credential_access` |
| `explanation` | str | Why the detector fired |

## Incident

| Field | Type | Notes |
|-------|------|-------|
| `id` | str | `INC-` followed by letters, digits or hyphens, for example `INC-0042` |
| `title` | str | |
| `status` | enum | `open` (default), `investigating`, `resolved`, `false_positive` |
| `severity` | enum | `low`, `medium`, `high`, `critical` |
| `score` | float >= 0 | |
| `score_breakdown` | list of `{reason, points}` | When present, points must add up to `score` |
| `first_seen`, `last_seen` | datetime (UTC) | `last_seen` must not precede `first_seen` |
| `entities` | map of str to list of str | For example `{"source.ip": ["203.0.113.7"], "user.name": ["alice"]}` |
| `alerts` | list of `Alert` | At least one |
| `timeline` | list of `{timestamp, description, event_id?, alert_id?}` | |
| `indicators` | list of `{type, value, enrichment[]}` | `type`: `ip`, `domain`, `url`, `hash`, `user`, `user_agent` |
| `attack` | list of str | ATT&CK tags as for alerts |
| `recommended_actions` | list of str | From runbooks |
| `confidence` | enum | `low`, `medium` (default), `high` |
| `limitations` | list of str | For example `single log source`, `enrichment offline` |

Each enrichment entry is `{provider, retrieved_at, data, note?}`, where `data` maps strings to
scalars.

## Severity

One ordered scale is shared by events, alerts and incidents: `low` < `medium` < `high` <
`critical` (`Severity.rank` gives 1-4). Source events use only `low`, `medium` and `high`;
`critical` is reserved for Prohori's own alerts and incidents.

## Field access

```python
from prohori.schema import FIELD_PATHS, get_field, is_valid_path

get_field(event, "event.action")  # "auth.signin.failure"
get_field(event, "source.ip")  # "203.0.113.7" (string)
get_field(event, "extra.port")  # value from the extra map, or None
is_valid_path("http.status")  # True
```

`get_field` returns JSON scalars: enums as their string value, IP addresses as strings and
timestamps in ISO-8601. Unknown paths raise `KeyError`. `FIELD_PATHS` lists every path except the
open-ended `extra.<key>`.

## Serialisation

```python
from prohori.schema import Event, from_json, read_jsonl, to_json, write_jsonl

text = to_json(event)  # one JSON document
same = from_json(Event, text)  # validated model, equal to `event`

with open("events.jsonl", "w", encoding="utf-8", newline="\n") as out:
    write_jsonl(events, out)
with open("events.jsonl", encoding="utf-8") as src:
    for event in read_jsonl(Event, src):  # lazy; blank lines skipped
        ...
```
