# Architecture

> This describes the target design. Components are implemented incrementally; see
> [CHANGELOG.md](../CHANGELOG.md) for what exists today.

## Data flow

```
 log files / app JSON events / dataset CSVs
              |
        +-----v------+      +----------------------+
        |  parsers   |----->| common event schema  |
        +------------+      +----------+-----------+
                                       |
              +------------------------+------------------------+
              |                                                 |
      +-------v--------+                                +-------v--------+
      | rule engine    |                                | ML detectors   |
      | (YAML rules)   |                                | (flows, logs)  |
      +-------+--------+                                +-------+--------+
              +------------------------+------------------------+
                                       |
                                +------v-------+
                                |    alerts    |
                                +------+-------+
                                       |
                             +---------v----------+     +----------------+
                             | enrichment         |<----| cache (SQLite) |
                             +---------+----------+     +----------------+
                                       |
                             +---------v----------+
                             | incident builder   |  group, score, map to ATT&CK
                             +---------+----------+
                                       |
            +--------------------------+--------------------------+
            |                          |                          |
     +------v------+           +-------v-------+          +-------v--------+
     | reports     |           | warehouse     |          | LLM analyst    |
     | md/html/json|           | + dashboard   |          | (optional)     |
     +-------------+           +---------------+          +----------------+
```

## Run modes

Both modes share the same core library.

- **Batch / CLI mode** (no Docker): file in, incidents and report out.
- **Pipeline mode** (Docker Compose): producers -> Kafka-compatible message queue -> consumers
  (normalise -> detect -> alert -> incident) -> warehouse, with scheduled jobs and a dashboard.
  A file-based **lite mode** runs the same consumers without Docker.

## Package layout

| Package | Responsibility |
|---------|----------------|
| `prohori.cli` | Typer application and commands |
| `prohori.schema` | Pydantic models: `Event`, `Alert`, `Incident` |
| `prohori.parsers` | Streaming log parsers and the parser registry |
| `prohori.rules` | Rule loader, validator, engine and built-in rules |
| `prohori.enrich` | Enrichment providers, cache, rate limiting, offline fixtures |
| `prohori.incidents` | Grouping, scoring, ATT&CK mapping |
| `prohori.reports` | Report templates, renderers and redaction |
| `prohori.simulate` | Labelled attack-scenario log generator |
| `prohori.ml` | Dataset registry, chunked loading, leakage-controlled cleaning, flow models, training and SOC metrics (`prohori score` follows) |
| `prohori.pipeline` | Producers, consumers, sinks, lite-mode runner |
| `prohori.llm` | Provider interface, retrieval, safeguards |

## Principles

- Logs are untrusted input: bounded sizes, escaped output, safe YAML only, no `eval` or pickle on
  untrusted data.
- The base install stays small; heavy dependencies sit behind the `ml`, `pipeline` and `llm` extras.
- Everything works offline and on free services only.
- Prohori recommends actions; it never takes them.
