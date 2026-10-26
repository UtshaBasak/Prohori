# Reports

`prohori report` turns an incident into a document an analyst can read, share or archive.

```bash
prohori incidents auth.log -f json > incidents.jsonl          # build incidents first
prohori report incidents.jsonl --incident INC-597217faa07b7dc8 # choose one when there are several
prohori report samples/incidents/INC-f124f17a36e60980.json                 # Markdown to stdout
prohori report samples/incidents/INC-f124f17a36e60980.json -f html -o report.html
prohori report samples/incidents/INC-f124f17a36e60980.json -f json -o report.json
prohori report samples/incidents/INC-f124f17a36e60980.json -f csv -o timeline.csv
prohori report samples/incidents/INC-f124f17a36e60980.json --redact        # hide accounts
prohori report samples/incidents/INC-f124f17a36e60980.json --redact-ips    # hide accounts and IPs
```

The input is an incident JSON document, a JSON array of incidents, or the JSON Lines written by
`prohori incidents -f json` (use `--incident ID` when the file holds more than one). Input is
validated against the incident schema and capped at 32 MiB. Use `-o FILE` rather than shell
redirection on Windows: PowerShell 5.1 re-encodes redirected output as UTF-16.

Exit codes: `0` written, `1` redaction could not remove every personal value (nothing is
written), `2` invalid usage or input.

## Formats

| Format | Contents | Use |
|--------|----------|-----|
| `md` (default) | Every section below as GitHub-flavoured Markdown | Tickets, wikis, pull requests |
| `html` | The same as one self-contained file: inline CSS, no scripts, no external resources, light and dark themes | Sharing by email or attaching to a case |
| `json` | `format: prohori.report/1`, summary, ATT&CK table, appendix and the full incident | Other tools |
| `csv` | The timeline: `timestamp, kind, description, event_id, alert_id, account, source_ip` | Spreadsheets |

## Sections

1. **Header:** title, incident id, status, severity and score, confidence, time range.
2. **Summary:** one generated paragraph (alerts, rules, time range, addresses, accounts) and the
   three largest score factors.
3. **Timeline:** every matched event and alert, in time order.
4. **Indicators:** IP addresses with each provider's data, retrieval time and note; user agents.
5. **Affected entities:** every IP, account, request and session the incident links on.
6. **Evidence:** each alert with its rule, time range, explanation and up to 10 event ids.
7. **ATT&CK mapping:** tactics with their techniques, and the ATT&CK version.
8. **Score breakdown:** every component and the total (see [INCIDENTS.md](INCIDENTS.md#score)).
9. **Recommended actions** from the runbooks. Prohori only recommends; it never acts.
10. **Confidence and limitations.**
11. **Appendix:** rules fired (with the SHA-256 of each rule file), input files (name, parser,
    events, bytes, SHA-256), the versions that built the incident and rendered the report, the
    SHA-256 of the incident file, and the redaction statement.

The output depends only on the incident (no "generated at" time), so the same incident always
gives the same report, which the golden-file tests rely on.

## Redaction

`--redact` replaces account names, user ids, email hashes and email addresses; `--redact-ips` also
replaces IP addresses (including networks such as `203.0.113.0/24`).

- Values become **keyed pseudonyms** such as `[user:fb05937cd0]`: the first 10 hex digits of an
  HMAC-SHA256 with a random key made for each run and never stored. One account keeps one
  pseudonym within a report, but pseudonyms cannot be reversed (an unsalted hash of a user id or
  email could be) and cannot be linked across reports.
- Values are collected from every structured field: incident and alert entities, timeline
  accounts and addresses, and indicators. They are then replaced in **every** string, because they
  also appear in titles, explanations, score reasons and limitations. Email addresses and, with
  `--redact-ips`, IP addresses are also found by pattern in free text.
- Replacement is whole-token: an account named `admin` is replaced in "account admin" but not
  inside `admin.role.granted` or `PRH-ADMIN-001`. Prose may change; identifiers do not.
- **Fail closed:** after rendering, Prohori searches the report data for every original value.
  If one is left, it prints an error, writes nothing and exits with code `1`.
- Not redacted: event, alert and incident ids (hashes of the log lines), rule ids, provider data
  other than addresses (country, network owner) and input file names. Review a report before
  sharing it outside your organisation.

## Security

Everything in an incident may come from attacker-controlled log lines or third-party data.

- Every value is cleaned before it reaches a template: control characters and ANSI escape
  sequences removed, line breaks collapsed, at most 500 characters per value.
- **HTML:** Jinja2 with autoescaping on, a Content-Security-Policy of `default-src 'none'`
  (inline styles only), no links or resources built from data, and no JavaScript.
- **Markdown:** every value is escaped by the template engine itself, so a template cannot forget
  one: `[`, `]`, `<`, `>`, `|`, emphasis characters and the like are backslash-escaped, bare URLs and
  `www.` are broken so they are not turned into links, and identifiers go in code spans with a
  fence longer than any backtick run in the value.
- **CSV:** cells starting with `=`, `+`, `-`, `@`, a tab or a carriage return (or the full-width
  forms of the first four) are prefixed with `'`, so spreadsheets show them as text.
- Templates are packaged with Prohori; custom templates are not accepted.
- Tests feed a hostile incident (`<script>`, Markdown links, `=HYPERLINK(...)`, ANSI escapes,
  injected headings and table pipes in every text field) through every format.
