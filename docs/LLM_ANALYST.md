# LLM analyst

`prohori explain` asks a large language model to explain an incident in plain language: what
happened, why it matters, the evidence, what to do next and what is uncertain. `prohori ask`
answers a question from ATT&CK and Prohori's runbooks, about an incident if you give one. Both
are **opt-in and off by default**. Everything Prohori does works without them, and
`prohori report` already writes a full report offline.

```bash
pip install "prohori[llm]"                                   # or: uv sync --extra llm
prohori explain samples/incidents/INC-ee7c8818fbb34989.json --show-payload   # what would be sent; sends nothing
export PROHORI_LLM_PROVIDER=gemini GEMINI_API_KEY=...         # or put them in .env
prohori explain samples/incidents/INC-ee7c8818fbb34989.json
prohori ask "How should I respond to password spraying?"      # offline: shows the best sources
```

## Contents

- [Before you turn it on](#before-you-turn-it-on)
- [What is sent](#what-is-sent)
- [Sources and tools](#sources-and-tools)
- [Prompt injection and answer checks](#prompt-injection-and-answer-checks)
- [Providers and settings](#providers-and-settings)
- [Limits and fallback](#limits-and-fallback)
- [Output](#output)
- [Getting a Gemini key](#getting-a-gemini-key)
- [Limitations](#limitations)

## Before you turn it on

- **Data use on the free tier.** Google's Gemini API pricing page (checked 2026-11-02) says the
  free tier is "Content used to improve our products" and the paid tier is "Content **not** used
  to improve our products". On the free tier, assume Google keeps and may read what is sent.
  Prohori prints a reminder each time unless you set `PROHORI_LLM_TIER=paid`. The terms are at
  <https://ai.google.dev/gemini-api/terms>.
- **Only send what you may share.** Redaction (below) removes account names, ids and email
  addresses, and optionally IP addresses. It does not make every incident safe to share: rule
  titles, timestamps, enrichment data and the shape of an attack still go out.
- **Check first.** `--show-payload` prints exactly what would be sent and sends nothing.

## What is sent

A system instruction fixed in code, and a prompt with the task (or your question), a JSON
document built from an **allow-list** of incident fields (`prohori.llm.payload`) and a few
sources (below). Nothing else from the incident is included:

| Sent | Not sent |
|------|----------|
| Id, title, severity, confidence, score and its breakdown, first and last time | Raw log lines (incidents hold none) |
| Entities, ATT&CK techniques | The timeline's event descriptions: they carry request paths, user agents and other text an attacker controls |
| Alerts: rule, kind, title, severity, times, event count, ATT&CK, explanation | Event ids, input file names and hashes (provenance) |
| The number of events, the alert entries of the timeline | Enrichment notes |
| Indicators with their enrichment data | |
| Recommended actions, limitations | |

- **Redaction first.** Account names, ids and email addresses become keyed pseudonyms such as
  `[user:3f2a9c1e07]`, wherever they appear: entities, titles, explanations, reasons, actions and
  limitations. The key is random for each run and never written down, so a pseudonym cannot be
  looked up. `--mask-ips` (or `PROHORI_LLM_MASK_IPS=true`) also replaces IP addresses. Without
  it, IP addresses are sent, because they are usually the evidence.
- **Fail closed.** Before sending, the exact text is searched for every value that was
  replaced. It searches the decoded text, so a Bangla or other non-ASCII name counts. If one
  remains, nothing is sent and the command exits 1.
- **Size cap.** Each free-text value is cut at 300 characters. If the estimated size (characters
  / 4) is over `PROHORI_LLM_MAX_INPUT_TOKENS`, Prohori drops indicators beyond five, then alerts
  beyond twenty, then the alert timeline, and says so in the payload's `trimmed` field.
- **Untrusted values are fenced** (see below).

## Sources and tools

- **Sources.** Prohori searches two local collections with BM25 and adds the best matches to
  the prompt as `[S1]`, `[S2]`, ..., which the model is told to cite:
  - **ATT&CK.** Every active technique and sub-technique of Enterprise ATT&CK v20.0, 706 in
    all: id, name, tactics, and the first paragraph of the description without citations or
    links, capped at 600 characters. `src/prohori/llm/data/attack.jsonl` is built from the pinned
    official STIX bundle (SHA-256 checked) by `scripts/build_attack_corpus.py`.
  - **Runbooks.** Prohori's runbooks, one document per section.

  For `explain`, the sources are the incident's own techniques and its rules' recommended
  actions. For `ask`, they are the five best matches for the question, plus the incident's own
  if you give one. A technique id in the question (such as `T1110.003`) is matched exactly
  first.
- **Read-only tools.** The model may ask for more by replying with one line such as
  `CALL search_knowledge {"query": "..."}`. The tools are:
  - `search_knowledge`: ATT&CK and the runbooks;
  - `get_technique`: one ATT&CK technique;
  - `get_alert`: one of the incident's alerts.

  The tools only read local data. There are at most three calls per answer (`--max-tool-calls`,
  0 to 5). An unknown tool, bad arguments or more calls than allowed end the conversation with a
  local answer. Every request counts against the daily budget, including tool rounds.

## Prompt injection and answer checks

An attacker controls parts of the logs: user agents, usernames, request paths, sometimes text
that rules quote. Prohori assumes some of it will try to instruct the model.

- **Most of it is never sent.** Event descriptions are dropped, and account names become
  pseudonyms, so an instruction hidden in a username arrives as `[user:...]`.
- **What is sent is fenced.** Every value that can carry log content is wrapped as
  `⟦u:NONCE⟧...⟦/u:NONCE⟧`, with a random nonce for each request. That covers titles,
  explanations, score reasons, alert timeline entries, entity and indicator values (such as a
  scanner's user agent) and limitations. The fence characters are removed from the value first,
  so it cannot close its fence or forge one. The system instruction says fenced text is data and
  that any instruction in it must be ignored. Tool results are fenced the same way.
- **Answers are checked before they are shown.** Every IP address, email address, pseudonym,
  incident id, rule id and ATT&CK technique id in the answer must exist in the incident's
  identity fields (addresses and pseudonymised accounts, never free text such as a user agent)
  or in the sources and tool results the model was given. Links are allowed only to
  attack.mitre.org.
- **Conservative by design.** One unknown value rejects the whole answer. You get the local
  summary instead, and stderr lists what was unknown. A model that obeys an injected "the
  attacker is 198.51.100.250" or "link to https://evil.example" is therefore caught. The checks
  look at what is cited, not at what is claimed: a wrong judgement made only from real values
  ("this is benign") is not detected.
- **Tested.** `tests/unit/llm/test_injection.py` turns real logs into incidents with
  instructions hidden in a user agent, a username and a request path. It checks three things:
  - the instruction never reaches the model outside a fence;
  - seven kinds of compromised answers are rejected for each vector;
  - an honest answer citing real values is accepted.

## Providers and settings

| Provider | Sends data | What it does |
|----------|-----------|--------------|
| `none` (default) | No | Prints that the analyst is off and exits 0 |
| `mock` | No | Answers offline from the payload, for tests and demonstrations |
| `gemini` | Yes | Calls the Gemini Developer API with the official `google-genai` SDK (`llm` extra) |

Settings come from the environment or `.env` (environment wins); see `.env.example`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `PROHORI_LLM_PROVIDER` | `none` | `none`, `mock` or `gemini` (`--provider` overrides it) |
| `GEMINI_API_KEY` | | Key from Google AI Studio |
| `PROHORI_LLM_MODEL` | `gemini-3.5-flash-lite` | Any Gemini model name (`--model` overrides it) |
| `PROHORI_LLM_TIER` | `free` | `paid` once billing is enabled; only turns off the free-tier reminder |
| `PROHORI_LLM_MASK_IPS` | `false` | Also redact IP addresses |
| `PROHORI_LLM_DAILY_REQUESTS` | `20` | Requests per UTC day before Prohori stops asking |
| `PROHORI_LLM_MAX_INPUT_TOKENS` | `6000` | Estimated payload size before trimming |
| `PROHORI_LLM_MAX_OUTPUT_TOKENS` | `1024` | Longest answer requested |
| `PROHORI_LLM_TIMEOUT` | `60` | Seconds to wait for an answer |

**The default model.** On 2026-11-02, Google's models page listed these stable models with a free
tier:
- `gemini-3.8-flash` and `gemini-3.6-flash` (Flash);
- `gemini-3.5-flash-lite` and `gemini-3.1-flash-lite` (Flash-Lite).

Prohori uses `gemini-3.5-flash-lite`, the newest stable Flash-Lite model: an explanation is a short
task, and Flash-Lite is the cheapest model with free-tier access. Model names change, so set
`PROHORI_LLM_MODEL` when Google retires one. Prohori never uses a `-latest` alias, so answers do
not change model without notice.

**Pages checked on 2026-11-02:**
- <https://ai.google.dev/gemini-api/docs/pricing> for free-tier models and data use;
- <https://ai.google.dev/gemini-api/docs/models> for the stable model names;
- <https://ai.google.dev/gemini-api/docs/rate-limits> for limits. It does not list free-tier
  numbers; they are shown per project in AI Studio.

**SDK.** `google-genai` 2.31.0, Apache 2.0. Prohori calls `client.models.generate_content`
with these settings:
- an explicit API key, so `GOOGLE_API_KEY` in the environment is never used;
- `vertexai=False`;
- the configured timeout;
- the SDK's own retries turned off, so one explanation is one request.

## Limits and fallback

- **Daily budget.** Each request is counted before it is sent, in the same local cache file as
  the enrichment budgets, so a failed request still counts. When the day's budget is used up,
  nothing is sent.
- **Fallback.** If the provider cannot answer, `explain` prints a **local summary** written
  from the incident itself, then exits 0. On stderr it says why and whether the request was
  sent. That covers:
  - no key, or the `llm` extra missing;
  - the budget used up;
  - Google's rate limit or quota (HTTP 429);
  - a refused key, a timeout or a connection error;
  - an empty or blocked answer, such as a safety filter or the length limit.
- **Errors never show the key.** Messages are cleaned and shortened.

## Output

The answer is untrusted text. Control characters and terminal escape sequences are removed, the
answer is shown without any markup processing and is capped at 20,000 characters. Pseudonyms are
replaced with the real values on your machine; `--keep-pseudonyms` shows the answer as the model
wrote it. stderr says which provider and model answered and how many tokens it used.

## Getting a Gemini key

Optional, only to try the real provider:

1. Sign in at <https://aistudio.google.com/> with a Google account.
2. Choose *Get API key*, then *Create API key*.
3. Put it in `.env` as `GEMINI_API_KEY=...` (git-ignored) and set `PROHORI_LLM_PROVIDER=gemini`.

Never commit the key. gitleaks checks every commit for it.

## Limitations

- **Explanations can be wrong.** The model can misread an incident or overstate it. The
  incident, its score and its evidence remain the source of truth.
- **Injection defences reduce risk; they do not remove it.** Fencing and answer checks stop
  invented citations and links. A model can still be talked into a wrong judgement made only
  from real values, so read answers critically.
- **Retrieval is lexical.** BM25 matches words, not meaning; a question in other words than
  ATT&CK's may find weaker sources.
- **One provider.** The interface (`prohori.llm.provider`) is small, so another provider can be
  added later.
