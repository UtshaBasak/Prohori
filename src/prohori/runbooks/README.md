# Runbooks

Response guidance for the built-in rules, one Markdown file per kind of incident. A rule's
`response` key (`runbooks/<name>.md`) names its runbook, resolved against the `prohori` package.

Every runbook uses the same structure, so tools can extract sections such as the recommended
actions:

```markdown
# <title>

**Rules:** <rule ids>

## What it means
## Triage
## Recommended actions
## False positives
## ATT&CK
```

Recommended actions that apply to only one kind of system start with an exact prefix, so the
incident builder can leave them out where they do not apply:

- `For SSH,` - shown only for incidents that contain SSH events.
- `For the web app,` - shown only for incidents that contain web-app events.
