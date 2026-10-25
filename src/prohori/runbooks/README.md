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
