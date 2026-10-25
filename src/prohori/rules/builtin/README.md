# Built-in rules

Detection rules shipped with Prohori, one YAML file per rule. The format is documented in
`docs/RULES.md`. This directory is included in the package and is the default for
`prohori rules list`, `prohori rules validate` and `prohori rules test`.

Each rule `<name>.yml` has a fixture file `<name>.tests.yml` beside it and a runbook in
`../../runbooks/`. Tests check that every rule has both and uses verified ATT&CK tags.
