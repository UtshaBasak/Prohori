# Scripts

Maintenance and reproducibility scripts (dataset download, results-table generation and similar).
Scripts are run explicitly; nothing is downloaded at import time.

| Script | Purpose |
|--------|---------|
| `evaluate_rules.py` | Run the built-in rules on every simulated scenario (default and held-out variants, seeds 1-5) and write `results/rules_eval.json` |
| `generate_results_table.py` | Write the evaluation tables into `docs/SIMULATOR.md` from `results/rules_eval.json` (`--check` only verifies) |
| `verify_attack.py` | Check `prohori.rules.attack` against the pinned official ATT&CK STIX bundle (network access, about 50 MB) |
