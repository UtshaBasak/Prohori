# Scripts

Maintenance and reproducibility scripts (dataset download, results-table generation and similar).
Scripts are run explicitly; nothing is downloaded at import time.

| Script | Purpose |
|--------|---------|
| `download_datasets.py` | List, fetch (CIC-IDS-2017 only, on request), verify and prepare the ML datasets in `data/`; see `docs/DATASETS.md` |
| `evaluate_rules.py` | Run the built-in rules on every simulated scenario (default and held-out variants, seeds 1-5) and write `results/rules_eval.json` |
| `generate_results_table.py` | Write the evaluation tables into `docs/SIMULATOR.md`, `docs/MODEL_CARD.md` and the README from `results/` (`--check` only verifies) |
| `traffic_clones.py` | Fold GitHub's 14-day clone numbers into an all-time record and badge (run daily by `.github/workflows/traffic.yml`) |
| `release_notes.py` | Print a version's CHANGELOG section (used by the release workflow) |
| `generate_examples.py` | Regenerate `docs/examples/` and `docs/images/demo.svg` |
| `benchmark.py` | Measure throughput and peak memory on million-line logs and write `results/performance.json` |
| `build_attack_corpus.py` | Build `src/prohori/llm/data/attack.jsonl` from the pinned ATT&CK STIX bundle (network access, about 50 MB) |
| `build_llm_eval_set.py` | Rebuild the LLM evaluation cases in `evaluation/llm/cases/` from the simulator |
| `verify_attack.py` | Check `prohori.rules.attack` against the pinned official ATT&CK STIX bundle (network access, about 50 MB) |
