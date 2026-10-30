# Results

Evaluation metrics as JSON files (committed), from which the documentation tables are generated
by `scripts/generate_results_table.py`.

| File | Contents | Written by |
|------|----------|------------|
| `rules_eval.json` | Rule precision and recall on the simulated scenarios ([SIMULATOR.md](../docs/SIMULATOR.md)) | `scripts/evaluate_rules.py` |
| `ml_unsw-nb15.json`, `ml_cicids2017.json` | Flow-model metrics per seed, variant and model, with seed summaries ([MODEL_CARD.md](../docs/MODEL_CARD.md)) | `python -m prohori.ml.train` |

Trained models are not kept here: they go to the git-ignored `models/` directory.
