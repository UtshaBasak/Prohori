# LLM analyst evaluation

The data for the offline evaluation of the LLM analyst. How it works and the results:
[docs/LLM_ANALYST.md](../../docs/LLM_ANALYST.md#evaluation).

| Path | Contents | Written by |
| ------ | ---------- | ------------ |
| `cases/` | 30 incidents with their truth label, and for the injection cases the injected text's markers | `scripts/build_llm_eval_set.py` |
| `references.yaml` | A hand-written reference answer for each case | By hand |
| `recordings/` | Recorded answers, one file per system, with each request's prompt hash | `python -m prohori.llm.evaluate record --system NAME` |

Every incident is synthetic: documentation IP addresses and simulated accounts only.
