# CRIX datasets

Exported by `backend/scripts/export_datasets.py`. These are the exact datasets the
code loads at runtime — nothing here is illustrative or hand-typed for the docs.

## Machine-learning dataset (SYNTHETIC, clearly labeled)

Generated deterministically from templates in `backend/app/ml/dataset.py`
(`seed=1234`). Train and test use **disjoint template families**, so test metrics
measure generalization to unseen templates within a synthetic distribution. These
are NOT claims about real-world phishing detection.

| File | Rows | Purpose |
|------|------|---------|
| `phishing_corpus_train.jsonl` / `.csv` | 223 | Fits the TF-IDF phishing classifier and the stylometric AI detector. |
| `phishing_corpus_test.jsonl` / `.csv` | 153 | Disjoint-template held-out set -> precision/recall/F1/confusion matrix. |
| `phishing_corpus_heldout.jsonl` | 4 | Hand-authored examples used by the end-to-end smoke test. |

Fields: `text`, `phishing` (0/1), `ai_generated` (0/1), `family`.

## Curated reference datasets (HAND-VERIFIED STATIC)

Each row carries a `source` (and, where relevant, `last_verified`) so it is never
mistaken for auto-discovered or measured data.

| File | What it is |
|------|------------|
| `providers.json` | ~20 real services with passkey/MFA/recovery capability. |
| `graph_relationships.json` | Curated account-dependency edges (recovery/OAuth routes). |
| `knowledge_graph.json` | Curated GraphRAG nodes + enables/defeats/prevented_by edges. |
| `permissions_taxonomy.json` | Explainable per-permission sensitivity ratings. |
| `correlation_rules.json` | The declarative correlation rules the engine interprets. |

## Not datasets (measured at runtime)

Risk scores, Shapley attributions, remediation plans, and ML metrics are COMPUTED,
not stored datasets. ML metrics are persisted to the `evaluation_records` table by
`backend/scripts/run_evaluation.py`; the curated YAML files under
`backend/app/data/` remain the source of truth (this folder is a readable export).
