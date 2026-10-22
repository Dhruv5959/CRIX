"""Export every dataset CRIX actually uses into inspectable files.

Writes to ``datasets/`` at the repo root:
  - phishing_corpus_train.jsonl / .csv   (synthetic, labeled)
  - phishing_corpus_test.jsonl  / .csv   (disjoint templates -> the eval set)
  - phishing_corpus_heldout.jsonl        (hand-authored, used by smoke test)
  - providers.json                       (curated service catalog)
  - graph_relationships.json             (curated dependency edges)
  - knowledge_graph.json                 (curated KG nodes + edges)
  - permissions_taxonomy.json            (curated permission sensitivity)
  - correlation_rules.json               (declarative rule definitions)
  - DATASETS.md                          (manifest: what each file is, real vs synthetic)

Usage (from repo root):
    .venv\\Scripts\\python.exe backend\\scripts\\export_datasets.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.data.loader import (  # noqa: E402
    correlation_rules,
    graph_relationships_data,
    knowledge_graph_data,
    permissions_taxonomy,
    providers_data,
)
from app.ml.dataset import generate_corpus  # noqa: E402

OUT = ROOT / "datasets"


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _write_json(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def main() -> None:
    OUT.mkdir(exist_ok=True)

    # 1. Synthetic phishing / AI corpus (the ML dataset).
    corpus = generate_corpus(seed=1234)
    for split in ("train", "test", "heldout"):
        rows = corpus[split]
        _write_jsonl(OUT / f"phishing_corpus_{split}.jsonl", rows)
    # CSV for the labelled splits.
    for split in ("train", "test"):
        rows = corpus[split]
        _write_csv(
            OUT / f"phishing_corpus_{split}.csv",
            rows,
            ["text", "phishing", "ai_generated", "family"],
        )

    # 2. Curated reference datasets.
    _write_json(OUT / "providers.json", providers_data())
    _write_json(OUT / "graph_relationships.json", graph_relationships_data())
    _write_json(OUT / "knowledge_graph.json", knowledge_graph_data())
    _write_json(OUT / "permissions_taxonomy.json", permissions_taxonomy())
    _write_json(OUT / "correlation_rules.json", correlation_rules())

    # 3. Manifest.
    manifest = f"""# CRIX datasets

Exported by `backend/scripts/export_datasets.py`. These are the exact datasets the
code loads at runtime — nothing here is illustrative or hand-typed for the docs.

## Machine-learning dataset (SYNTHETIC, clearly labeled)

Generated deterministically from templates in `backend/app/ml/dataset.py`
(`seed=1234`). Train and test use **disjoint template families**, so test metrics
measure generalization to unseen templates within a synthetic distribution. These
are NOT claims about real-world phishing detection.

| File | Rows | Purpose |
|------|------|---------|
| `phishing_corpus_train.jsonl` / `.csv` | {len(corpus['train'])} | Fits the TF-IDF phishing classifier and the stylometric AI detector. |
| `phishing_corpus_test.jsonl` / `.csv` | {len(corpus['test'])} | Disjoint-template held-out set -> precision/recall/F1/confusion matrix. |
| `phishing_corpus_heldout.jsonl` | {len(corpus['heldout'])} | Hand-authored examples used by the end-to-end smoke test. |

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
"""
    (OUT / "DATASETS.md").write_text(manifest, encoding="utf-8")

    files = sorted(p.name for p in OUT.iterdir())
    print(f"Exported {len(files)} files to {OUT}:")
    for name in files:
        print(f"  {name}")


if __name__ == "__main__":
    main()