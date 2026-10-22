"""Training for the phishing classifier and the AI-text detector (§3.C).

Two genuinely-trained models:
  1. Phishing classifier: TF-IDF (word + char n-grams) -> Logistic Regression.
  2. AI-generated detector: stylometric features -> Logistic Regression.

Neither model is trained on labels produced by CRIX's own risk formula; labels
come from the synthetic corpus generator (documented synthetic data). This keeps
the ML honest and non-circular (§0.5).

Artifacts are written to backend/artifacts/ so runtime inference never trains.
The authoritative metrics are produced by scripts/evaluate_phishing.py (Phase 13),
not here — this module only fits and persists.
"""
from __future__ import annotations

import re
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline as SKPipeline
from sklearn.preprocessing import StandardScaler

from app.ml.dataset import generate_corpus

ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / "artifacts"
PHISHING_MODEL_PATH = ARTIFACTS_DIR / "phishing_model.joblib"
AI_MODEL_PATH = ARTIFACTS_DIR / "ai_detector.joblib"
MODEL_VERSION = "tfidf-lr-v1"

_SENTENCE_RE = re.compile(r"[.!?]+")


def build_phishing_pipeline() -> SKPipeline:
    return SKPipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    min_df=1,
                    lowercase=True,
                    analyzer="word",
                    strip_accents="unicode",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    C=4.0,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )


# --------------------------------------------------------------------------- #
# Stylometric features for the AI-vs-human detector
# --------------------------------------------------------------------------- #
_AI_MARKERS = (
    "i hope this message finds you well",
    "best regards",
    "kind regards",
)


def stylometric_features(texts) -> np.ndarray:
    """Module-level (picklable) stateless feature transformer."""
    rows = []
    for text in texts:
        t = text or ""
        lower = t.lower()
        sentences = [s for s in _SENTENCE_RE.split(t) if s.strip()]
        sent_lengths = [len(s.split()) for s in sentences] or [0]
        words = t.split()
        unique = set(w.lower() for w in words)
        newlines = t.count("\n")
        letters = [c for c in t if c.isalpha()]
        upper = sum(1 for c in letters if c.isupper())
        digits = sum(1 for c in t if c.isdigit())
        punct = sum(1 for c in t if c in ".,!?;:")
        rows.append(
            [
                float(np.mean(sent_lengths)),
                float(np.std(sent_lengths)),
                len(words),
                len(unique) / max(1, len(words)),          # type-token ratio
                newlines,
                upper / max(1, len(letters)),               # uppercase ratio
                digits / max(1, len(t)),                    # digit ratio
                punct / max(1, len(t)),                     # punctuation density
                t.count(" "),                               # spaces
                float(any(m in lower for m in _AI_MARKERS)),
                float(lower.startswith("hello")),
                float(len(sentences)),
            ]
        )
    return np.asarray(rows, dtype=float)


def build_ai_pipeline() -> SKPipeline:
    from sklearn.preprocessing import FunctionTransformer

    return SKPipeline(
        steps=[
            ("features", FunctionTransformer(stylometric_features, validate=False)),
            ("scale", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000, C=1.0, class_weight="balanced", solver="liblinear"
                ),
            ),
        ]
    )


# --------------------------------------------------------------------------- #
# Metric helpers (used by the eval harness — real numbers, real data)
# --------------------------------------------------------------------------- #
def _metrics(y_true, y_pred) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "n_samples": int(len(y_true)),
    }


def train_all(*, seed: int = 1234) -> dict:
    """Fit both models on the synthetic train split and persist artifacts.

    Returns a small summary. Full metrics are computed by the eval harness on the
    disjoint test split.
    """
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    corpus = generate_corpus(seed=seed)
    train_texts = [r["text"] for r in corpus["train"]]
    train_phish = [r["phishing"] for r in corpus["train"]]
    train_ai = [r["ai_generated"] for r in corpus["train"]]

    phishing = build_phishing_pipeline()
    phishing.fit(train_texts, train_phish)
    joblib.dump(phishing, PHISHING_MODEL_PATH)

    ai = build_ai_pipeline()
    ai.fit(train_texts, train_ai)
    joblib.dump(ai, AI_MODEL_PATH)

    return {
        "model_version": MODEL_VERSION,
        "train_size": len(train_texts),
        "phishing_model": str(PHISHING_MODEL_PATH),
        "ai_model": str(AI_MODEL_PATH),
        "labels_are_synthetic": True,
    }


def evaluate(*, seed: int = 1234) -> dict:
    """Evaluate both models on the DISJOINT-template test split.

    Assumes artifacts exist (run train_all first). Returns real measured metrics.
    """
    phishing = joblib.load(PHISHING_MODEL_PATH)
    ai = joblib.load(AI_MODEL_PATH)
    corpus = generate_corpus(seed=seed)
    test = corpus["test"]
    texts = [r["text"] for r in test]
    y_phish = [r["phishing"] for r in test]
    y_ai = [r["ai_generated"] for r in test]

    phish_pred = phishing.predict(texts)
    ai_pred = ai.predict(texts)
    return {
        "model_version": MODEL_VERSION,
        "dataset": "synthetic (disjoint-template test split)",
        "phishing": _metrics(y_phish, phish_pred),
        "ai_generated": _metrics(y_ai, ai_pred),
    }