"""Phishing / scam ML signal module (§3.C).

Loads the trained artifacts and scores REAL user-submitted message text. Also
extracts human-readable signals (urgency markers, embedded links, credential
request language) so the verdict is explained, not a bare number.

If artifacts are missing the module returns UNAVAILABLE — it never silently
pretends a message is safe.
"""
from __future__ import annotations

import re
from functools import lru_cache

import joblib

from app import events
from app.ml.trainer import AI_MODEL_PATH, MODEL_VERSION, PHISHING_MODEL_PATH
from app.schemas import PhishingAnalyzeResponse, SecurityEventSchema

_URGENCY = ("urgent", "immediately", "within 24", "final warning", "act now",
            "suspended", "locked", "expires", "overdue", "deactivated")
_CREDENTIAL = ("password", "login", "sign in", "verify your identity",
               "card details", "bank", "re-enter", "confirm your account",
               "authenticate", "security code", "otp")
_URL_RE = re.compile(r"https?://[^\s)\"']+", re.IGNORECASE)


@lru_cache
def _load_models():
    phishing = joblib.load(PHISHING_MODEL_PATH) if PHISHING_MODEL_PATH.exists() else None
    ai = joblib.load(AI_MODEL_PATH) if AI_MODEL_PATH.exists() else None
    return phishing, ai


def artifacts_available() -> bool:
    phishing, _ = _load_models()
    return phishing is not None


def _extract_signals(text: str) -> list[dict]:
    lowered = text.lower()
    signals: list[dict] = []
    urgency_hits = [m for m in _URGENCY if m in lowered]
    if urgency_hits:
        signals.append({"type": "urgency", "detail": urgency_hits, "weight": "high"})
    cred_hits = [m for m in _CREDENTIAL if m in lowered]
    if cred_hits:
        signals.append({"type": "credential_request", "detail": cred_hits, "weight": "high"})
    links = _URL_RE.findall(text)
    if links:
        signals.append({"type": "embedded_links", "detail": links[:10], "weight": "medium"})
    return signals


def analyze_text(text: str) -> PhishingAnalyzeResponse:
    phishing, ai = _load_models()
    if phishing is None:
        return PhishingAnalyzeResponse(
            label="UNAVAILABLE",
            confidence=0.0,
            ai_generated_label=None,
            ai_generated_confidence=None,
            model_version=MODEL_VERSION,
            signals=_extract_signals(text),
            provenance="Model artifacts not found; run scripts/train_phishing.py.",
            note="Phishing classifier UNAVAILABLE — artifacts have not been trained.",
        )

    proba = phishing.predict_proba([text])[0]
    classes = list(phishing.classes_)
    phish_idx = classes.index(1) if 1 in classes else -1
    phish_prob = float(proba[phish_idx]) if phish_idx >= 0 else 0.0
    label = "PHISHING" if phish_prob >= 0.5 else "LEGITIMATE"

    ai_label = None
    ai_conf = None
    if ai is not None:
        ai_proba = ai.predict_proba([text])[0]
        ai_classes = list(ai.classes_)
        ai_idx = ai_classes.index(1) if 1 in ai_classes else -1
        ai_prob = float(ai_proba[ai_idx]) if ai_idx >= 0 else 0.0
        ai_label = "LIKELY_AI_GENERATED" if ai_prob >= 0.5 else "LIKELY_HUMAN_WRITTEN"
        ai_conf = round(max(ai_prob, 1 - ai_prob), 4)

    return PhishingAnalyzeResponse(
        label=label,
        confidence=round(abs(phish_prob - 0.5) * 2, 4),  # distance from decision boundary
        ai_generated_label=ai_label,
        ai_generated_confidence=ai_conf,
        model_version=MODEL_VERSION,
        signals=_extract_signals(text),
        provenance=(
            "Trained classifier (TF-IDF + Logistic Regression) applied to "
            "user-submitted text. Training labels are synthetic (disjoint-template)."
        ),
        note=(
            "Contextual assessment of the submitted message text. Not a statement "
            "about any person or a guarantee about future events."
        ),
    )


def build_phishing_events(
    *, user_id: str, account_id: str, text: str, result: PhishingAnalyzeResponse
) -> list[SecurityEventSchema]:
    out: list[SecurityEventSchema] = []
    if result.label == "UNAVAILABLE":
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PHISHING_MESSAGE_DETECTED,
                exposure_type=None,
                severity=0.0,
                confidence=0.0,
                source="ml_classifier",
                status="UNAVAILABLE",
                metadata={"reason": result.provenance},
                provenance=result.provenance,
            )
        )
        return out
    if result.label == "PHISHING":
        # Map classifier confidence (distance from boundary) into severity.
        severity = 0.5 + 0.4 * result.confidence
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PHISHING_MESSAGE_DETECTED,
                exposure_type=None,
                severity=round(severity, 4),
                confidence=round(max(0.5, result.confidence), 4),
                source="ml_classifier",
                status="FINDING",
                metadata={"signals": result.signals, "model_version": result.model_version},
                provenance=result.provenance,
            )
        )
        if result.ai_generated_label == "LIKELY_AI_GENERATED":
            out.append(
                SecurityEventSchema(
                    event_id=events.new_event_id(),
                    user_id=user_id,
                    account_id=account_id,
                    event_type=events.AI_GENERATED_MESSAGE_DETECTED,
                    exposure_type=None,
                    severity=0.4,
                    confidence=float(result.ai_generated_confidence or 0.5),
                    source="ml_classifier",
                    status="FINDING",
                    metadata={"model_version": result.model_version},
                    provenance=(
                        "Stylometric AI-text detector indicates likely AI generation. "
                        "This is a probabilistic style signal, not proof of authorship."
                    ),
                )
            )
    else:
        out.append(
            SecurityEventSchema(
                event_id=events.new_event_id(),
                user_id=user_id,
                account_id=account_id,
                event_type=events.PHISHING_MESSAGE_DETECTED,
                exposure_type=None,
                severity=0.0,
                confidence=round(0.5 + 0.5 * result.confidence, 4),
                source="ml_classifier",
                status="CHECKED_SAFE",
                metadata={"model_version": result.model_version},
                provenance="Classifier assessed the message as legitimate (below threshold).",
            )
        )
    return out