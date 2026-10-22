"""Train the phishing classifier and AI-text detector.

Usage (from repo root):
    .venv\\Scripts\\python.exe backend\\scripts\\train_phishing.py

Produces backend/artifacts/*.joblib. Metrics are NOT printed here — run the
evaluation harness for measured numbers.
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.ml.trainer import train_all  # noqa: E402


def main() -> None:
    summary = train_all()
    print("Trained models:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("\nRun backend/scripts/run_evaluation.py for measured metrics.")


if __name__ == "__main__":
    main()