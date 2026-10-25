"""Seed only CRIX's curated, non-tenant reference records.

This is intentionally separate from ``seed_demo.py``. It creates no users,
organizations, signals, fixtures, or test scenarios, and is idempotent so the
Render start command can run it on a fresh deployment safely.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.data.loader import seed_all  # noqa: E402
from app.db import SessionLocal  # noqa: E402


def main() -> None:
    session = SessionLocal()
    try:
        print(json.dumps({"reference_records_added": seed_all(session)}, sort_keys=True))
    finally:
        session.close()


if __name__ == "__main__":
    main()
