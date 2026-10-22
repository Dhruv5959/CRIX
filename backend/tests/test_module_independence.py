"""Module-independence guards (decision D4).

The compromise-propagation simulator is an independent, defensively-framed
module: it must not import the authoritative risk engine, so it can never
change or duplicate risk scoring.
"""
from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            for alias in node.names:
                found.add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
    return found


def test_propagation_does_not_import_risk_engine():
    imports = _imported_modules(APP / "engine" / "propagation.py")
    offenders = {m for m in imports if m.split(".")[-1] == "risk" or m.endswith(".risk")}
    assert not offenders, f"propagation.py must not import the risk engine, found: {offenders}"


def test_propagation_does_not_import_risk_in_package_form():
    imports = _imported_modules(APP / "engine" / "propagation.py")
    # ``from app.engine import risk`` would appear as "app.engine.risk".
    assert "app.engine.risk" not in imports
    assert "app.engine" not in imports or "app.engine.risk" not in imports