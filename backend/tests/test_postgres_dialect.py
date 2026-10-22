"""PostgreSQL compatibility of the schema (DDL level).

The suite runs on SQLite by default and on PostgreSQL when
``CRIX_TEST_DATABASE_URL`` is set (see docker-compose.yml). This test compiles
every table for the PostgreSQL dialect with no server required, so a dialect-only
breakage (an unsupported column type, for example) fails fast in CI.
"""
from __future__ import annotations

import app.models  # noqa: F401  (register all mappers)
from sqlalchemy import create_mock_engine
from sqlalchemy.schema import CreateTable

from app.db import Base


def _compile_for_postgres() -> list[str]:
    statements: list[str] = []
    engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *args, **kwargs: statements.append(
            str(sql.compile(dialect=engine.dialect))
        ),
    )
    Base.metadata.create_all(engine)
    return statements


def test_all_tables_compile_for_postgres_dialect():
    statements = _compile_for_postgres()
    assert statements, "expected DDL statements"
    ddl = "\n".join(statements)
    for table in ("organizations", "memberships", "invitations", "org_assets",
                  "asset_dependencies", "admin_view_audit_log"):
        assert CreateTable  # noqa: B018 - keep import used
        assert table in ddl, f"{table} missing from PostgreSQL DDL"


def test_postgres_ddl_has_no_sqlite_only_types():
    ddl = "\n".join(_compile_for_postgres()).upper()
    # SQLite-only affinity that would be wrong on PostgreSQL.
    assert "DATETIME" not in ddl
    assert "VARCHAR" in ddl  # String maps to VARCHAR on PG