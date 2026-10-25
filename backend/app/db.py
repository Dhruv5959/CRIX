"""Database engine, session factory, and declarative base."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    connect_args = {}
    if url.startswith("sqlite"):
        # Allow use across FastAPI's threadpool.
        connect_args = {"check_same_thread": False}
        return create_engine(url, connect_args=connect_args, future=True)

    settings = get_settings()
    # A Render web service is a persistent process. Keep a bounded SQLAlchemy
    # pool, validate a connection before each checkout, and recycle old
    # connections so stale Supabase-pooler sockets do not surface as 500s.
    return create_engine(
        url,
        future=True,
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_recycle=settings.database_pool_recycle_seconds,
    )


_engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def get_engine():
    return _engine


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _sql_literal(value: object) -> str | None:
    """Render a Python scalar as a SQL literal, or None if unsupported."""
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None


def init_db() -> None:
    """Create tables. Used in tests / local dev; prod uses Alembic.

    Also performs *additive* column migrations: ``create_all`` is a no-op for
    tables that already exist, so a column added to a model would otherwise be
    silently missing from a pre-existing dev database. This inspects each table
    and issues ``ALTER TABLE ... ADD COLUMN`` for columns the model declares but
    the database does not have. It only ever adds — it never drops or rewrites —
    so it is safe to run on every startup.
    """
    from sqlalchemy import inspect, text

    from app import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=_engine)

    inspector = inspect(_engine)
    existing_tables = set(inspector.get_table_names())
    with _engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            have = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue

                literal = None
                if column.default is not None and column.default.is_scalar:
                    literal = _sql_literal(column.default.arg)

                # A NOT NULL column on a table with existing rows needs a
                # constant default or the ALTER fails. Skip rather than break.
                if not column.nullable and literal is None:
                    continue

                ddl = (
                    f'ALTER TABLE "{table.name}" '
                    f'ADD COLUMN "{column.name}" {column.type.compile(_engine.dialect)}'
                )
                if literal is not None:
                    ddl += f" DEFAULT {literal}"
                conn.execute(text(ddl))

                if literal is not None and not column.nullable:
                    conn.execute(
                        text(
                            f'UPDATE "{table.name}" SET "{column.name}" = {literal} '
                            f'WHERE "{column.name}" IS NULL'
                        )
                    )
