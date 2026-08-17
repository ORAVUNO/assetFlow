"""SQLite persistence for fetched adapter data (via SQLAlchemy).

Every successful fetch is stored as a row in ``fetch_runs`` — the columns and
row values are kept as JSON so any adapter's shape fits. The most recent run
per (adapter, query) is the "latest result"; older runs form the history.

The database is a single local file (``assetflow.db`` by default) and is
gitignored — real fetched telemetry never leaves the machine. Point
``DATABASE_URL`` at Postgres later without changing callers.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import DateTime, Integer, String, Text, create_engine, desc, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .models import Query
from .runner import QueryResult

DEFAULT_DB_URL = "sqlite:///assetflow.db"


class Base(DeclarativeBase):
    pass


class FetchRun(Base):
    __tablename__ = "fetch_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), index=True)
    query_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(32), default="")
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    limit_n: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    time_range: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    columns_json: Mapped[str] = mapped_column(Text, default="[]")
    rows_json: Mapped[str] = mapped_column(Text, default="[]")

    def to_record(self, include_data: bool = True) -> dict:
        rec = {
            "run_id": self.id,
            "adapter": self.adapter,
            "query_id": self.query_id,
            "name": self.name,
            "status": self.status,
            "ran_at": self.ran_at.isoformat() if self.ran_at else None,
            "limit": self.limit_n,
            "time_range": self.time_range,
            "row_count": self.row_count,
        }
        if include_data:
            rec["columns"] = json.loads(self.columns_json)
            rec["rows"] = json.loads(self.rows_json)
        return rec


_engine = None
_Session: Optional[sessionmaker] = None


def init_engine(url: Optional[str] = None):
    """Create (or recreate) the engine and ensure tables exist."""
    global _engine, _Session
    url = url or os.getenv("DATABASE_URL") or DEFAULT_DB_URL
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, future=True, connect_args=connect_args)
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(_engine, expire_on_commit=False, class_=Session)
    return _engine


def _session() -> Session:
    if _Session is None:
        init_engine()
    assert _Session is not None
    return _Session()


def save_fetch(
    adapter: str,
    query: Query,
    result: QueryResult,
    limit: Optional[int],
    time_range: Optional[str],
) -> dict:
    """Persist a fetch result and return its record."""
    with _session() as s:
        run = FetchRun(
            adapter=adapter,
            query_id=query.id,
            name=query.name,
            status=query.status.value,
            ran_at=datetime.now(timezone.utc),
            limit_n=limit,
            time_range=time_range,
            row_count=result.row_count,
            columns_json=json.dumps(result.columns, default=str),
            rows_json=json.dumps(result.rows, default=str),
        )
        s.add(run)
        s.commit()
        return run.to_record()


def latest_fetch(adapter: str, query_id: str, include_data: bool = True) -> Optional[dict]:
    """Return the most recent fetch for an (adapter, query), or None."""
    with _session() as s:
        stmt = (
            select(FetchRun)
            .where(FetchRun.adapter == adapter, FetchRun.query_id == query_id)
            .order_by(desc(FetchRun.ran_at))
            .limit(1)
        )
        run = s.scalars(stmt).first()
        return run.to_record(include_data) if run else None


def history(adapter: str, query_id: str, limit: int = 25) -> List[dict]:
    """Return recent fetch runs (newest first, metadata only)."""
    with _session() as s:
        stmt = (
            select(FetchRun)
            .where(FetchRun.adapter == adapter, FetchRun.query_id == query_id)
            .order_by(desc(FetchRun.ran_at))
            .limit(limit)
        )
        return [r.to_record(include_data=False) for r in s.scalars(stmt)]
