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
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    desc,
    func,
    select,
)
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


class ChangeWatermark(Base):
    """Last revision id already processed per (adapter, device).

    Powers the Tufin change-detail "since last seen" mode: each incremental
    fetch diffs only the revisions newer than this watermark, then advances it —
    so every change is reported exactly once, with no missed intermediate
    revisions and no re-processing of history.
    """

    __tablename__ = "tufin_change_watermarks"

    adapter: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision_id: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TufinChange(Base):
    """Deduplicated Tufin change-log sink.

    Every change-detail fetch (any mode — window, All time, or incremental)
    upserts its rows here keyed by the globally-unique revision id plus the rule
    and change type, so the same change is stored **exactly once** no matter how
    many times or in which mode it is fetched. This is the cumulative change log,
    separate from the per-fetch snapshots in ``fetch_runs``.
    """

    __tablename__ = "tufin_changes"
    __table_args__ = (
        UniqueConstraint(
            "adapter", "revision_id", "rule_uid", "change_type", name="uq_tufin_change"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), index=True)
    revision_id: Mapped[str] = mapped_column(String(64), default="")
    rule_uid: Mapped[str] = mapped_column(String(128), default="")
    change_type: Mapped[str] = mapped_column(String(16), default="")
    device_name: Mapped[str] = mapped_column(String(256), default="")
    changed_by: Mapped[str] = mapped_column(String(256), default="")
    changed_at: Mapped[str] = mapped_column(String(64), default="")
    before: Mapped[str] = mapped_column(Text, default="")
    after: Mapped[str] = mapped_column(Text, default="")
    authorized: Mapped[str] = mapped_column(String(32), default="")
    requester: Mapped[str] = mapped_column(String(256), default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "host.name": self.device_name,
            "revision.id": self.revision_id,
            "@timestamp": self.changed_at,
            "changed_by": self.changed_by,
            "change_type": self.change_type,
            "rule.uid": self.rule_uid,
            "before": self.before,
            "after": self.after,
            "authorized": self.authorized,
            "requester": self.requester,
        }


# Column order for the change-log view (matches the change_detail result shape).
_CHANGE_COLUMNS = [
    "host.name", "revision.id", "@timestamp", "changed_by", "change_type",
    "rule.uid", "before", "after", "authorized", "requester",
]


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands back naive datetimes; treat stored times as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class Schedule(Base):
    """A recurring fetch: run ``query_id`` (or '*' for every runnable query) on
    an adapter every ``interval_seconds``. Executed by the background scheduler
    while the web app is running."""

    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), index=True)
    query_id: Mapped[str] = mapped_column(String(64), default="*")  # '*' = all runnable
    interval_seconds: Mapped[int] = mapped_column(Integer)
    time_range: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    limit_n: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        last = _aware(self.last_run_at)
        nxt = None
        if last is not None:
            nxt = last + timedelta(seconds=self.interval_seconds)
        return {
            "id": self.id,
            "adapter": self.adapter,
            "query_id": self.query_id,
            "interval_seconds": self.interval_seconds,
            "time_range": self.time_range,
            "limit": self.limit_n,
            "enabled": self.enabled,
            "last_run_at": last.isoformat() if last else None,
            "next_run_at": nxt.isoformat() if nxt else None,
        }

    def is_due(self, now: datetime) -> bool:
        last = _aware(self.last_run_at)
        return last is None or (now - last).total_seconds() >= self.interval_seconds


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


def latest_all(adapter: Optional[str] = None, include_data: bool = True) -> List[dict]:
    """Latest fetch for every (adapter, query) — optionally scoped to one adapter.

    Used to build adapter-wide and platform-wide exports.
    """
    with _session() as s:
        grouped = select(
            FetchRun.adapter.label("a"),
            FetchRun.query_id.label("q"),
            func.max(FetchRun.ran_at).label("m"),
        )
        if adapter:
            grouped = grouped.where(FetchRun.adapter == adapter)
        grouped = grouped.group_by(FetchRun.adapter, FetchRun.query_id).subquery()
        stmt = (
            select(FetchRun)
            .join(
                grouped,
                (FetchRun.adapter == grouped.c.a)
                & (FetchRun.query_id == grouped.c.q)
                & (FetchRun.ran_at == grouped.c.m),
            )
            .order_by(FetchRun.adapter, FetchRun.query_id)
        )
        return [r.to_record(include_data) for r in s.scalars(stmt).all()]


def add_schedule(
    adapter: str,
    query_id: str,
    interval_seconds: int,
    time_range: Optional[str] = None,
    limit: Optional[int] = None,
    enabled: bool = True,
) -> dict:
    with _session() as s:
        sch = Schedule(
            adapter=adapter,
            query_id=query_id or "*",
            interval_seconds=max(1, int(interval_seconds)),
            time_range=time_range,
            limit_n=limit,
            enabled=enabled,
            created_at=datetime.now(timezone.utc),
        )
        s.add(sch)
        s.commit()
        return sch.to_record()


def list_schedules(adapter: Optional[str] = None) -> List[dict]:
    with _session() as s:
        stmt = select(Schedule)
        if adapter:
            stmt = stmt.where(Schedule.adapter == adapter)
        return [sc.to_record() for sc in s.scalars(stmt.order_by(Schedule.id))]


def delete_schedule(schedule_id: int) -> bool:
    with _session() as s:
        sch = s.get(Schedule, schedule_id)
        if sch is None:
            return False
        s.delete(sch)
        s.commit()
        return True


def set_schedule_enabled(schedule_id: int, enabled: bool) -> Optional[dict]:
    with _session() as s:
        sch = s.get(Schedule, schedule_id)
        if sch is None:
            return None
        sch.enabled = enabled
        s.commit()
        return sch.to_record()


def due_schedules(now: Optional[datetime] = None) -> List[dict]:
    """Enabled schedules whose interval has elapsed — as run-ready records."""
    now = now or datetime.now(timezone.utc)
    with _session() as s:
        out = []
        for sc in s.scalars(select(Schedule).where(Schedule.enabled.is_(True))):
            if sc.is_due(now):
                out.append({
                    "id": sc.id,
                    "adapter": sc.adapter,
                    "query_id": sc.query_id,
                    "time_range": sc.time_range,
                    "limit": sc.limit_n,
                })
        return out


def mark_schedule_ran(schedule_id: int, when: Optional[datetime] = None) -> None:
    with _session() as s:
        sch = s.get(Schedule, schedule_id)
        if sch is not None:
            sch.last_run_at = when or datetime.now(timezone.utc)
            s.commit()


def record_changes(adapter: str, result) -> int:
    """Upsert change-detail rows into the deduped change log; return new count.

    ``result`` is a ``QueryResult`` (columns + rows) from the change_detail
    resource. Rows already present (same adapter + revision id + rule uid +
    change type) are skipped, so re-fetching in any mode never duplicates a
    change. Returns how many rows were newly inserted.
    """
    rows = result.to_dicts()
    if not rows:
        return 0
    rev_ids = {str(r.get("revision.id", "")) for r in rows}
    with _session() as s:
        existing = {
            (r.revision_id, r.rule_uid, r.change_type)
            for r in s.scalars(
                select(TufinChange).where(
                    TufinChange.adapter == adapter,
                    TufinChange.revision_id.in_(rev_ids),
                )
            )
        }
        now = datetime.now(timezone.utc)
        inserted = 0
        for r in rows:
            key = (
                str(r.get("revision.id", "")),
                str(r.get("rule.uid", "")),
                str(r.get("change_type", "")),
            )
            if key in existing:  # already stored, or seen earlier in this batch
                continue
            existing.add(key)
            s.add(
                TufinChange(
                    adapter=adapter,
                    revision_id=key[0],
                    rule_uid=key[1],
                    change_type=key[2],
                    device_name=str(r.get("host.name", "")),
                    changed_by=str(r.get("changed_by", "")),
                    changed_at=str(r.get("@timestamp", "")),
                    before=str(r.get("before", "")),
                    after=str(r.get("after", "")),
                    authorized=str(r.get("authorized", "")),
                    requester=str(r.get("requester", "")),
                    first_seen_at=now,
                )
            )
            inserted += 1
        s.commit()
        return inserted


def change_log(adapter: str, limit: int = 1000) -> dict:
    """Return the deduplicated change log for an adapter (newest first)."""
    with _session() as s:
        stmt = (
            select(TufinChange)
            .where(TufinChange.adapter == adapter)
            .order_by(desc(TufinChange.id))
            .limit(limit)
        )
        rows = [c.to_record() for c in s.scalars(stmt)]
    return {
        "columns": [{"name": c} for c in _CHANGE_COLUMNS],
        "rows": [[rec[c] for c in _CHANGE_COLUMNS] for rec in rows],
    }


def get_change_watermark(adapter: str, device_id: str) -> Optional[str]:
    """Return the last processed revision id for a device, or None."""
    with _session() as s:
        row = s.get(ChangeWatermark, {"adapter": adapter, "device_id": device_id})
        return row.revision_id if row else None


def set_change_watermark(adapter: str, device_id: str, revision_id: str) -> None:
    """Record the newest revision id processed for a device."""
    with _session() as s:
        row = s.get(ChangeWatermark, {"adapter": adapter, "device_id": device_id})
        if row is None:
            s.add(
                ChangeWatermark(
                    adapter=adapter,
                    device_id=device_id,
                    revision_id=revision_id,
                    updated_at=datetime.now(timezone.utc),
                )
            )
        else:
            row.revision_id = revision_id
            row.updated_at = datetime.now(timezone.utc)
        s.commit()


class _DbWatermarkStore:
    """Adapter-scoped view over the change watermark table (get/set by device)."""

    def __init__(self, adapter: str):
        self.adapter = adapter

    def get(self, device_id: str) -> Optional[str]:
        return get_change_watermark(self.adapter, device_id)

    def set(self, device_id: str, revision_id: str) -> None:
        set_change_watermark(self.adapter, device_id, revision_id)


def watermark_store(adapter: str) -> _DbWatermarkStore:
    return _DbWatermarkStore(adapter)


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
