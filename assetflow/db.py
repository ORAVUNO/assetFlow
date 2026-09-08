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
from typing import List, Optional, Sequence

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


class Connection(Base):
    """A configured adapter **instance** (connection).

    assetFlow supports many connections of the same adapter *kind* — e.g. two
    Tufin servers or three Elasticsearch clusters — each with a user-chosen
    ``label``. The connection ``id`` is the stable key everything else
    (``fetch_runs``, ``schedules``, watermarks, changes) is scoped by, so each
    instance keeps its own data. Remembered credentials are stored here as JSON
    (plaintext, local file — the same posture as ``.env``; gitignored)."""

    __tablename__ = "connections"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(256), default="")
    secrets_json: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "has_secrets": bool(self.secrets_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Ticket(Base):
    """An imported firewall change-request ticket, used to authorize changes.

    Populated from the enterprise's own ticketing system (CSV/JSON import). Each
    row is one approved requested access line item — device + source +
    destination + service + action + change window — which the reconciliation
    engine matches detected changes against. Replaced wholesale on each import.
    """

    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), index=True)
    ticket_id: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="")
    change_type: Mapped[str] = mapped_column(String(32), default="")
    device: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(Text, default="")
    destination: Mapped[str] = mapped_column(Text, default="")
    service: Mapped[str] = mapped_column(String(128), default="")
    action: Mapped[str] = mapped_column(String(32), default="")
    window_start: Mapped[str] = mapped_column(String(64), default="")
    window_end: Mapped[str] = mapped_column(String(64), default="")
    requester: Mapped[str] = mapped_column(String(256), default="")
    approver: Mapped[str] = mapped_column(String(256), default="")
    expiry: Mapped[str] = mapped_column(String(64), default="")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "ticket_id": self.ticket_id, "status": self.status,
            "change_type": self.change_type, "device": self.device,
            "source": self.source, "destination": self.destination,
            "service": self.service, "action": self.action,
            "window_start": self.window_start, "window_end": self.window_end,
            "requester": self.requester, "approver": self.approver, "expiry": self.expiry,
        }


# Ticket field name → the aliases an ITSM export might use (case-insensitive).
_TICKET_ALIASES = {
    "ticket_id": ("ticket_id", "ticket", "id", "number", "cr", "change", "ref"),
    "status": ("status", "state", "approval", "approval_status"),
    "change_type": ("change_type", "type", "operation", "action_type"),
    "device": ("device", "firewall", "host", "target", "ci", "device_name"),
    "source": ("source", "src", "source_ip", "src_ip", "from"),
    "destination": ("destination", "dst", "dest", "dest_ip", "dst_ip", "to"),
    "service": ("service", "port", "ports", "service_port", "protocol_port"),
    "action": ("action", "rule_action", "permit", "allow_deny"),
    "window_start": ("window_start", "start", "planned_start", "implementation_start", "approved_at"),
    "window_end": ("window_end", "end", "planned_end", "implementation_end", "expiry"),
    "requester": ("requester", "requested_by", "requestor"),
    "approver": ("approver", "approved_by", "authorizer"),
    "expiry": ("expiry", "expires", "expiry_date", "valid_until"),
}


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
    entity: Mapped[str] = mapped_column(String(16), default="rule")
    device_name: Mapped[str] = mapped_column(String(256), default="")
    changed_by: Mapped[str] = mapped_column(String(256), default="")
    changed_at: Mapped[str] = mapped_column(String(64), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    changed_fields: Mapped[str] = mapped_column(String(256), default="")
    risk: Mapped[str] = mapped_column(String(64), default="")
    blast_radius: Mapped[str] = mapped_column(String(16), default="")
    action: Mapped[str] = mapped_column(String(64), default="")  # the REVISION action
    policy_package: Mapped[str] = mapped_column(String(256), default="")
    src_zone: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(Text, default="")
    dst_zone: Mapped[str] = mapped_column(String(256), default="")
    destination: Mapped[str] = mapped_column(Text, default="")
    service: Mapped[str] = mapped_column(Text, default="")
    rule_action: Mapped[str] = mapped_column(String(32), default="")  # accept/drop/reject
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
            "revision.action": self.action,
            "policy_package": self.policy_package,
            "change_type": self.change_type,
            "entity": self.entity,
            "rule.uid": self.rule_uid,
            "summary": self.summary,
            "changed_fields": self.changed_fields,
            "risk": self.risk,
            "blast_radius": self.blast_radius,
            "src_zone": self.src_zone,
            "source": self.source,
            "dst_zone": self.dst_zone,
            "destination": self.destination,
            "service": self.service,
            "rule.action": self.rule_action,
            "before": self.before,
            "after": self.after,
            "authorized": self.authorized,
            "requester": self.requester,
        }


# Column order for the change-log view (matches the change_detail result shape).
_CHANGE_COLUMNS = [
    "host.name", "revision.id", "@timestamp", "changed_by", "revision.action", "policy_package",
    "change_type", "entity", "rule.uid", "summary", "changed_fields", "risk", "blast_radius",
    "src_zone", "source", "dst_zone", "destination", "service", "rule.action",
    "before", "after", "authorized", "requester",
]


class SnapshotChange(Base):
    """Deduplicated inventory-drift log (the Elasticsearch analogue of the Tufin
    change log). Each row is one ``(host, attribute, value)`` that appeared or
    disappeared between two saved snapshots of a query, keyed so re-diffing the
    same snapshot pair never duplicates a transition."""

    __tablename__ = "snapshot_changes"
    __table_args__ = (
        UniqueConstraint(
            "adapter", "query_id", "host", "attribute", "change_type", "value", "new_run_id",
            name="uq_snapshot_change",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(64), index=True)
    query_id: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[str] = mapped_column(String(256), default="")
    attribute: Mapped[str] = mapped_column(String(128), default="")
    change_type: Mapped[str] = mapped_column(String(16), default="")
    value: Mapped[str] = mapped_column(Text, default="")
    old_run_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    new_run_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "host.name": self.host,
            "query": self.query_id,
            "attribute": self.attribute,
            "change_type": self.change_type,
            "value": self.value,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


_DRIFT_COLUMNS = ["host.name", "query", "attribute", "change_type", "value", "detected_at"]


class RemedyTicket(Base):
    """Durable per-ticket record — the BMC Remedy ticket *system of record*.

    Unlike the per-fetch snapshots in ``fetch_runs`` (which keep every fetch as
    history), this table holds **one row per ticket**, keyed by
    ``(adapter, resource, ticket_id)`` and upserted in place on every fetch. It
    is how an operator sees the current state of every ticket ever fetched, with
    ``first_seen`` / ``last_seen`` bookends, regardless of how many times the
    ticket has been re-fetched. Status/field transitions are logged separately in
    ``remedy_ticket_changes`` (see :class:`RemedyTicketChange`)."""

    __tablename__ = "remedy_tickets"
    __table_args__ = (
        UniqueConstraint("adapter", "resource", "ticket_id", name="uq_remedy_ticket"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(96), index=True)
    resource: Mapped[str] = mapped_column(String(64), index=True)
    ticket_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(64), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    modified: Mapped[str] = mapped_column(String(64), default="")
    state_json: Mapped[str] = mapped_column(Text, default="{}")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "resource": self.resource,
            "status": self.status,
            "summary": self.summary,
            "modified": self.modified,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "updated_at": _iso(self.updated_at),
        }


class RemedyTicketChange(Base):
    """Deduplicated log of field transitions on BMC Remedy tickets.

    Each row is one tracked field changing on one ticket between fetches — e.g.
    ``INC001 status "Assigned" → "Resolved"``. Keyed so re-fetching the same
    unchanged ticket never re-logs a transition, while a genuine flip-flop across
    runs is preserved (``run_id`` is part of the key). This is the "what changed
    on previously fetched tickets" feed the operator watches."""

    __tablename__ = "remedy_ticket_changes"
    __table_args__ = (
        UniqueConstraint(
            "adapter", "resource", "ticket_id", "field", "old_value", "new_value",
            "run_id", name="uq_remedy_ticket_change",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(96), index=True)
    resource: Mapped[str] = mapped_column(String(64), index=True)
    ticket_id: Mapped[str] = mapped_column(String(128), index=True)
    field: Mapped[str] = mapped_column(String(64), default="")
    old_value: Mapped[str] = mapped_column(Text, default="")
    new_value: Mapped[str] = mapped_column(Text, default="")
    run_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def to_record(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "resource": self.resource,
            "field": self.field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "detected_at": _iso(self.detected_at),
        }


_TICKET_COLUMNS = [
    "ticket_id", "resource", "status", "summary", "modified",
    "first_seen", "last_seen", "updated_at",
]
_TICKET_CHANGE_COLUMNS = [
    "ticket_id", "resource", "field", "old_value", "new_value", "detected_at",
]


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


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
    _migrate_added_columns(_engine)
    _Session = sessionmaker(_engine, expire_on_commit=False, class_=Session)
    return _engine


# Columns added to existing tables after their first release. ``create_all``
# only creates missing *tables*, not missing *columns*, so an already-created
# SQLite database needs these added by hand (all nullable text, default '').
_ADDED_COLUMNS = {
    "tufin_changes": [
        "entity", "summary", "changed_fields", "risk", "blast_radius", "action",
        "policy_package", "src_zone", "source", "dst_zone", "destination", "service",
        "rule_action",
    ],
}


def _migrate_added_columns(engine) -> None:
    from sqlalchemy import text

    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            try:
                existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            except Exception:  # pragma: no cover - non-sqlite backends
                existing = set()
                if not str(engine.url).startswith("sqlite"):
                    continue
            if not existing:
                continue  # table absent (a fresh DB already has the new schema)
            for name in columns:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} TEXT DEFAULT ''"))


def _session() -> Session:
    if _Session is None:
        init_engine()
    assert _Session is not None
    return _Session()


# -- connections (adapter instances) ----------------------------------------


def list_connections(kind: Optional[str] = None) -> List[dict]:
    with _session() as s:
        stmt = select(Connection)
        if kind:
            stmt = stmt.where(Connection.kind == kind)
        return [c.to_record() for c in s.scalars(stmt.order_by(Connection.created_at, Connection.id))]


def get_connection(connection_id: str) -> Optional[dict]:
    with _session() as s:
        row = s.get(Connection, connection_id)
        return row.to_record() if row else None


def add_connection(connection_id: str, kind: str, label: str) -> dict:
    with _session() as s:
        row = Connection(
            id=connection_id, kind=kind, label=label,
            secrets_json="", created_at=datetime.now(timezone.utc),
        )
        s.add(row)
        s.commit()
        return row.to_record()


def update_connection_label(connection_id: str, label: str) -> Optional[dict]:
    with _session() as s:
        row = s.get(Connection, connection_id)
        if row is None:
            return None
        row.label = label
        s.commit()
        return row.to_record()


def delete_connection(connection_id: str) -> bool:
    with _session() as s:
        row = s.get(Connection, connection_id)
        if row is None:
            return False
        s.delete(row)
        s.commit()
        return True


def set_connection_secrets(connection_id: str, secrets: Optional[dict]) -> None:
    """Store (or clear, when ``secrets`` is falsy) a connection's remembered
    credentials as JSON."""
    with _session() as s:
        row = s.get(Connection, connection_id)
        if row is None:
            return
        row.secrets_json = json.dumps(secrets) if secrets else ""
        s.commit()


def get_connection_secrets(connection_id: str) -> Optional[dict]:
    with _session() as s:
        row = s.get(Connection, connection_id)
        if row is None or not row.secrets_json:
            return None
        try:
            return json.loads(row.secrets_json)
        except ValueError:
            return None


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


def last_two_fetches(adapter: str, query_id: str) -> List[dict]:
    """The two most recent fetches (with data) for a query, newest first."""
    with _session() as s:
        stmt = (
            select(FetchRun)
            .where(FetchRun.adapter == adapter, FetchRun.query_id == query_id)
            .order_by(desc(FetchRun.ran_at))
            .limit(2)
        )
        return [r.to_record(include_data=True) for r in s.scalars(stmt)]


def record_snapshot_changes(
    adapter: str,
    query_id: str,
    rows: List[list],
    old_run_id: Optional[int],
    new_run_id: Optional[int],
    detected_at: Optional[datetime] = None,
) -> int:
    """Upsert drift rows (``[host, attribute, change_type, value]``) into the
    deduplicated snapshot-change log. Returns how many were newly inserted."""
    if not rows:
        return 0
    when = detected_at or datetime.now(timezone.utc)
    if isinstance(when, str):
        try:
            when = datetime.fromisoformat(when)
        except ValueError:
            when = datetime.now(timezone.utc)
    with _session() as s:
        existing = {
            (c.host, c.attribute, c.change_type, c.value)
            for c in s.scalars(
                select(SnapshotChange).where(
                    SnapshotChange.adapter == adapter,
                    SnapshotChange.query_id == query_id,
                    SnapshotChange.new_run_id == new_run_id,
                )
            )
        }
        inserted = 0
        for row in rows:
            host, attribute, change_type, value = (list(row) + ["", "", "", ""])[:4]
            key = (str(host), str(attribute), str(change_type), str(value))
            if key in existing:
                continue
            existing.add(key)
            s.add(
                SnapshotChange(
                    adapter=adapter,
                    query_id=query_id,
                    host=str(host),
                    attribute=str(attribute),
                    change_type=str(change_type),
                    value=str(value),
                    old_run_id=old_run_id,
                    new_run_id=new_run_id,
                    detected_at=when,
                )
            )
            inserted += 1
        s.commit()
        return inserted


def snapshot_change_log(adapter: str, limit: int = 1000) -> dict:
    """Return the deduplicated inventory-drift log for an adapter (newest first)."""
    with _session() as s:
        stmt = (
            select(SnapshotChange)
            .where(SnapshotChange.adapter == adapter)
            .order_by(desc(SnapshotChange.id))
            .limit(limit)
        )
        rows = [c.to_record() for c in s.scalars(stmt)]
    return {
        "columns": [{"name": c} for c in _DRIFT_COLUMNS],
        "rows": [[rec[c] for c in _DRIFT_COLUMNS] for rec in rows],
    }


def record_ticket_states(
    adapter: str,
    resource: str,
    result,
    run_id: Optional[int] = None,
    id_col: str = "",
    tracked: Sequence[str] = (),
) -> dict:
    """Upsert a ticket fetch into the durable ticket sink and change log.

    ``result`` is a ``QueryResult`` for a ticket resource (incidents / changes).
    For each row keyed by ``id_col`` (e.g. ``incident.id``):

    * **A — durable sink** (:class:`RemedyTicket`): the ticket is inserted the
      first time it is seen and updated in place thereafter (status/summary/
      modified/full-state + ``last_seen``), so there is exactly one row per
      ticket no matter how many times it is fetched.
    * **B — change log** (:class:`RemedyTicketChange`): every ``tracked`` field
      whose stored value differs from the incoming value is logged as one
      transition (old → new), deduplicated so re-fetching an unchanged ticket
      records nothing.

    Returns ``{"new": …, "updated": …, "transitions": …}``.
    """
    rows = result.to_dicts()
    if not rows:
        return {"new": 0, "updated": 0, "transitions": 0}
    ids = {str(r.get(id_col, "")) for r in rows if str(r.get(id_col, ""))}
    now = datetime.now(timezone.utc)
    new = updated = transitions = 0
    with _session() as s:
        existing = {
            t.ticket_id: t
            for t in s.scalars(
                select(RemedyTicket).where(
                    RemedyTicket.adapter == adapter,
                    RemedyTicket.resource == resource,
                    RemedyTicket.ticket_id.in_(ids),
                )
            )
        }
        # Change keys already recorded for this run, so re-processing the same
        # run (idempotency) never double-logs a transition.
        seen_changes = {
            (c.ticket_id, c.field, c.old_value, c.new_value)
            for c in s.scalars(
                select(RemedyTicketChange).where(
                    RemedyTicketChange.adapter == adapter,
                    RemedyTicketChange.resource == resource,
                    RemedyTicketChange.run_id == run_id,
                )
            )
        }
        for r in rows:
            tid = str(r.get(id_col, ""))
            if not tid:
                continue
            state = {k: ("" if v is None else str(v)) for k, v in r.items()}
            status = str(r.get("status", ""))
            summary = str(r.get("summary", ""))
            modified = str(r.get("modified", ""))
            ticket = existing.get(tid)
            if ticket is None:
                ticket = RemedyTicket(
                    adapter=adapter, resource=resource, ticket_id=tid,
                    status=status, summary=summary, modified=modified,
                    state_json=json.dumps(state, default=str),
                    first_seen=now, last_seen=now, updated_at=now,
                )
                s.add(ticket)
                existing[tid] = ticket  # guard against the same id twice in a batch
                new += 1
                continue
            try:
                old_state = json.loads(ticket.state_json or "{}")
            except ValueError:
                old_state = {}
            changed = False
            for field in tracked:
                ov = str(old_state.get(field, ""))
                nv = str(r.get(field, "") or "")
                if ov == nv:
                    continue
                changed = True
                key = (tid, field, ov, nv)
                if key in seen_changes:
                    continue
                seen_changes.add(key)
                s.add(
                    RemedyTicketChange(
                        adapter=adapter, resource=resource, ticket_id=tid,
                        field=field, old_value=ov, new_value=nv,
                        run_id=run_id, detected_at=now,
                    )
                )
                transitions += 1
            ticket.status = status
            ticket.summary = summary
            ticket.modified = modified
            ticket.state_json = json.dumps(state, default=str)
            ticket.last_seen = now
            if changed:
                ticket.updated_at = now
            updated += 1
        s.commit()
    return {"new": new, "updated": updated, "transitions": transitions}


def ticket_states(
    adapter: str, resource: Optional[str] = None, limit: int = 5000
) -> dict:
    """Return the durable ticket sink for an adapter (most-recently-updated first)."""
    with _session() as s:
        stmt = select(RemedyTicket).where(RemedyTicket.adapter == adapter)
        if resource:
            stmt = stmt.where(RemedyTicket.resource == resource)
        stmt = stmt.order_by(desc(RemedyTicket.updated_at)).limit(limit)
        rows = [t.to_record() for t in s.scalars(stmt)]
    return {
        "columns": [{"name": c} for c in _TICKET_COLUMNS],
        "rows": [[rec[c] for c in _TICKET_COLUMNS] for rec in rows],
    }


def ticket_change_log(
    adapter: str, resource: Optional[str] = None, limit: int = 1000
) -> dict:
    """Return the deduplicated ticket change log for an adapter (newest first)."""
    with _session() as s:
        stmt = select(RemedyTicketChange).where(RemedyTicketChange.adapter == adapter)
        if resource:
            stmt = stmt.where(RemedyTicketChange.resource == resource)
        stmt = stmt.order_by(desc(RemedyTicketChange.id)).limit(limit)
        rows = [c.to_record() for c in s.scalars(stmt)]
    return {
        "columns": [{"name": c} for c in _TICKET_CHANGE_COLUMNS],
        "rows": [[rec[c] for c in _TICKET_CHANGE_COLUMNS] for rec in rows],
    }


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
                    entity=str(r.get("entity", "rule") or "rule"),
                    device_name=str(r.get("host.name", "")),
                    changed_by=str(r.get("changed_by", "")),
                    changed_at=str(r.get("@timestamp", "")),
                    summary=str(r.get("summary", "")),
                    changed_fields=str(r.get("changed_fields", "")),
                    risk=str(r.get("risk", "")),
                    blast_radius=str(r.get("blast_radius", "")),
                    action=str(r.get("revision.action", r.get("action", ""))),
                    policy_package=str(r.get("policy_package", "")),
                    src_zone=str(r.get("src_zone", "")),
                    source=str(r.get("source", "")),
                    dst_zone=str(r.get("dst_zone", "")),
                    destination=str(r.get("destination", "")),
                    service=str(r.get("service", "")),
                    rule_action=str(r.get("rule.action", "")),
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


def change_dashboard(adapter: str, recent: int = 25, top: int = 10) -> dict:
    """Aggregate the change log for an adapter into dashboard figures.

    Returns totals, counts by change type / authorization / device / admin, and
    the most recent changes — all from the deduplicated ``tufin_changes`` sink.
    """
    with _session() as s:
        base = select(TufinChange).where(TufinChange.adapter == adapter)
        total = s.scalar(select(func.count()).select_from(base.subquery())) or 0

        def grouped(col, limit=None):
            stmt = (
                select(col, func.count().label("n"))
                .where(TufinChange.adapter == adapter)
                .group_by(col)
                .order_by(desc("n"))
            )
            if limit:
                stmt = stmt.limit(limit)
            return [{"key": (k or ""), "count": n} for k, n in s.execute(stmt).all()]

        by_type = {row["key"]: row["count"] for row in grouped(TufinChange.change_type)}
        by_auth = {row["key"]: row["count"] for row in grouped(TufinChange.authorized)}
        by_action = {row["key"]: row["count"] for row in grouped(TufinChange.action)}
        by_risk = {row["key"]: row["count"] for row in grouped(TufinChange.risk) if row["key"]}
        by_device = grouped(TufinChange.device_name, top)
        by_admin = grouped(TufinChange.changed_by, top)

        recent_stmt = (
            select(TufinChange)
            .where(TufinChange.adapter == adapter)
            .order_by(desc(TufinChange.id))
            .limit(recent)
        )
        recent_rows = [c.to_record() for c in s.scalars(recent_stmt)]

    return {
        "total_changes": total,
        "by_type": by_type,
        "by_authorization": by_auth,
        "by_action": by_action,
        "by_risk": by_risk,
        "top_devices": by_device,
        "top_admins": by_admin,
        "recent": {
            "columns": [{"name": c} for c in _CHANGE_COLUMNS],
            "rows": [[rec[c] for c in _CHANGE_COLUMNS] for rec in recent_rows],
        },
    }


# -- change-request tickets (authorization source of truth) -----------------


def parse_tickets_csv(text: str) -> List[dict]:
    """Parse a CSV export into normalized ticket dicts (header aliases honored)."""
    import csv
    import io

    reader = csv.DictReader(io.StringIO(text))
    header_map = {}
    for raw in (reader.fieldnames or []):
        key = (raw or "").strip().lower().replace(" ", "_")
        for field, aliases in _TICKET_ALIASES.items():
            if key in aliases and field not in header_map.values():
                header_map[raw] = field
                break
    out: List[dict] = []
    for row in reader:
        rec = {field: "" for field in _TICKET_ALIASES}
        for raw, value in row.items():
            field = header_map.get(raw)
            if field:
                rec[field] = str(value or "").strip()
        if any(rec.values()):
            out.append(rec)
    return out


def replace_tickets(adapter: str, tickets: List[dict]) -> int:
    """Replace all tickets for an adapter with the given set; return the count."""
    now = datetime.now(timezone.utc)
    with _session() as s:
        s.query(Ticket).filter(Ticket.adapter == adapter).delete()
        for t in tickets:
            s.add(Ticket(
                adapter=adapter,
                ticket_id=str(t.get("ticket_id", "")),
                status=str(t.get("status", "")),
                change_type=str(t.get("change_type", "")),
                device=str(t.get("device", "")),
                source=str(t.get("source", "")),
                destination=str(t.get("destination", "")),
                service=str(t.get("service", "")),
                action=str(t.get("action", "")),
                window_start=str(t.get("window_start", "")),
                window_end=str(t.get("window_end", "")),
                requester=str(t.get("requester", "")),
                approver=str(t.get("approver", "")),
                expiry=str(t.get("expiry", "")),
                imported_at=now,
            ))
        s.commit()
        return len(tickets)


def list_tickets(adapter: str) -> List[dict]:
    with _session() as s:
        stmt = select(Ticket).where(Ticket.adapter == adapter).order_by(Ticket.id)
        return [t.to_record() for t in s.scalars(stmt)]


def clear_tickets(adapter: str) -> int:
    with _session() as s:
        n = s.query(Ticket).filter(Ticket.adapter == adapter).delete()
        s.commit()
        return n


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
