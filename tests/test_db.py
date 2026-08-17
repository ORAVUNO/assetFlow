"""Tests for the SQLite persistence layer."""

from assetflow import db
from assetflow.models import Query, Status
from assetflow.runner import QueryResult

RESULT = QueryResult(
    columns=[{"name": "host.name"}, {"name": "LoginCount"}],
    rows=[["host-a", 5], ["host-b", 2]],
)
Q = Query(
    id="AI001", category="Identity Intelligence", name="User Device Mapping",
    status=Status.validated, purpose="x", esql_query="FROM logs-*", validated=True,
)


def setup_db(tmp_path):
    db.init_engine(f"sqlite:///{tmp_path}/t.db")


def test_save_and_latest(tmp_path):
    setup_db(tmp_path)
    rec = db.save_fetch("elasticsearch", Q, RESULT, limit=100, time_range="7d")
    assert rec["row_count"] == 2
    assert rec["time_range"] == "7d"

    latest = db.latest_fetch("elasticsearch", "AI001")
    assert latest["rows"][0] == ["host-a", 5]
    assert latest["limit"] == 100


def test_latest_is_most_recent(tmp_path):
    setup_db(tmp_path)
    db.save_fetch("elasticsearch", Q, RESULT, limit=1, time_range=None)
    r2 = QueryResult(columns=RESULT.columns, rows=[["host-c", 9]])
    db.save_fetch("elasticsearch", Q, r2, limit=2, time_range="24h")
    latest = db.latest_fetch("elasticsearch", "AI001")
    assert latest["rows"] == [["host-c", 9]]
    assert latest["limit"] == 2
    assert len(db.history("elasticsearch", "AI001")) == 2


def test_latest_missing_returns_none(tmp_path):
    setup_db(tmp_path)
    assert db.latest_fetch("elasticsearch", "AI999") is None
