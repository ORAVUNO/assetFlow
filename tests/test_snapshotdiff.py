"""Tests for Elasticsearch inventory drift: snapshot diff + deduped drift log."""

from assetflow import db
from assetflow import snapshotdiff
from assetflow.models import Query, Status
from assetflow.runner import QueryResult


def _rec(columns, rows, run_id=None, ran_at="2026-01-01T00:00:00+00:00"):
    return {"columns": [{"name": c} for c in columns], "rows": rows,
            "run_id": run_id, "ran_at": ran_at}


def test_is_inventory_distinguishes_event_from_inventory():
    assert snapshotdiff.is_inventory([{"name": "host.name"}, {"name": "Applications"}]) is True
    # event feeds carry @timestamp -> not inventory
    assert snapshotdiff.is_inventory([{"name": "host.name"}, {"name": "@timestamp"}]) is False
    # no host key -> not inventory
    assert snapshotdiff.is_inventory([{"name": "service.name"}, {"name": "Hosts"}]) is False


def test_diff_detects_added_and_removed_list_items():
    cols = ["host.name", "Applications"]
    old = _rec(cols, [["h1", ["nginx", "sshd"]]])
    new = _rec(cols, [["h1", ["nginx", "docker"]]])  # sshd removed, docker added
    d = snapshotdiff.diff_snapshots(old, new)
    facts = {(r[2], r[3]) for r in d["rows"]}
    assert ("added", "docker") in facts
    assert ("removed", "sshd") in facts
    assert d["added"] == 1 and d["removed"] == 1


def test_diff_ignores_volatile_columns():
    # LoginCount/LastLogin change but user set is stable -> no drift.
    cols = ["host.name", "user.name", "LoginCount", "LastLogin"]
    old = _rec(cols, [["h1", "alice", 3, "t1"]])
    new = _rec(cols, [["h1", "alice", 9, "t2"]])
    d = snapshotdiff.diff_snapshots(old, new)
    assert d["rows"] == []


def test_diff_new_and_gone_hosts():
    cols = ["host.name", "user.name"]
    old = _rec(cols, [["h1", "alice"]])
    new = _rec(cols, [["h2", "bob"]])
    d = snapshotdiff.diff_snapshots(old, new)
    kinds = {(r[0], r[2], r[3]) for r in d["rows"]}
    assert ("h2", "added", "bob") in kinds
    assert ("h1", "removed", "alice") in kinds


def test_event_feed_yields_no_drift():
    cols = ["host.name", "@timestamp", "user.name"]
    old = _rec(cols, [["h1", "t1", "alice"]])
    new = _rec(cols, [["h1", "t2", "carol"]])
    assert snapshotdiff.diff_snapshots(old, new)["rows"] == []


def test_drift_log_dedupes_by_run(tmp_path):
    db.init_engine(f"sqlite:///{tmp_path}/d.db")
    rows = [["h1", "Applications", "added", "docker"], ["h1", "Applications", "removed", "sshd"]]
    # Same snapshot pair (same new_run_id) -> inserted once, re-record is a no-op.
    assert db.record_snapshot_changes("elasticsearch", "AI011", rows, 1, 2) == 2
    assert db.record_snapshot_changes("elasticsearch", "AI011", rows, 1, 2) == 0
    # A later snapshot pair (new run id) re-detecting a value records it again.
    assert db.record_snapshot_changes("elasticsearch", "AI011", [["h1", "Applications", "added", "docker"]], 2, 3) == 1
    log = db.snapshot_change_log("elasticsearch")
    assert len(log["rows"]) == 3
    assert [c["name"] for c in log["columns"]][:3] == ["host.name", "query", "attribute"]


def _inv_query(qid="AI011"):
    return Query(id=qid, category="Application Discovery", name="Host Application Mapping",
                 status=Status.validated, purpose="x", esql_query="FROM logs-*")


def test_service_records_drift_on_second_inventory_fetch(tmp_path):
    from assetflow import service
    from assetflow import adapters as adapters_mod
    db.init_engine(f"sqlite:///{tmp_path}/svc.db")
    a = adapters_mod.default_manager().get("elasticsearch")
    q = _inv_query()

    r1 = QueryResult(columns=[{"name": "host.name"}, {"name": "Applications"}], rows=[["h1", ["nginx"]]])
    rec1 = service.save_result(a, q, r1)
    assert rec1.get("drift") is None  # first fetch -> nothing to compare

    r2 = QueryResult(columns=[{"name": "host.name"}, {"name": "Applications"}], rows=[["h1", ["nginx", "docker"]]])
    rec2 = service.save_result(a, q, r2)
    assert rec2["drift"] == 1  # docker added
    assert any(r[4] == "docker" for r in db.snapshot_change_log("elasticsearch")["rows"])  # value col


def test_service_skips_drift_for_event_feed(tmp_path):
    from assetflow import service
    from assetflow import adapters as adapters_mod
    db.init_engine(f"sqlite:///{tmp_path}/evt.db")
    a = adapters_mod.default_manager().get("elasticsearch")
    q = Query(id="AI002", category="User Management Changes", name="User Created",
              status=Status.validated, purpose="x", esql_query="FROM logs-*")
    cols = [{"name": "host.name"}, {"name": "@timestamp"}]
    service.save_result(a, q, QueryResult(columns=cols, rows=[["h1", "t1"]]))
    rec = service.save_result(a, q, QueryResult(columns=cols, rows=[["h1", "t2"]]))
    assert rec.get("drift") is None  # event feed -> not diffed
    assert db.snapshot_change_log("elasticsearch")["rows"] == []
