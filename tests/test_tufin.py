"""Tests for the Tufin adapter, registry, and REST-response normalization.

No live SecureTrack is contacted: a FakeClient returns canned JSON payloads
keyed by request path, mirroring how the real client's ``get`` behaves.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import tufin_client as tufin_client_mod
from assetflow import tufin_runner as tufin_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry
from assetflow.runner import QueryResult

TUFIN_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "tufin_registry.yaml"


class FakeClient:
    """Path -> payload map; unknown paths raise so fallbacks are exercised."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.host = "tufin.test"

    def get(self, path):
        if path in self.mapping:
            return self.mapping[path]
        raise RuntimeError(f"404 {path}")


def _q(resource: str) -> Query:
    return Query(
        id="TUF999",
        category="Device Inventory",
        name="test",
        status=Status.partially_validated,
        purpose="test",
        resource=resource,
    )


DEVICES = {
    "devices.json?show_os_version=true": {
        "devices": [
            {
                "id": "1",
                "name": "HQ-Perimeter-FW",
                "vendor": "Cisco",
                "model": "FMC",
                "management_ip": "10.0.0.5",
                "os_version": "7.2",
                "domain": "KWALE",
            }
        ]
    }
}


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_tufin_registry_loads_and_validates():
    reg = load_registry(str(TUFIN_REGISTRY))
    assert reg.metadata.version == 1
    assert len(reg.queries) == 10
    assert len(reg.feeds) == 8
    # every query names a resource the runner knows how to fetch
    for q in reg.queries:
        assert q.resource in tufin_runner_mod._COLLECTORS
        assert q.is_runnable


# --------------------------------------------------------------------------- #
# Runner normalization
# --------------------------------------------------------------------------- #

def test_devices_resource_is_host_keyed():
    client = FakeClient(DEVICES)
    result = tufin_runner_mod.run_query(client, _q("devices"))
    assert result.column_names[0] == "host.name"
    assert result.rows[0][0] == "HQ-Perimeter-FW"
    assert "10.0.0.5" in result.rows[0]


def test_devices_derive_asset_type():
    mapping = {
        "devices.json?show_os_version=true": {"devices": [
            {"id": "1", "name": "HQ-FW", "vendor": "Cisco", "model": "asa", "parent_id": "9"},
            {"id": "9", "name": "FMC-Mgmt", "vendor": "Cisco", "model": "fmc"},
            {"id": "3", "name": "PA-vsys1", "vendor": "PaloAlto", "model": "PANOSDevice", "virtual_type": "vsys"},
            {"id": "4", "name": "Core-RTR", "vendor": "Cisco", "model": "router_ios"},
        ]}
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("devices"))
    by_name = {r[0]: dict(zip(result.column_names, r)) for r in result.rows}
    assert by_name["HQ-FW"]["asset.type"] == "Firewall"
    assert by_name["FMC-Mgmt"]["asset.type"] == "Firewall Management"   # model hint + is a parent
    assert by_name["PA-vsys1"]["asset.type"] == "Virtual Firewall (vsys)"
    assert by_name["Core-RTR"]["asset.type"] == "Router/Switch"


def test_devices_capture_full_dto():
    # Exact DetailedDeviceDTO shape from a live SecureTrack (R25-2).
    mapping = {"devices.json?show_os_version=true": {"devices": [{
        "context_name": "", "domain_id": "1", "domain_name": "Default", "id": "77",
        "ip": "192.168.104.91", "latest_revision": "3829", "model": "asa",
        "module_type": "", "module_uid": "", "name": "KWL-FP4150-ASA-01",
        "offline": False, "status": "Started", "topology": True, "vendor": "Cisco",
        "virtual_type": "",
    }]}}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("devices"))
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["host.name"] == "KWL-FP4150-ASA-01"
    assert row["device.id"] == "77"
    assert row["device.domain"] == "Default" and row["domain.id"] == "1"
    assert row["host.ip"] == "192.168.104.91"
    assert row["latest_revision"] == "3829"
    assert row["device.status"] == "Started"
    assert row["topology"] == "True"
    assert row["asset.type"] == "Firewall"


def test_revisions_expose_who_what_when():
    # Shape mirrors SecureTrack R25-2 RevisionDTO: id/revisionId, split
    # date+time, admin, guiClient, nested comment, and a tickets wrapper.
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [
            {
                "id": "1052",
                "revisionId": "37",
                "date": "2026-07-26",
                "time": "19:42:11",
                "admin": "jane.admin",
                "guiClient": "SmartConsole@10.2.44.18",
                "action": "Policy Installed",
                "policyPackage": "HQ perimeter policy",
                "authorizationStatus": "authorized",
                "comment": {"comment": "added vendor VPN rule", "editor": "jane.admin"},
                "tickets": {"ticket": [{"id": "CR-100", "source": "SecureChange"}]},
            }
        ]
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("revisions"))
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["host.name"] == "HQ-Perimeter-FW"
    assert row["revision.id"] == "1052"
    assert row["revision.number"] == "37"
    assert row["changed_by"] == "jane.admin"
    assert row["gui_client"] == "SmartConsole@10.2.44.18"
    assert row["ticket"] == "CR-100"
    assert row["policy_package"] == "HQ perimeter policy"
    assert row["action"] == "Policy Installed"
    assert row["comment"] == "added vendor VPN rule"


def test_rules_flatten_real_r25_2_fields():
    # R25-2 rules put source/dest/service under src_network/dst_network/
    # dst_service, with zones under src_zone/dst_zone.
    mapping = dict(DEVICES)
    mapping["devices/1/rules.json"] = {
        "rules": [
            {
                "uid": "{abc}",
                "name": "Allow web",
                "src_zone": [{"name": "DMZ"}],
                "src_network": [{"display_name": "net-a"}, {"display_name": "net-b"}],
                "dst_zone": [{"name": "INSIDE"}],
                "dst_network": [{"ip": "10.10.10.10"}],
                "dst_service": [{"display_name": "https"}],
                "action": "accept",
            },
            {"uid": "{any}", "name": "Any-any", "action": "drop"},  # no networks -> Any
        ]
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("rules"))
    rows = [dict(zip(result.column_names, r)) for r in result.rows]
    r0 = rows[0]
    assert r0["source"] == "net-a, net-b"
    assert r0["destination"] == "10.10.10.10"
    assert r0["service"] == "https"
    assert r0["src_zone"] == "DMZ" and r0["dst_zone"] == "INSIDE"
    assert r0["action"] == "accept"
    # a rule with no source/dest objects renders as Any
    assert rows[1]["source"] == "Any" and rows[1]["destination"] == "Any"


def test_cleanups_require_code_and_unwrap_shadowed_rule():
    mapping = dict(DEVICES)
    mapping["devices/1/cleanups.json?code=C01"] = {
        "cleanup_set": {"shadowed_rules_cleanup": {"shadowed_rules": {"shadowed_rule": [
            {"uid": "r5", "name": "dead rule", "comment": "shadowed by r1"},
        ]}}}
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("cleanups"))
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["host.name"] == "HQ-Perimeter-FW"
    assert row["rule.uid"] == "r5"
    assert row["cleanup.type"] == "fully_shadowed"


def test_zones_are_per_device():
    mapping = dict(DEVICES)
    mapping["devices/1/zones.json"] = {"zones": {"zones": [
        {"id": "7", "name": "DMZ", "global": False},
    ]}}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("zones"))
    assert result.column_names[0] == "host.name"
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["host.name"] == "HQ-Perimeter-FW"
    assert row["zone.name"] == "DMZ" and row["zone.id"] == "7"


def test_limit_caps_rows():
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [{"id": str(i), "date": "2026-07-26", "time": "00:00:00"} for i in range(10)]
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("revisions"), limit=3)
    assert result.row_count == 3


def test_time_range_filters_old_revisions():
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [
            {"id": "new", "date": recent, "admin": "a"},
            {"id": "old", "date": old, "admin": "b"},
        ]
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("revisions"), time_range="24h")
    ids = [dict(zip(result.column_names, r))["revision.id"] for r in result.rows]
    assert ids == ["new"]


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        tufin_runner_mod.run_query(FakeClient({}), _q("nonsense"))


def test_change_detail_diffs_revisions_with_authorization():
    # Device 1 has two revisions; rev 1051 -> 1052 adds a rule, modifies one
    # (service change), and removes one. change_authorization returns the verdict.
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [
            {"id": "1051", "date": "2026-07-25", "time": "08:00:00", "admin": "bob.admin"},
            {"id": "1052", "date": "2026-07-26", "time": "19:42:11", "admin": "jane.admin"},
        ]
    }
    mapping["revisions/1051/rules.json"] = {
        "rules": [
            {"uid": "r10", "source": "10.0.0.0/24", "destination": "db", "service": "tcp/8443", "action": "accept"},
            {"uid": "r20", "source": "any", "destination": "net", "service": "tcp/22", "action": "drop"},
        ]
    }
    mapping["revisions/1052/rules.json"] = {
        "rules": [
            {"uid": "r10", "source": "10.0.0.0/24", "destination": "db", "service": "tcp/443", "action": "accept"},
            {"uid": "r30", "source": "196.10.15.20", "destination": "vpn", "service": "tcp/3389", "action": "accept"},
        ]
    }
    mapping["change_authorization?old_version=1051&new_version=1052"] = {
        "change_authorization": {
            "status": "unauthorized",
            "tickets": {"ticket": [{"id": 55, "requester_display_name": "Alice Requester"}]},
        }
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"))
    rows = [dict(zip(result.column_names, r)) for r in result.rows]
    by_type = {(r["change_type"], r["rule.uid"]): r for r in rows}

    assert ("modified", "r10") in by_type
    assert ("added", "r30") in by_type
    assert ("removed", "r20") in by_type

    modified = by_type[("modified", "r10")]
    assert "tcp/8443" in modified["before"] and "tcp/443" in modified["after"]
    assert modified["changed_by"] == "jane.admin"
    assert modified["revision.id"] == "1052"
    assert modified["authorized"] == "unauthorized"
    assert modified["requester"] == "Alice Requester"
    # Full context: the changed rule's actual after-state fields, plus action.
    assert modified["source"] == "10.0.0.0/24"
    assert modified["destination"] == "db"
    assert modified["service"] == "tcp/443"
    # A removed rule carries its pre-change fields (there is no after-state).
    assert by_type[("removed", "r20")]["destination"] == "net"


def test_change_detail_automatic_action_labels_the_actor():
    # A revision with no admin but an "automatic" action -> changed_by filled.
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {"revisions": [
        {"id": "1", "date": "2026-01-01", "time": "00:00:00", "action": "automatic",
         "policyPackage": "KWL_DCN_INTERNET_ACP"},
        {"id": "2", "date": "2026-01-02", "time": "00:00:00", "action": "automatic",
         "policyPackage": "KWL_DCN_INTERNET_ACP"},  # no admin
    ]}
    mapping["revisions/1/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/80", "action": "accept"}]}
    mapping["revisions/2/rules.json"] = {"rules": [
        {"uid": "a", "service": "tcp/80", "action": "accept"},
        {"uid": "b", "src_network": "10.1.1.1", "dst_network": "web", "service": "tcp/443", "action": "accept"},
    ]}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"))
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["change_type"] == "added" and row["rule.uid"] == "b"
    assert row["action"] == "automatic"
    assert row["changed_by"] == "(automatic)"      # blank actor labelled from the action
    assert row["policy_package"] == "KWL_DCN_INTERNET_ACP"
    assert row["source"] == "10.1.1.1" and row["destination"] == "web"


def test_change_detail_ignores_pure_rename():
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [
            {"id": "1", "date": "2026-01-01", "time": "00:00:00", "admin": "a"},
            {"id": "2", "date": "2026-01-02", "time": "00:00:00", "admin": "a"},
        ]
    }
    # Same effect, only the name changed -> not a traffic change.
    mapping["revisions/1/rules.json"] = {"rules": [{"uid": "r1", "name": "old name", "source": "a", "destination": "b", "service": "tcp/80", "action": "accept"}]}
    mapping["revisions/2/rules.json"] = {"rules": [{"uid": "r1", "name": "new name", "source": "a", "destination": "b", "service": "tcp/80", "action": "accept"}]}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"))
    assert result.row_count == 0


def test_change_detail_single_revision_skipped():
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {"revisions": [{"id": "1", "date": "2026-01-01"}]}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"))
    assert result.row_count == 0


def _rev(rid, days_ago, action_svc):
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"id": rid, "date": ts.strftime("%Y-%m-%d"), "time": ts.strftime("%H:%M:%S"), "admin": f"admin{rid}"}


def test_change_detail_time_range_walks_window_with_baseline():
    # Four revisions: r1 (100d ago) baseline, then r2 (10d), r3 (5d), r4 (1d).
    # A 7-day range should diff r2->r3 and r3->r4 (r2 is the pre-window baseline
    # that lets the first in-window change be detected), i.e. changes at r3 & r4.
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [_rev("1", 100, None), _rev("2", 10, None), _rev("3", 5, None), _rev("4", 1, None)],
    }
    mapping["revisions/2/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/1", "action": "accept"}]}
    mapping["revisions/3/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/2", "action": "accept"}]}  # modified at r3
    mapping["revisions/4/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/2", "action": "accept"}, {"uid": "b", "service": "tcp/9", "action": "drop"}]}  # added b at r4
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"), time_range="7d")
    rows = [dict(zip(result.column_names, r)) for r in result.rows]
    changed_revs = sorted({r["revision.id"] for r in rows})
    assert changed_revs == ["3", "4"]  # r2->r3 modified, r3->r4 added; r1->r2 excluded
    assert {(r["change_type"], r["rule.uid"]) for r in rows} == {("modified", "a"), ("added", "b")}


def test_change_detail_range_excludes_old_only_history():
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [_rev("1", 400, None), _rev("2", 380, None)],
    }
    mapping["revisions/1/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/1", "action": "accept"}]}
    mapping["revisions/2/rules.json"] = {"rules": [{"uid": "a", "service": "tcp/2", "action": "accept"}]}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("change_detail"), time_range="24h")
    assert result.row_count == 0  # nothing changed inside the last 24h


class FakeStore:
    def __init__(self):
        self.data = {}

    def get(self, device_id):
        return self.data.get(device_id)

    def set(self, device_id, revision_id):
        self.data[device_id] = revision_id


def test_change_detail_incremental_baseline_then_since_last_seen():
    store = FakeStore()
    m = dict(DEVICES)
    m["devices/1/revisions.json"] = {"revisions": [
        {"id": "1", "date": "2026-01-01", "time": "00:00:00", "admin": "a"},
        {"id": "2", "date": "2026-01-02", "time": "00:00:00", "admin": "a"},
    ]}
    m["revisions/1/rules.json"] = {"rules": [{"uid": "r", "service": "tcp/1", "action": "accept"}]}
    m["revisions/2/rules.json"] = {"rules": [{"uid": "r", "service": "tcp/1", "action": "accept"}]}
    client = FakeClient(m)

    # First run establishes a baseline silently and records the watermark.
    r1 = tufin_runner_mod.run_query(client, _q("change_detail"), time_range="incremental", watermark_store=store)
    assert r1.row_count == 0
    assert store.get("1") == "2"

    # A new revision modifies rule r; the next run reports only that change.
    m["devices/1/revisions.json"]["revisions"].append(
        {"id": "3", "date": "2026-01-03", "time": "00:00:00", "admin": "jane"}
    )
    m["revisions/3/rules.json"] = {"rules": [{"uid": "r", "service": "tcp/2", "action": "accept"}]}
    r2 = tufin_runner_mod.run_query(client, _q("change_detail"), time_range="incremental", watermark_store=store)
    rows = [dict(zip(r2.column_names, row)) for row in r2.rows]
    assert len(rows) == 1
    assert rows[0]["change_type"] == "modified" and rows[0]["revision.id"] == "3"
    assert rows[0]["changed_by"] == "jane"
    assert store.get("1") == "3"

    # Nothing new since -> no rows, watermark unchanged.
    r3 = tufin_runner_mod.run_query(client, _q("change_detail"), time_range="incremental", watermark_store=store)
    assert r3.row_count == 0
    assert store.get("1") == "3"


def test_incremental_without_store_falls_back_to_latest_two():
    m = dict(DEVICES)
    m["devices/1/revisions.json"] = {"revisions": [
        {"id": "1", "date": "2026-01-01", "time": "00:00:00"},
        {"id": "2", "date": "2026-01-02", "time": "00:00:00"},
    ]}
    m["revisions/1/rules.json"] = {"rules": [{"uid": "r", "service": "tcp/1", "action": "accept"}]}
    m["revisions/2/rules.json"] = {"rules": [{"uid": "r", "service": "tcp/2", "action": "accept"}]}
    result = tufin_runner_mod.run_query(FakeClient(m), _q("change_detail"), time_range="incremental")
    assert result.row_count == 1  # no store -> behaves like the latest-two default


def test_change_log_dedupes_across_fetches_and_modes(tmp_path):
    from assetflow import db
    db.init_engine(f"sqlite:///{tmp_path}/c.db")
    cols = [{"name": n} for n in [
        "host.name", "revision.id", "@timestamp", "changed_by", "change_type",
        "rule.uid", "before", "after", "authorized", "requester",
    ]]
    row = ["HQ", "1052", "2026-07-26 19:42:11", "jane", "modified", "r10",
           "a → b : tcp/8443 (accept)", "a → b : tcp/443 (accept)", "unauthorized", "Alice"]
    res = QueryResult(columns=cols, rows=[row])

    # First fetch records the change.
    assert db.record_changes("tufin", res) == 1
    # Re-fetching the same change (any mode) inserts nothing.
    assert db.record_changes("tufin", res) == 0

    # A distinct change (different rule + type) is added once.
    row2 = list(row)
    row2[4], row2[5] = "added", "r30"
    assert db.record_changes("tufin", QueryResult(columns=cols, rows=[row2])) == 1

    # A batch containing an in-batch duplicate only counts it once.
    assert db.record_changes("tufin", QueryResult(columns=cols, rows=[row, row2, list(row)])) == 0

    log = db.change_log("tufin")
    assert len(log["rows"]) == 2
    assert [c["name"] for c in log["columns"]][:2] == ["host.name", "revision.id"]
    # scoped per adapter
    assert db.change_log("elasticsearch")["rows"] == []


def test_db_schedule_crud_and_due(tmp_path):
    from datetime import datetime, timedelta, timezone
    from assetflow import db
    db.init_engine(f"sqlite:///{tmp_path}/s.db")

    rec = db.add_schedule("tufin", "*", interval_seconds=600, time_range="incremental", limit=50)
    sid = rec["id"]
    assert rec["query_id"] == "*" and rec["enabled"] is True
    assert [s["id"] for s in db.list_schedules("tufin")] == [sid]

    # A brand-new schedule (never run) is due immediately.
    assert any(s["id"] == sid for s in db.due_schedules())

    # After running, it is not due until the interval elapses.
    now = datetime.now(timezone.utc)
    db.mark_schedule_ran(sid, now)
    assert not any(s["id"] == sid for s in db.due_schedules(now + timedelta(seconds=60)))
    assert any(s["id"] == sid for s in db.due_schedules(now + timedelta(seconds=601)))

    # Disable removes it from the due set; delete removes it entirely.
    db.set_schedule_enabled(sid, False)
    assert not db.due_schedules(now + timedelta(seconds=601))
    assert db.delete_schedule(sid) is True
    assert db.list_schedules("tufin") == []


def test_scheduler_tick_runs_due_schedule(tmp_path, monkeypatch):
    from assetflow import db, scheduler as scheduler_mod, adapters as adapters_mod
    from assetflow import tufin_client as tufin_client_mod
    db.init_engine(f"sqlite:///{tmp_path}/tick.db")

    manager = adapters_mod.default_manager()
    a = manager.get("tufin")
    # Connect the tufin adapter against a fake client that serves one device.
    fake = FakeClient(DEVICES)
    monkeypatch.setattr(tufin_client_mod, "build_client", lambda **kw: fake)
    monkeypatch.setattr(tufin_client_mod, "ping", lambda cl: {"summary": "ok"})
    a.connect_form({"host": "h", "username": "u", "password": "p"})

    db.add_schedule("tufin", "TUF001", interval_seconds=600)  # device inventory
    outcomes = scheduler_mod.tick_once(manager)
    assert any(o["status"] == "ran" for o in outcomes)
    # The device fetch was saved by the scheduler.
    assert db.latest_fetch("tufin", "TUF001")["row_count"] == 1

    # Disconnected adapter schedules are skipped (and stay due), not run.
    from datetime import datetime, timedelta, timezone
    future = datetime.now(timezone.utc) + timedelta(seconds=3600)
    a._client = None
    outs = scheduler_mod.tick_once(manager, future)
    assert outs and all(o["status"] == "skipped-disconnected" for o in outs)


def test_scheduler_status_reports_heartbeat():
    from assetflow import adapters as adapters_mod, scheduler as scheduler_mod
    manager = adapters_mod.default_manager()
    sched = scheduler_mod.Scheduler(manager, tick=999)
    assert sched.status()["running"] is False
    sched.start()
    try:
        st = sched.status()
        assert st["running"] is True
        assert st["tick_seconds"] == 999
        assert st["started_at"] is not None
    finally:
        sched.stop()


def test_db_change_watermark_roundtrip(tmp_path):
    from assetflow import db
    db.init_engine(f"sqlite:///{tmp_path}/w.db")
    assert db.get_change_watermark("tufin", "d1") is None
    db.set_change_watermark("tufin", "d1", "10")
    assert db.get_change_watermark("tufin", "d1") == "10"
    db.set_change_watermark("tufin", "d1", "11")
    assert db.get_change_watermark("tufin", "d1") == "11"
    assert db.get_change_watermark("tufin", "other") is None


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_tufin_adapter_registered():
    manager = adapters_mod.default_manager()
    a = manager.get("tufin")
    assert a.info.kind == "tufin"
    assert a.info.category == "Network Security Policy"
    assert len(a.registry.queries) == 10


def test_connect_form_and_run(monkeypatch):
    manager = adapters_mod.default_manager()
    a = manager.get("tufin")

    fake = FakeClient(DEVICES)
    monkeypatch.setattr(tufin_client_mod, "build_client", lambda **kw: fake)
    monkeypatch.setattr(tufin_client_mod, "ping", lambda cl: {"summary": "SecureTrack @ tufin.test"})

    assert a.connected is False
    info = a.connect_form({"host": "tufin.test", "username": "u", "password": "p"})
    assert info["summary"].startswith("SecureTrack")
    assert a.connected is True

    q = a.registry.get_query("TUF001")
    out = a.run(q, limit=10)
    assert isinstance(out, QueryResult)
    assert out.rows[0][0] == "HQ-Perimeter-FW"


def test_run_before_connect_raises():
    a = adapters_mod.default_manager().get("tufin")
    q = a.registry.get_query("TUF001")
    with pytest.raises(tufin_client_mod.TufinConfigError):
        a.run(q)


def test_build_client_requires_host_and_creds():
    with pytest.raises(tufin_client_mod.TufinConfigError):
        tufin_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(tufin_client_mod.TufinConfigError):
        tufin_client_mod.build_client(host="h", username="", password="")


# --------------------------------------------------------------------------- #
# Revision rulebase snapshot (TUF009) + saved-data comparison / policy views
# --------------------------------------------------------------------------- #

def _compare_mapping():
    """Device 1 with revisions 100 -> 101: r10 modified (service), r20 removed,
    r30 added, r50 reordered (a clean 'moved' while r10/r40 stay put)."""
    mapping = dict(DEVICES)
    mapping["devices/1/revisions.json"] = {
        "revisions": [
            {"id": "100", "revisionId": "100", "date": "2026-08-01", "time": "09:00:00", "admin": "bob"},
            {"id": "101", "revisionId": "101", "date": "2026-08-05", "time": "17:30:00", "admin": "jane",
             "action": "Install Policy"},
        ]
    }
    mapping["revisions/100/rules.json"] = {"rules": [
        {"uid": "r10", "src_network": "10.0.0.0/24", "dst_network": "db", "dst_service": "tcp/8443",
         "src_zone": "inside", "dst_zone": "dmz", "action": "accept"},
        {"uid": "r20", "src_network": "any", "dst_network": "net", "dst_service": "tcp/22", "action": "drop"},
        {"uid": "r40", "src_network": "1.1.1.1", "dst_network": "web", "dst_service": "tcp/80", "action": "accept"},
        {"uid": "r50", "src_network": "2.2.2.2", "dst_network": "dns", "dst_service": "udp/53", "action": "accept"},
    ]}
    mapping["revisions/101/rules.json"] = {"rules": [
        {"uid": "r50", "src_network": "2.2.2.2", "dst_network": "dns", "dst_service": "udp/53", "action": "accept"},
        {"uid": "r10", "src_network": "10.0.0.0/24", "dst_network": "db", "dst_service": "tcp/443",
         "src_zone": "inside", "dst_zone": "dmz", "action": "accept"},
        {"uid": "r40", "src_network": "1.1.1.1", "dst_network": "web", "dst_service": "tcp/80", "action": "accept"},
        {"uid": "r30", "src_network": "196.10.15.20", "dst_network": "vpn", "dst_service": "tcp/3389",
         "action": "accept"},
    ]}
    # o1 modified (ip .9 -> .10); o2 added; o3 removed.
    mapping["revisions/100/network_objects.json"] = {"network_objects": [
        {"uid": "o1", "display_name": "srv-a", "type": "host", "ip": "10.0.0.9"},
        {"uid": "o3", "display_name": "old-host", "type": "host", "ip": "10.0.0.3"},
    ]}
    mapping["revisions/101/network_objects.json"] = {"network_objects": [
        {"uid": "o1", "display_name": "srv-a", "type": "host", "ip": "10.0.0.10"},
        {"uid": "o2", "display_name": "srv-b", "type": "host", "ip": "10.0.0.20"},
    ]}
    return mapping


def _snapshot():
    """Run the TUF009 collector and return its (columns, rows) — the saved shape
    the compare/policy views read back."""
    result = tufin_runner_mod.run_query(FakeClient(_compare_mapping()), _q("revision_rules"))
    return result.columns, result.rows


def _object_snapshot():
    """Run the TUF010 collector and return its (columns, rows)."""
    result = tufin_runner_mod.run_query(FakeClient(_compare_mapping()), _q("revision_objects"))
    return result.columns, result.rows


def test_revision_rules_collector_snapshots_recent_revisions():
    cols, rows = _snapshot()
    names = [c["name"] for c in cols]
    assert names[:7] == ["host.name", "device.id", "revision.id", "revision.number",
                         "@timestamp", "changed_by", "rule.uid"]
    # 4 rules in rev 100 + 4 rules in rev 101.
    assert len(rows) == 8
    revs = {r[names.index("revision.id")] for r in rows}
    assert revs == {"100", "101"}


def test_compare_from_saved_summary_and_detail():
    cols, rows = _snapshot()
    d = tufin_runner_mod.compare_from_saved(cols, rows, "1")
    # Defaulted to the latest two saved revisions, oldest -> newest.
    assert d["from"]["id"] == "100" and d["to"]["id"] == "101"
    assert d["device"]["name"] == "HQ-Perimeter-FW" and d["to"]["admin"] == "jane"

    rules = {s["category"]: s for s in d["summary"]}["Security Rules"]
    assert rules["added"] == 1 and rules["deleted"] == 1
    assert rules["modified"] == 1 and rules["moved"] == 1

    by = {(r["change_type"], r["rule_uid"]): r for r in d["rules"]}
    assert ("added", "r30") in by and ("removed", "r20") in by and ("moved", "r50") in by
    mod = by[("modified", "r10")]
    assert "service" in mod["changed_fields"]
    assert mod["before"]["service"] == "tcp/8443" and mod["after"]["service"] == "tcp/443"
    assert by[("moved", "r50")]["changed_fields"] == []


def test_compare_from_saved_explicit_ids_ordered_and_missing_errors():
    cols, rows = _snapshot()
    # Reversed ids still read 100 -> 101.
    d = tufin_runner_mod.compare_from_saved(cols, rows, "1", old_rev="101", new_rev="100")
    assert d["from"]["id"] == "100" and d["to"]["id"] == "101"
    # A revision not in the snapshot is reported, not silently compared.
    miss = tufin_runner_mod.compare_from_saved(cols, rows, "1", old_rev="100", new_rev="999")
    assert "error" in miss and "999" in miss["error"]
    # Unknown device -> needs a fetch.
    none = tufin_runner_mod.compare_from_saved(cols, rows, "nope")
    assert "error" in none and none["rules"] == []


def test_revision_objects_collector_snapshots_recent_revisions():
    cols, rows = _object_snapshot()
    names = [c["name"] for c in cols]
    assert names[:7] == ["host.name", "device.id", "revision.id", "revision.number",
                         "@timestamp", "changed_by", "object.uid"]
    # rev 100 has o1+o3, rev 101 has o1+o2.
    assert len(rows) == 4
    val = names.index("object.value")
    by = {(r[names.index("revision.id")], r[names.index("object.uid")]): r for r in rows}
    assert by[("100", "o1")][val] == "10.0.0.9" and by[("101", "o1")][val] == "10.0.0.10"


def test_compare_from_saved_without_objects_flags_has_objects_false():
    cols, rows = _snapshot()
    d = tufin_runner_mod.compare_from_saved(cols, rows, "1")
    assert d["has_objects"] is False
    assert all(s["category"] != "Network Objects" for s in d["summary"])
    assert "objects" not in d


def test_compare_from_saved_includes_object_changes():
    cols, rows = _snapshot()
    ocols, orows = _object_snapshot()
    d = tufin_runner_mod.compare_from_saved(
        cols, rows, "1", object_columns=ocols, object_rows=orows
    )
    assert d["has_objects"] is True
    objsum = {s["category"]: s for s in d["summary"]}["Network Objects"]
    assert objsum["added"] == 1 and objsum["deleted"] == 1 and objsum["modified"] == 1

    by = {(o["change_type"], o["object_uid"]): o for o in d["objects"]}
    assert ("added", "o2") in by and ("removed", "o3") in by
    mod = by[("modified", "o1")]
    assert "value" in mod["changed_fields"]
    assert mod["before"]["value"] == "10.0.0.9" and mod["after"]["value"] == "10.0.0.10"


def test_index_revision_rules_lists_devices_newest_first():
    cols, rows = _snapshot()
    idx = tufin_runner_mod.index_revision_rules(cols, rows)
    assert idx[0]["id"] == "1" and idx[0]["name"] == "HQ-Perimeter-FW"
    assert [r["id"] for r in idx[0]["revisions"]] == ["101", "100"]  # newest first
    assert idx[0]["revisions"][0]["admin"] == "jane"


def test_policy_from_saved_views_specific_and_latest():
    cols, rows = _snapshot()
    d = tufin_runner_mod.policy_from_saved(cols, rows, "1", revision_id="100")
    assert d["revision"]["id"] == "100"
    names = [c["name"] for c in d["columns"]]
    assert names[:3] == ["rule.uid", "name", "src_zone"]
    by_uid = {r[0]: r for r in d["rows"]}
    assert set(by_uid) == {"r10", "r20", "r40", "r50"}
    assert by_uid["r10"][names.index("service")] == "tcp/8443"
    # Default -> latest revision.
    latest = tufin_runner_mod.policy_from_saved(cols, rows, "1")
    assert latest["revision"]["id"] == "101"
    assert "r30" in {r[0] for r in latest["rows"]} and "r20" not in {r[0] for r in latest["rows"]}


# --------------------------------------------------------------------------- #
# Whole-estate coverage: scan, parallelism, device-list caching
# --------------------------------------------------------------------------- #

_LIST_PATHS = {"devices.json?show_os_version=true", "devices.json", "devices"}


class CountingClient(FakeClient):
    """FakeClient that counts how often the device *list* endpoint is hit."""

    def __init__(self, mapping):
        super().__init__(mapping)
        self.device_hits = 0

    def get(self, path):
        if path in _LIST_PATHS:
            self.device_hits += 1
        return super().get(path)


def _estate_mapping(n):
    devs = [{"id": str(i), "name": f"FW-{i:02d}", "model": "asa"} for i in range(n)]
    mapping = {"devices.json?show_os_version=true": {"devices": devs}}
    for i in range(n):
        mapping[f"devices/{i}/rules.json"] = {"rules": [{"uid": f"r{i}", "action": "accept"}]}
    return mapping


def test_scan_covers_whole_estate_by_default():
    # 30 devices > the old cap of 25 — every one must be scanned now.
    result = tufin_runner_mod.run_query(FakeClient(_estate_mapping(30)), _q("rules"))
    names = {r[0] for r in result.rows}
    assert len(names) == 30


def test_explicit_device_scan_still_caps():
    result = tufin_runner_mod.run_query(
        FakeClient(_estate_mapping(30)), _q("rules"), device_scan_limit=5
    )
    assert len({r[0] for r in result.rows}) == 5


def test_device_list_is_cached_across_collectors():
    c = CountingClient(_estate_mapping(6))
    tufin_runner_mod.run_query(c, _q("rules"))
    tufin_runner_mod.run_query(c, _q("services"))  # services.json absent -> skipped, list reused
    assert c.device_hits == 1  # fetched once, then served from cache


def test_resolve_device_scan_env(monkeypatch):
    monkeypatch.delenv("TUFIN_DEVICE_SCAN", raising=False)
    assert tufin_runner_mod.resolve_device_scan() is None  # default = whole estate
    monkeypatch.setenv("TUFIN_DEVICE_SCAN", "50")
    assert tufin_runner_mod.resolve_device_scan() == 50
    monkeypatch.setenv("TUFIN_DEVICE_SCAN", "0")
    assert tufin_runner_mod.resolve_device_scan() is None  # 0 = all
    monkeypatch.setenv("TUFIN_DEVICE_SCAN", "nonsense")
    assert tufin_runner_mod.resolve_device_scan() is None


# --------------------------------------------------------------------------- #
# Pagination: SecureTrack caps list responses (~200) and reports `total`
# --------------------------------------------------------------------------- #

class PagingClient:
    """Serves list endpoints in server-capped pages, advertising the full total
    — mirroring how SecureTrack returns at most ~200 rows per call."""

    def __init__(self, lists, cap=200):
        # lists: {base_path: (envelope_key, [items])}
        self.lists = lists
        self.cap = cap
        self.host = "tufin.test"
        self.calls = 0

    def get(self, path):
        self.calls += 1
        base, _, query = path.partition("?")
        params = {}
        for kv in query.split("&"):
            if kv.startswith(("start=", "count=")):
                k, v = kv.split("=")
                params[k] = int(v)
        for key, (env_key, items) in self.lists.items():
            if key.partition("?")[0] == base:
                start = params.get("start", 0)
                count = min(params.get("count", self.cap), self.cap)
                return {"total": len(items), env_key: items[start:start + count]}
        raise RuntimeError(f"404 {path}")


def test_fetch_list_walks_every_page_for_rules():
    devs = [{"id": "1", "name": "FW-1", "model": "asa"}]
    rules = [{"uid": f"r{i}", "action": "accept"} for i in range(450)]  # > one 200-page
    client = PagingClient(
        {"devices.json": ("devices", devs), "devices/1/rules.json": ("rules", rules)},
        cap=200,
    )
    result = tufin_runner_mod.run_query(client, _q("rules"))
    assert len(result.rows) == 450  # all three pages (200 + 200 + 50), not just 200


def test_fetch_list_paginates_the_device_list():
    devs = [{"id": str(i), "name": f"FW-{i:03d}", "model": "asa"} for i in range(300)]
    client = PagingClient({"devices.json": ("devices", devs)}, cap=200)
    result = tufin_runner_mod.run_query(client, _q("devices"))
    assert len(result.rows) == 300  # 40 > 25 and 300 > 200 — the whole estate


def test_fetch_list_single_page_when_short_page_no_total():
    # A short page (< requested size) with no `total` ends after one call.
    mapping = dict(DEVICES)
    mapping["devices/1/rules.json"] = {"rules": [{"uid": "r1", "action": "accept"}]}
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("rules"))
    assert len(result.rows) == 1


class NoTotalPagingClient:
    """Pages by start/count but never advertises `total` — the runner must keep
    paging while a page comes back full and stop on the first short page."""

    def __init__(self, base_key, env_key, items, page):
        self.base_key, self.env_key, self.items, self.page = base_key, env_key, items, page
        self.host = "tufin.test"

    def get(self, path):
        base, _, query = path.partition("?")
        params = {}
        for kv in query.split("&"):
            if kv.startswith(("start=", "count=")):
                k, v = kv.split("=")
                params[k] = int(v)
        if base == self.base_key:
            start = params.get("start", 0)
            count = min(params.get("count", self.page), self.page)
            return {self.env_key: self.items[start:start + count]}  # no total
        raise RuntimeError(f"404 {path}")


def test_fetch_list_pages_without_total_via_full_page_signal(monkeypatch):
    monkeypatch.setenv("TUFIN_PAGE_SIZE", "3")  # server caps at 3, exposes no total
    items = [{"uid": f"r{i}"} for i in range(7)]
    client = NoTotalPagingClient("x/rules.json", "rules", items, page=3)
    got = tufin_runner_mod._fetch_list(client, ("x/rules.json",), ("rules", "rule"))
    assert len(got) == 7  # 3 + 3 + 1, not just the first full page of 3
