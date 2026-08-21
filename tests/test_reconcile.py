"""Tests for ticket import + authorization reconciliation."""

from assetflow import db, reconcile


def _change(**kw):
    row = {"host.name": "FW-A", "entity": "rule", "change_type": "added",
           "rule.uid": "r1", "source": "10.1.1.5", "destination": "10.2.0.10",
           "service": "tcp/443", "rule.action": "accept", "@timestamp": "2026-08-10 10:00:00"}
    row.update(kw)
    return row


def _ticket(**kw):
    t = {"ticket_id": "CR-1", "status": "approved", "change_type": "add",
         "device": "FW-A", "source": "10.1.0.0/16", "destination": "10.2.0.0/16",
         "service": "tcp/443", "action": "allow", "window_start": "", "window_end": ""}
    t.update(kw)
    return t


def test_authorized_when_ticket_covers_the_5_tuple():
    v = reconcile.match_change(_change(), [_ticket()])
    assert v["authorization"] == "authorized"
    assert v["matched_ticket"] == "CR-1"


def test_unauthorized_when_no_ticket_covers():
    # ticket allows a different destination network
    v = reconcile.match_change(_change(), [_ticket(destination="10.9.0.0/16")])
    assert v["authorization"] == "unauthorized"


def test_over_provisioned_when_broader_than_requested():
    # implemented source is a /8 while the ticket only requested a single host
    v = reconcile.match_change(
        _change(source="10.0.0.0/8"),
        [_ticket(source="10.1.1.5/32")],
    )
    assert v["authorization"] == "over_provisioned" and v["matched_ticket"] == "CR-1"


def test_only_approved_tickets_authorize():
    v = reconcile.match_change(_change(), [_ticket(status="rejected")])
    assert v["authorization"] == "unauthorized"


def test_action_must_match():
    # ticket authorizes an allow; the change is a deny -> not covered
    v = reconcile.match_change(_change(**{"rule.action": "drop"}), [_ticket(action="allow")])
    assert v["authorization"] == "unauthorized"


def test_change_window_is_enforced():
    inside = _ticket(window_start="2026-08-01", window_end="2026-08-31")
    outside = _ticket(window_start="2026-01-01", window_end="2026-01-31")
    assert reconcile.match_change(_change(), [inside])["authorization"] == "authorized"
    assert reconcile.match_change(_change(), [outside])["authorization"] == "unauthorized"


def test_object_names_resolve_to_addresses():
    # the change references object names; the index maps them to CIDRs the ticket uses
    ch = _change(source="Web-Servers", destination="DB-Servers")
    objects = {"Web-Servers": "10.1.1.0/24", "DB-Servers": "10.2.0.5"}
    v = reconcile.match_change(ch, [_ticket()], objects)
    assert v["authorization"] == "authorized"


def test_object_and_moved_changes_are_not_applicable():
    assert reconcile.match_change(_change(entity="object"), [_ticket()])["authorization"] == "not_applicable"
    assert reconcile.match_change(_change(change_type="moved"), [_ticket()])["authorization"] == "not_applicable"


def test_reconcile_changes_summary_and_columns():
    cols = [{"name": n} for n in ["host.name", "entity", "change_type", "rule.uid",
                                  "source", "destination", "service", "rule.action", "@timestamp"]]
    rows = [
        ["FW-A", "rule", "added", "r1", "10.1.1.5", "10.2.0.10", "tcp/443", "accept", "2026-08-10 10:00:00"],
        ["FW-A", "rule", "added", "r2", "0.0.0.0/0", "10.2.0.10", "tcp/443", "accept", "2026-08-10 10:00:00"],
    ]
    out = reconcile.reconcile_changes({"columns": cols, "rows": rows}, [_ticket()])
    assert [c["name"] for c in out["columns"]][-4:] == reconcile.VERDICT_COLUMNS
    assert out["summary"]["authorized"] == 1          # r1 covered
    assert out["summary"]["over_provisioned"] == 1    # r2 opens 'any' source -> broader than requested


def test_ticket_csv_import_honors_header_aliases(tmp_path):
    db.init_engine(f"sqlite:///{tmp_path}/t.db")
    csv = (
        "Change,Approval,Type,Firewall,Src,Dest,Port,Permit,Start,End\n"
        "CR-42,Approved,add,FW-A,10.1.0.0/16,10.2.0.0/16,tcp/443,allow,2026-08-01,2026-08-31\n"
    )
    tickets = db.parse_tickets_csv(csv)
    assert tickets[0]["ticket_id"] == "CR-42" and tickets[0]["device"] == "FW-A"
    assert tickets[0]["source"] == "10.1.0.0/16" and tickets[0]["action"] == "allow"

    assert db.replace_tickets("tufin", tickets) == 1
    assert len(db.list_tickets("tufin")) == 1
    # re-import replaces rather than appends
    assert db.replace_tickets("tufin", tickets) == 1
    assert len(db.list_tickets("tufin")) == 1
    assert db.clear_tickets("tufin") == 1
    assert db.list_tickets("tufin") == []
