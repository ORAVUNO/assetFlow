"""Tests for the unified Tufin device-profile builder (Discover view)."""

from assetflow import tufin_profile


def _rec(columns, rows):
    return {"columns": [{"name": c} for c in columns], "rows": rows}


DEVICES = _rec(
    ["host.name", "device.id", "asset.type", "device.vendor", "device.model",
     "host.ip", "os.version"],
    [
        ["FW-A", "1", "Firewall", "Cisco", "FMC", "10.0.0.1", "7.2"],
        ["MGMT", "9", "Firewall Management", "Cisco", "FMC-mgr", "10.0.0.9", "7.2"],
    ],
)
RULES = _rec(
    ["host.name", "rule.uid", "source", "destination", "service", "action"],
    [
        ["FW-A", "r1", "any", "web", "tcp/443", "accept"],
        ["FW-A", "r2", "net", "db", "tcp/1521", "accept"],
    ],
)
OBJECTS = _rec(
    ["host.name", "object.id", "object.name", "object.type", "object.ip"],
    [["FW-A", "o1", "srv-a", "host", "10.0.0.50"]],
)
CHANGES = _rec(
    ["host.name", "revision.id", "@timestamp", "changed_by", "change_type",
     "rule.uid", "before", "after", "authorized", "requester"],
    [
        ["FW-A", "101", "t", "jane", "modified", "r1", "a", "b", "unauthorized", "Alice"],
        ["FW-A", "101", "t", "jane", "added", "r2", "", "c", "authorized", "Bob"],
        ["MGMT", "55", "t", "bob", "removed", "r9", "d", "", "", ""],
    ],
)


def test_profile_folds_sections_by_device():
    p = tufin_profile.build_profile(
        {"devices": DEVICES, "rules": RULES, "network_objects": OBJECTS},
        CHANGES, generated_at="2026-08-20T00:00:00+00:00",
    )
    by_name = {d["name"]: d for d in p["devices"]}
    assert set(by_name) == {"FW-A", "MGMT"}

    fw = by_name["FW-A"]
    assert fw["asset_type"] == "Firewall" and fw["vendor"] == "Cisco"
    assert fw["ip"] == "10.0.0.1"
    assert fw["counts"]["rules"] == 2 and fw["counts"]["objects"] == 1
    # host.name is stripped from the nested rows (device already carries it).
    assert "host.name" not in fw["rules"][0]
    assert fw["rules"][0]["rule.uid"] == "r1"


def test_profile_change_rollup_per_device_and_estate():
    p = tufin_profile.build_profile({"devices": DEVICES, "rules": RULES}, CHANGES)
    by_name = {d["name"]: d for d in p["devices"]}
    fw = by_name["FW-A"]["changes"]
    assert fw["total"] == 2 and fw["modified"] == 1 and fw["added"] == 1
    assert fw["unauthorized"] == 1
    assert len(fw["recent"]) == 2

    est = p["totals"]["changes"]
    assert est["total"] == 3 and est["removed"] == 1 and est["unauthorized"] == 1


def test_profile_totals_and_asset_type_breakdown():
    p = tufin_profile.build_profile({"devices": DEVICES, "rules": RULES}, CHANGES)
    t = p["totals"]
    assert t["devices"] == 2 and t["rules"] == 2
    assert t["by_asset_type"] == {"Firewall": 1, "Firewall Management": 1}


def test_profile_orders_most_changed_first():
    p = tufin_profile.build_profile({"devices": DEVICES}, CHANGES)
    # FW-A has 2 changes, MGMT has 1 -> FW-A first.
    assert [d["name"] for d in p["devices"]] == ["FW-A", "MGMT"]


def test_profile_device_only_in_subsection_is_kept():
    # A device that appears in rules but not in the device inventory still shows.
    rules = _rec(["host.name", "rule.uid", "action"], [["GHOST", "r1", "accept"]])
    p = tufin_profile.build_profile({"rules": rules}, None)
    by_name = {d["name"]: d for d in p["devices"]}
    assert "GHOST" in by_name and by_name["GHOST"]["counts"]["rules"] == 1
    assert by_name["GHOST"]["asset_type"] == ""  # unknown inventory


def test_profile_empty_when_nothing_saved():
    p = tufin_profile.build_profile({}, None, generated_at="x")
    assert p["devices"] == []
    assert p["totals"]["devices"] == 0 and p["totals"]["changes"]["total"] == 0
