"""Tests for host-keyed correlation (merge.build_host_view)."""

from assetflow import merge


def rec(qid, name, columns, rows):
    return {"query_id": qid, "name": name,
            "columns": [{"name": c} for c in columns], "rows": rows}


def test_excludes_non_host_keyed():
    records = [
        rec("AI001", "User Device Mapping",
            ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "administrator"], ["WIN-DC01", "10.0.0.5", "svc_backup"]]),
        rec("AI010", "App by Service", ["service.name", "Hosts"], [["Elastic Agent", 12]]),
    ]
    view = merge.build_host_view(records)
    assert view["contributing"] == ["AI001"]
    assert view["excluded"] == ["AI010"]
    assert view["host_count"] == 1


def test_golden_record_merges_hosts_and_ips():
    records = [
        rec("AI001", "User Device Mapping",
            ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "administrator"],
             ["WIN-DC01", "10.0.0.5", "svc_backup"],
             ["WIN-APP07", "10.0.2.31", "jsmith"]]),
        rec("AI011", "Host Application Mapping",
            ["host.name", "Applications"],
            [["WIN-DC01", ["Elastic Agent", "Zabbix Agent 2"]]]),
    ]
    view = merge.build_host_view(records)
    names = [c["name"] for c in view["columns"]]
    assert names[0] == "host.name" and names[1] == "host.ip"
    by_host = {r[0]: r for r in view["rows"]}
    assert set(by_host) == {"WIN-DC01", "WIN-APP07"}
    dc = by_host["WIN-DC01"]
    assert dc[1] == "10.0.0.5"
    # AI001 column summarizes the two users
    ai001_col = names.index("AI001 User Device Mapping")
    assert "administrator" in dc[ai001_col] and "svc_backup" in dc[ai001_col]
    # AI011 column flattens the Applications list
    ai011_col = names.index("AI011 Host Application Mapping")
    assert "Elastic Agent" in dc[ai011_col] and "Zabbix Agent 2" in dc[ai011_col]
    # WIN-APP07 has no AI011 data -> empty cell
    assert by_host["WIN-APP07"][ai011_col] == ""


def test_empty_records():
    view = merge.build_host_view([])
    assert view["host_count"] == 0
    assert view["columns"] == [{"name": "host.name"}, {"name": "host.ip"}]


# -- cross-adapter unified inventory (layer 3) ------------------------------


def _block(aid, name, records):
    return ({"id": aid, "name": name, "category": "c"}, records)


def test_unified_inventory_flags_multi_adapter_assets():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping",
            ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "administrator"],
             ["WIN-APP07", "10.0.2.31", "jsmith"]]),
    ])
    tufin = _block("tufin", "Tufin SecureTrack", [
        rec("TUF001", "Device Inventory",
            ["host.name", "host.ip", "vendor"],
            [["WIN-DC01", "10.0.0.5", "Check Point"]]),
    ])
    inv = merge.build_unified_inventory([es, tufin])

    names = [c["name"] for c in inv["columns"]]
    assert names[:6] == [
        "host.name", "aliases", "identifiers", "seen_by", "adapter_count", "correlated_by",
    ]
    # one column per contributing adapter, in input order
    assert names[6:] == ["Elasticsearch", "Tufin SecureTrack"]

    assert inv["asset_count"] == 2
    assert inv["multi_adapter_count"] == 1

    by_host = {r[0]: r for r in inv["rows"]}
    # WIN-DC01 seen by both adapters -> surfaces first, adapter_count == 2
    assert inv["rows"][0][0] == "WIN-DC01"
    dc = by_host["WIN-DC01"]
    ci = names.index("adapter_count")
    assert dc[ci] == 2
    assert "Elasticsearch" in dc[names.index("seen_by")]
    assert "Tufin SecureTrack" in dc[names.index("seen_by")]
    # single-adapter asset
    app = by_host["WIN-APP07"]
    assert app[ci] == 1
    assert app[names.index("Tufin SecureTrack")] == ""


def test_unified_inventory_merges_different_names_by_shared_ip():
    # Same machine, two different hostnames, correlated by a shared IP.
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping",
            ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "administrator"]]),
    ])
    tufin = _block("tufin", "Tufin SecureTrack", [
        rec("TUF001", "Device Inventory",
            ["host.name", "host.ip", "vendor"],
            [["dc01.corp.local", "10.0.0.5", "Check Point"]]),
    ])
    inv = merge.build_unified_inventory([es, tufin])
    # one asset, not two — merged on the shared IP
    assert inv["asset_count"] == 1
    assert inv["multi_adapter_count"] == 1
    assert inv["correlated_count"] == 1
    names = [c["name"] for c in inv["columns"]]
    row = inv["rows"][0]
    # aliases column carries the other name; correlated_by names the shared IP
    aliases = row[names.index("aliases")]
    assert "dc01.corp.local" in aliases or "WIN-DC01" in aliases
    assert "10.0.0.5" in row[names.index("correlated_by")]


def test_correlate_matches_mac_across_separators():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI020", "Host Inventory", ["host.name", "host.mac"],
            [["A", "AA:BB:CC:DD:EE:FF"]]),
    ])
    tufin = _block("tufin", "Tufin", [
        rec("TUF020", "Devices", ["host.name", "host.mac"],
            [["B", "aa-bb-cc-dd-ee-ff"]]),
    ])
    res = merge.correlate([es, tufin])
    assert len(res["assets"]) == 1  # different names + separators, same MAC
    assert res["assets"][0]["match_by"].get("mac")


def test_correlate_ignores_junk_identifiers():
    # A shared junk IP (0.0.0.0) must NOT merge two distinct hosts.
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "x", ["host.name", "host.ip"], [["HOST-A", "0.0.0.0"]]),
    ])
    tufin = _block("tufin", "Tufin", [
        rec("TUF001", "y", ["host.name", "host.ip"], [["HOST-B", "0.0.0.0"]]),
    ])
    res = merge.correlate([es, tufin])
    assert len(res["assets"]) == 2


def test_unified_inventory_skips_non_host_keyed():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI010", "App by Service", ["service.name", "Hosts"], [["Elastic Agent", 12]]),
    ])
    inv = merge.build_unified_inventory([es])
    assert inv["asset_count"] == 0
    # no adapter contributed a host, so no per-adapter columns
    assert [c["name"] for c in inv["columns"]] == [
        "host.name", "aliases", "identifiers", "seen_by", "adapter_count", "correlated_by",
    ]
    assert inv["adapters"] == []


def test_unified_inventory_empty():
    inv = merge.build_unified_inventory([])
    assert inv["asset_count"] == 0
    assert inv["multi_adapter_count"] == 0


# -- single-asset drill-down ------------------------------------------------


def test_asset_detail_fields_common_specific_and_preferred():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping",
            ["host.name", "host.ip", "os.name", "user.name"],
            [["WIN-DC01", "10.0.0.5", "Windows Server 2019", "administrator"],
             ["WIN-DC01", "10.0.0.5", "Windows Server 2019", "svc_backup"]]),
    ])
    tufin = _block("tufin", "Tufin SecureTrack", [
        rec("TUF001", "Device Inventory",
            ["host.name", "host.ip", "vendor"],
            [["WIN-DC01", "10.0.0.5", "Check Point"]]),
    ])
    d = merge.build_asset_detail([es, tufin], "WIN-DC01")
    assert d["found"] is True
    assert [a["id"] for a in d["adapters"]] == ["elasticsearch", "tufin"]

    by_name = {f["name"]: f for f in d["fields"]}
    # host.ip reported by both, same value -> common + agree
    ip = by_name["host.ip"]
    assert ip["scope"] == "common" and ip["agree"] is True
    assert ip["preferred"] == "10.0.0.5"
    # os.name only from Elasticsearch -> specific
    assert by_name["os.name"]["scope"] == "specific"
    assert by_name["os.name"]["adapters"] == ["Elasticsearch"]
    # vendor only from Tufin -> specific
    assert by_name["vendor"]["scope"] == "specific"
    assert by_name["vendor"]["adapters"] == ["Tufin SecureTrack"]


def test_asset_detail_mini_tables_scoped_to_host():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping",
            ["host.name", "user.name"],
            [["WIN-DC01", "administrator"], ["WIN-DC01", "svc_backup"],
             ["OTHER", "eve"]]),
    ])
    d = merge.build_asset_detail([es], "WIN-DC01")
    tbls = d["tables"]
    assert len(tbls) == 1
    t = tbls[0]
    assert t["adapter_id"] == "elasticsearch" and t["query_id"] == "AI001"
    # host column dropped; only this host's rows kept
    assert t["columns"] == ["user.name"]
    assert t["row_count"] == 2
    assert sorted(r[0] for r in t["rows"]) == ["administrator", "svc_backup"]


def test_asset_detail_lookup_by_alias():
    # Asset merged by IP under two names; detail is reachable by either name.
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping", ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "administrator"]]),
    ])
    tufin = _block("tufin", "Tufin SecureTrack", [
        rec("TUF001", "Device Inventory", ["host.name", "host.ip", "vendor"],
            [["dc01.corp.local", "10.0.0.5", "Check Point"]]),
    ])
    blocks = [es, tufin]
    for lookup in ("WIN-DC01", "dc01.corp.local"):
        d = merge.build_asset_detail(blocks, lookup)
        assert d["found"] is True
        assert len(d["adapters"]) == 2
        assert set(d["names"]) == {"WIN-DC01", "dc01.corp.local"}
        assert "10.0.0.5" in d["correlated_by"].get("ip", [])
        # both adapters' fields present
        assert {"vendor", "user.name"} <= {f["name"] for f in d["fields"]}


def test_asset_types_are_correlated_separately():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping", ["host.name", "host.ip", "user.name"],
            [["WIN-DC01", "10.0.0.5", "admin"], ["WIN-APP07", "10.0.2.9", "admin"]]),
    ])
    # devices: two hosts
    dev = merge.build_unified_inventory([es], "device")
    assert dev["type"] == "device"
    assert {r[0] for r in dev["rows"]} == {"WIN-DC01", "WIN-APP07"}
    # users: one user (admin), seen on both hosts — NOT merged into a device
    usr = merge.build_unified_inventory([es], "user")
    assert usr["type"] == "user"
    assert [c["name"] for c in usr["columns"]][0] == "user.name"
    assert {r[0] for r in usr["rows"]} == {"admin"}
    # inventory_types reports counts per type
    counts = {t["type"]: t["count"] for t in merge.inventory_types([es])}
    assert counts["device"] == 2 and counts["user"] == 1


def test_user_asset_detail_shows_hosts_as_fields():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping", ["host.name", "user.name"],
            [["WIN-DC01", "admin"], ["WIN-APP07", "admin"]]),
    ])
    d = merge.build_asset_detail([es], "admin", "user")
    assert d["found"] is True and d["type"] == "user" and d["host"] == "admin"
    # user.name is the asset identity (dropped); host.name becomes a field
    fnames = {f["name"] for f in d["fields"]}
    assert "host.name" in fnames and "user.name" not in fnames
    host_field = next(f for f in d["fields"] if f["name"] == "host.name")
    assert set(host_field["values_by_adapter"]["Elasticsearch"]) == {"WIN-DC01", "WIN-APP07"}


def test_application_assets_from_service_name():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI010", "App by Service", ["service.name", "Hosts"],
            [["Elastic Agent", 12], ["nginx", 3]]),
    ])
    inv = merge.build_unified_inventory([es], "application")
    assert inv["type"] == "application"
    assert [c["name"] for c in inv["columns"]][0] == "application.name"
    assert {r[0] for r in inv["rows"]} == {"Elastic Agent", "nginx"}


def test_unknown_asset_type_raises():
    import pytest
    with pytest.raises(KeyError):
        merge.correlate([], "vmware")


def test_asset_detail_missing_host():
    es = _block("elasticsearch", "Elasticsearch", [
        rec("AI001", "User Device Mapping", ["host.name", "user.name"],
            [["WIN-DC01", "administrator"]]),
    ])
    d = merge.build_asset_detail([es], "NOPE")
    assert d["found"] is False
    assert d["fields"] == [] and d["tables"] == []
