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
