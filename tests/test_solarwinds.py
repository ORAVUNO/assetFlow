"""Tests for the SolarWinds adapter, registry, and SWIS-response normalization.

No live SolarWinds is contacted: a FakeClient answers ``query`` / ``query_rows``
from canned SWQL→results rules, mirroring how the real SWIS client behaves. The
rules match on substrings of the SWQL so the tests do not pin exact query text.
"""

from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import solarwinds_client as sw_client_mod
from assetflow import solarwinds_runner as sw_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry

SW_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "solarwinds_registry.yaml"


class FakeClient:
    """Answer SWQL queries from a list of (substring, rows) rules.

    The first rule whose substring appears in the SWQL wins. A SWQL that matches
    no rule raises (so entity/field fallbacks are exercised). ``WITH ROWS`` paging
    clauses are honored by slicing the matched rows and reporting totalRows.
    """

    def __init__(self, rules, host="sw.test"):
        self.rules = rules
        self.host = host
        self._active_port = 17774
        self.port = 17774

    def _match(self, swql):
        for needle, rows in self.rules:
            if needle in swql:
                return rows
        raise RuntimeError(f"HTTP 400 from SWIS: no rule for {swql[:60]}")

    def query(self, swql):
        rows = self._match(swql)
        # Honor a WITH ROWS a TO b paging clause if present.
        if "WITH ROWS" in swql:
            import re
            m = re.search(r"WITH ROWS (\d+) TO (\d+)", swql)
            if m:
                a, b = int(m.group(1)), int(m.group(2))
                page = rows[a - 1:b]
                return {"results": page, "totalRows": len(rows)}
        return {"results": rows}

    def query_rows(self, swql):
        return list(self._match(swql))


def _q(resource: str, qid: str = "SW999", category: str = "Device Inventory") -> Query:
    return Query(
        id=qid,
        category=category,
        name="test",
        status=Status.partially_validated,
        purpose="test",
        resource=resource,
    )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_solarwinds_registry_loads_and_validates():
    reg = load_registry(str(SW_REGISTRY))
    assert reg.metadata.version == 1
    resources = {q.resource for q in reg.queries}
    assert {
        "nodes", "interfaces", "volumes", "custom_properties",
        "config_inventory", "change_detail", "policy_violations",
    } <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(SW_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


# --------------------------------------------------------------------------- #
# Nodes: classification + custom properties (prefixed) + MAC
# --------------------------------------------------------------------------- #

NODE_ROWS = [
    {"NodeID": 1, "Caption": "core-rtr-1", "IP_Address": "10.0.0.1", "DNS": "",
     "SysName": "core-rtr-1", "Vendor": "Cisco", "MachineType": "Cisco ASR 1001",
     "IOSVersion": "16.9", "NodeDescription": "Cisco IOS-XE router", "Location": "DC1",
     "Contact": "", "StatusDescription": "Up", "ObjectSubType": "SNMP",
     "Department": "Network", "Owner": "alice"},
    {"NodeID": 2, "Caption": "dist-sw-9", "IP_Address": "10.0.0.9", "DNS": "",
     "SysName": "dist-sw-9", "Vendor": "Cisco", "MachineType": "Cisco Catalyst 3850",
     "IOSVersion": "16.12", "NodeDescription": "Catalyst switch", "Location": "DC1",
     "Contact": "", "StatusDescription": "Up", "ObjectSubType": "SNMP",
     "Department": "Network", "Owner": ""},
    {"NodeID": 3, "Caption": "app-srv-3", "IP_Address": "10.0.1.3", "DNS": "",
     "SysName": "app-srv-3", "Vendor": "Windows", "MachineType": "Windows 2019 Server",
     "IOSVersion": "", "NodeDescription": "Windows host", "Location": "DC2",
     "Contact": "", "StatusDescription": "Down", "ObjectSubType": "WMI",
     "Department": "Apps", "Owner": "bob"},
]

# One row with all the custom-property + base columns, for the probe.
CP_PROBE = [{"NodeID": 1, "InstanceType": "Orion.NodesCustomProperties",
             "Uri": "swis://x", "Department": "Network", "Owner": "alice"}]

MAC_ROWS = [{"NodeID": 1, "MAC": "AABBCCDDEEFF"}, {"NodeID": 3, "MAC": "000000000000"}]


def _node_client():
    return FakeClient([
        ("FROM Orion.NodesCustomProperties", CP_PROBE),
        ("FROM Orion.NodeMACAddresses", MAC_ROWS),
        ("FROM Orion.Nodes", NODE_ROWS),
    ])


def test_nodes_classified_and_custom_prefixed():
    result = sw_runner_mod.run_query(_node_client(), _q("nodes"))
    cols = result.column_names
    assert cols[:3] == ["host.name", "node.id", "asset.type"]
    # Custom properties are appended and prefixed so they can't be confused with
    # system fields.
    assert "custom.Department" in cols
    assert "custom.Owner" in cols
    assert not any(c in ("Department", "Owner") for c in cols)

    rows = {r[0]: r for r in result.rows}
    assert rows["core-rtr-1"][cols.index("asset.type")] == "Router"
    assert rows["dist-sw-9"][cols.index("asset.type")] == "Switch"
    assert rows["app-srv-3"][cols.index("asset.type")] == "Server"  # WMI-polled
    # Custom values land on the right rows; missing ones are blank, not misaligned.
    assert rows["core-rtr-1"][cols.index("custom.Owner")] == "alice"
    assert rows["dist-sw-9"][cols.index("custom.Owner")] == ""
    # MAC merged; the all-zero MAC is dropped.
    assert rows["core-rtr-1"][cols.index("host.mac")] == "AABBCCDDEEFF"
    assert rows["app-srv-3"][cols.index("host.mac")] == ""
    # Standard fields fold into the unified view.
    assert rows["core-rtr-1"][cols.index("device.vendor")] == "Cisco"
    assert rows["core-rtr-1"][cols.index("device.model")] == "Cisco ASR 1001"


def test_nodes_without_custom_properties():
    # SELECT * unsupported / no custom props -> no custom.* columns, still lists.
    # The empty custom-properties probe must be matched before the broader
    # "FROM Orion.Nodes" rule (which is a substring of the custom entity name).
    client = FakeClient([
        ("FROM Orion.NodesCustomProperties", []),
        ("FROM Orion.NodeMACAddresses", []),
        ("FROM Orion.Nodes", NODE_ROWS),
    ])
    result = sw_runner_mod.run_query(client, _q("nodes"))
    cols = result.column_names
    assert not any(c.startswith("custom.") for c in cols)
    assert len(result.rows) == 3


def test_classify_firewall_and_load_balancer():
    fn = sw_runner_mod._classify_node
    assert fn("Palo Alto", "PA-3220", "pan-os", "SNMP") == "Firewall"
    assert fn("F5", "BIG-IP", "load balancer", "SNMP") == "Load Balancer"
    assert fn("Unknown", "Mystery Box", "", "ICMP") == "Network Device"


# --------------------------------------------------------------------------- #
# Config posture (NCM.ConfigArchive)
# --------------------------------------------------------------------------- #

def test_config_inventory_latest_per_type():
    archive = [
        {"NodeCaption": "core-rtr-1", "ConfigID": "c3", "ConfigType": "Running",
         "ConfigTitle": "running-3", "DownloadTime": "2026-08-19T02:00:00", "Baseline": False},
        {"NodeCaption": "core-rtr-1", "ConfigID": "c2", "ConfigType": "Running",
         "ConfigTitle": "running-2", "DownloadTime": "2026-08-18T02:00:00", "Baseline": True},
        {"NodeCaption": "core-rtr-1", "ConfigID": "c1", "ConfigType": "Startup",
         "ConfigTitle": "startup-1", "DownloadTime": "2026-08-17T02:00:00", "Baseline": False},
    ]
    client = FakeClient([("FROM NCM.ConfigArchive", archive)])
    result = sw_runner_mod.run_query(client, _q("config_inventory", "SW005", "Config Posture"))
    cols = result.column_names
    # Newest per (device, config type): the Running config keeps c3, not c2.
    running = [r for r in result.rows if r[cols.index("config.type")] == "Running"]
    assert len(running) == 1
    assert running[0][cols.index("config.id")] == "c3"
    startup = [r for r in result.rows if r[cols.index("config.type")] == "Startup"]
    assert len(startup) == 1


def test_config_inventory_falls_back_to_cirrus():
    archive = [{"NodeCaption": "sw1", "ConfigID": "x1", "ConfigType": "Running",
                "ConfigTitle": "t", "DownloadTime": "2026-08-19T00:00:00", "Baseline": False}]
    # Only the legacy Cirrus.* entity answers.
    client = FakeClient([("FROM Cirrus.ConfigArchive", archive)])
    result = sw_runner_mod.run_query(client, _q("config_inventory", "SW005", "Config Posture"))
    assert result.rows[0][result.column_names.index("host.name")] == "sw1"


# --------------------------------------------------------------------------- #
# Config change detail (diffing archived configs)
# --------------------------------------------------------------------------- #

CFG_OLD = "hostname rtr1\ninterface Gig0/0\n ip address 10.0.0.1 255.255.255.0\nno ip http server\n"
CFG_NEW = "hostname rtr1\ninterface Gig0/0\n ip address 10.0.0.2 255.255.255.0\nip http server\n"


def _change_client():
    return FakeClient([
        ("FROM NCM.Nodes", [{"NodeID": "guid-1", "NodeCaption": "rtr1"}]),
        # newest first
        ("FROM NCM.ConfigArchive", [
            {"ConfigID": "cfg-new", "ConfigType": "Running",
             "DownloadTime": "2026-08-19T02:00:00", "Config": CFG_NEW},
            {"ConfigID": "cfg-old", "ConfigType": "Running",
             "DownloadTime": "2026-08-18T02:00:00", "Config": CFG_OLD},
        ]),
    ])


def test_change_detail_diffs_config_lines():
    result = sw_runner_mod.run_query(_change_client(), _q("change_detail", "SW006", "Config Changes"))
    cols = result.column_names
    assert cols[:6] == ["host.name", "revision.id", "@timestamp", "changed_by", "change_type", "rule.uid"]
    types = [r[cols.index("change_type")] for r in result.rows]
    assert "added" in types and "removed" in types
    # revision.id is the newer ConfigID (globally unique -> dedup key).
    assert all(r[cols.index("revision.id")] == "cfg-new" for r in result.rows)
    added = [r[cols.index("after")] for r in result.rows if r[cols.index("change_type")] == "added"]
    removed = [r[cols.index("before")] for r in result.rows if r[cols.index("change_type")] == "removed"]
    assert any("ip http server" == a for a in added)
    assert any("no ip http server" == r for r in removed)


class MemWatermark:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v


def test_change_detail_incremental_baseline_then_quiet():
    wm = MemWatermark()
    # First incremental run establishes a baseline silently (no rows).
    r1 = sw_runner_mod.run_query(
        _change_client(), _q("change_detail", "SW006", "Config Changes"),
        time_range="since", watermark_store=wm,
    )
    assert r1.rows == []
    assert wm.get("guid-1") == "cfg-new"
    # Second run with no new config -> still no rows (watermark matches newest).
    r2 = sw_runner_mod.run_query(
        _change_client(), _q("change_detail", "SW006", "Config Changes"),
        time_range="since", watermark_store=wm,
    )
    assert r2.rows == []


def test_change_detail_skips_volatile_lines():
    old = "hostname rtr1\n! Last configuration change at 10:00\nip domain-name a\n"
    new = "hostname rtr1\n! Last configuration change at 12:00\nip domain-name b\n"
    client = FakeClient([
        ("FROM NCM.Nodes", [{"NodeID": "g", "NodeCaption": "rtr1"}]),
        ("FROM NCM.ConfigArchive", [
            {"ConfigID": "n", "DownloadTime": "t2", "Config": new},
            {"ConfigID": "o", "DownloadTime": "t1", "Config": old},
        ]),
    ])
    result = sw_runner_mod.run_query(client, _q("change_detail", "SW006", "Config Changes"))
    # Only the domain-name line changed; the volatile "Last configuration change"
    # line is ignored.
    joined = " ".join(str(v) for r in result.rows for v in r)
    assert "domain-name" in joined
    assert "Last configuration change" not in joined


# --------------------------------------------------------------------------- #
# Compliance
# --------------------------------------------------------------------------- #

def test_policy_violations_tolerant_columns():
    rows = [{"NodeCaption": "core-rtr-1", "PolicyReportName": "Hardening",
             "PolicyName": "No Telnet", "RuleName": "telnet-disabled",
             "Severity": "High", "ViolationString": "line vty 0 4 / transport input telnet"}]
    client = FakeClient([("FROM NCM.PolicyReportResults", rows)])
    result = sw_runner_mod.run_query(client, _q("policy_violations", "SW007", "Compliance"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("host.name")] == "core-rtr-1"
    assert row[cols.index("policy.rule")] == "telnet-disabled"
    assert row[cols.index("severity")] == "High"


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        sw_runner_mod.run_query(FakeClient([]), _q("nope"))


# --------------------------------------------------------------------------- #
# Client construction / env
# --------------------------------------------------------------------------- #

def test_build_client_requires_host_and_creds():
    with pytest.raises(sw_client_mod.SolarWindsConfigError):
        sw_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(sw_client_mod.SolarWindsConfigError):
        sw_client_mod.build_client(host="sw", username="", password="")


def test_clean_host_strips_scheme_port_path():
    assert sw_client_mod.clean_host("https://sw.example.com:17774/x") == "sw.example.com"
    assert sw_client_mod.clean_host("  sw.example.com  ") == "sw.example.com"


def test_build_client_from_env(monkeypatch):
    monkeypatch.setenv("SWIS_HOSTNAME", "sw.example.com")
    monkeypatch.setenv("SWIS_USERNAME", "svc")
    monkeypatch.setenv("SWIS_PASSWORD", "secret")
    monkeypatch.setenv("SWIS_PORT", "17778")
    client = sw_client_mod.build_client_from_env()
    assert client.host == "sw.example.com"
    assert client.port == 17778


def test_build_client_from_env_missing(monkeypatch):
    for var in ("SWIS_HOSTNAME", "SOLARWINDS_HOST", "ORION_HOST",
                "SWIS_USERNAME", "SWIS_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(sw_client_mod.SolarWindsConfigError):
        sw_client_mod.build_client_from_env()


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_default_manager_has_solarwinds():
    manager = adapters_mod.default_manager()
    a = manager.get("solarwinds")
    assert a.info.kind == "solarwinds"
    assert a.info.category == "Network Monitoring / NCM"


def test_solarwinds_adapter_env_for_form():
    manager = adapters_mod.default_manager()
    adapter = manager.get("solarwinds")
    env = adapter.env_for_form(
        {"host": "https://sw.example.com/", "username": "svc",
         "password": "secret", "port": 17774}
    )
    assert env["SWIS_HOSTNAME"] == "sw.example.com"
    assert env["SWIS_USERNAME"] == "svc"
    assert env["SWIS_VERIFY_CERTS"] == "true"


def test_solarwinds_adapter_run_before_connect_raises():
    manager = adapters_mod.default_manager()
    adapter = manager.get("solarwinds")
    q = adapter.registry.get_query("SW001")
    with pytest.raises(sw_client_mod.SolarWindsConfigError):
        adapter.run(q)


def test_solarwinds_adapter_connect_form(monkeypatch):
    manager = adapters_mod.default_manager()
    adapter = manager.get("solarwinds")
    monkeypatch.setattr(sw_client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(
        sw_client_mod, "ping",
        lambda cl: {"product": "SolarWinds Orion (SWIS)", "summary": "SWIS @ sw"},
    )
    info = adapter.connect_form(
        {"host": "sw.example.com", "username": "svc", "password": "secret",
         "port": 17774, "verify_certs": True, "request_timeout": 120}
    )
    assert info["product"] == "SolarWinds Orion (SWIS)"
    assert adapter.connected is True
