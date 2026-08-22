"""Tests for the Tenable.sc (SecurityCenter) adapter, registry, and normalization.

No live Tenable.sc is contacted: a FakeClient answers ``analysis`` and ``get``
from canned rules, mirroring how the real REST client behaves (the ``sumip``
analysis rule is filter-aware so device tag enrichment can be exercised).
"""

from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import tenable_sc_client as tsc_client_mod
from assetflow import tenable_sc_runner as tsc_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry

TSC_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "tenable_sc_registry.yaml"


class FakeClient:
    """Answer ``analysis(tool, ...)`` and ``get(path)`` from canned rules.

    ``analysis_rules[tool]`` is either a list of records or a callable(filters)
    returning records (so a filtered ``sumip`` can return per-asset IPs).
    ``get_rules`` maps a path substring to its unwrapped ``response`` body.
    """

    def __init__(self, analysis_rules=None, get_rules=None, host="sc.test"):
        self.analysis_rules = analysis_rules or {}
        self.get_rules = get_rules or {}
        self.host = host

    def login(self):
        pass

    def logout(self):
        pass

    def analysis(self, tool, *, analysis_type="vuln", source_type="cumulative",
                 filters=None, **kw):
        rule = self.analysis_rules.get(tool)
        if callable(rule):
            return list(rule(filters or []))
        return list(rule or [])

    def get(self, path):
        for needle, resp in self.get_rules.items():
            if needle in path:
                return resp
        raise RuntimeError(f"no get rule for {path}")


def _q(resource: str, qid: str = "TSC999", category: str = "Device Inventory") -> Query:
    return Query(
        id=qid, category=category, name="test",
        status=Status.partially_validated, purpose="test", resource=resource,
    )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_registry_loads_and_validates():
    reg = load_registry(str(TSC_REGISTRY))
    assert reg.metadata.version == 1
    resources = {q.resource for q in reg.queries}
    assert {
        "devices", "hosts", "findings", "software", "users", "asset_lists",
        "alerts", "incidents", "saas_applications",
    } <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(TSC_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


# --------------------------------------------------------------------------- #
# Devices (sumip) — flattening, custom.*, asset.type, tag enrichment
# --------------------------------------------------------------------------- #

SUMIP_ALL = [
    {"ip": "10.0.0.1", "dnsName": "web01.corp", "netbiosName": "WEB01",
     "macAddress": "aa:bb:cc:00:00:01", "osCPE": "cpe:/o:linux:linux_kernel",
     "repository": {"id": 1, "name": "Main"}, "score": "420", "total": "12",
     "acrScore": "7", "assetExposureScore": "812",
     "severityCritical": "1", "severityHigh": "3", "severityMedium": "5",
     "severityLow": "2", "severityInfo": "1", "lastAuthRun": "1600000000",
     "lastUnauthRun": "0", "uuid": "u-1", "hasPassive": "Yes"},
    {"ip": "10.0.0.2", "dnsName": "db01.corp", "netbiosName": "DB01",
     "macAddress": "aa:bb:cc:00:00:02", "osCPE": "cpe:/o:microsoft:windows",
     "repository": {"id": 1, "name": "Main"}, "score": "10", "total": "2",
     "severityCritical": "0", "severityHigh": "0", "severityMedium": "1",
     "severityLow": "1", "severityInfo": "0", "lastAuthRun": "1600000500",
     "lastUnauthRun": "0", "uuid": "u-2", "hasPassive": "No"},
]


def _sumip_rule(filters):
    """Full list with no filter; per-asset IPs when an asset filter is present."""
    for f in filters:
        if f.get("filterName") == "asset":
            asset_id = str(f.get("value", {}).get("id"))
            if asset_id == "100":  # "Web Servers" contains 10.0.0.1
                return [{"ip": "10.0.0.1"}]
            return []
    return SUMIP_ALL


ASSET_LISTS = [
    {"id": 100, "name": "Web Servers", "type": "static", "tags": "prod,web",
     "description": "front-end", "ipCount": 1, "owner": {"username": "admin"},
     "ownerGroup": {"name": "Full Access"}, "status": "0",
     "createdTime": "1600000000", "modifiedTime": "1600000000"},
]


def _device_client():
    return FakeClient(
        analysis_rules={"sumip": _sumip_rule},
        get_rules={"asset": ASSET_LISTS},
    )


def test_devices_flatten_custom_and_type():
    result = tsc_runner_mod.run_query(_device_client(), _q("devices"))
    cols = result.column_names
    assert cols[0] == "host.name"
    assert cols[1] == "asset.type"
    rows = {r[0]: r for r in result.rows}
    web = rows["web01.corp"]
    assert web[cols.index("asset.type")] == "Host"
    assert web[cols.index("host.ip")] == "10.0.0.1"
    assert web[cols.index("repository")] == "Main"          # nested object -> name
    # ACR / AES (Tenable Security Center 6.x sumip fields) get named columns.
    assert web[cols.index("acr")] == "7"
    assert web[cols.index("aes")] == "812"
    assert "custom.acrScore" not in cols                     # promoted, not swept
    assert web[cols.index("vuln.critical")] == "1"
    # Epoch -> ISO; the "never" (0) unauth scan is blank, not "1970".
    assert web[cols.index("last.auth.scan")].startswith("2020-09-13")
    assert web[cols.index("last.unauth.scan")] == ""
    # Unmapped field rides along under custom.*
    assert "custom.hasPassive" in cols
    assert web[cols.index("custom.hasPassive")] == "Yes"


def test_devices_stamped_with_asset_tags():
    result = tsc_runner_mod.run_query(_device_client(), _q("devices"))
    cols = result.column_names
    rows = {r[0]: r for r in result.rows}
    # 10.0.0.1 is in the "Web Servers" asset list; 10.0.0.2 is in none.
    assert rows["web01.corp"][cols.index("tags")] == "Web Servers"
    assert rows["db01.corp"][cols.index("tags")] == ""


def test_devices_tags_degrade_when_asset_lookup_fails():
    # No asset get-rule -> enrichment fails silently, devices still returned.
    client = FakeClient(analysis_rules={"sumip": _sumip_rule})
    result = tsc_runner_mod.run_query(client, _q("devices"))
    cols = result.column_names
    assert "tags" in cols
    assert all(r[cols.index("tags")] == "" for r in result.rows)
    assert len(result.rows) == 2


# --------------------------------------------------------------------------- #
# Hosts (Explore Assets, /rest/hosts — Security Center 6.x)
# --------------------------------------------------------------------------- #

def test_hosts_explore_assets_flatten():
    resp = {"totalRecords": 1, "results": [
        {"id": "1", "uuid": "h-1", "name": "web01.corp", "ipAddress": "10.0.0.1",
         "dnsName": "web01.corp", "netBios": "WEB01", "macAddress": "aa:bb:cc:00:00:01",
         "os": "Linux", "acrScore": "7", "assetExposureScore": "812",
         "repositories": [{"id": 1, "name": "Main"}], "systemType": "General Purpose",
         "firstSeen": "1600000000", "lastSeen": "1600000500", "source": "SCAN"}]}
    client = FakeClient(get_rules={"hosts": resp})
    result = tsc_runner_mod.run_query(client, _q("hosts", "TSC009", "Device Inventory"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("host.name")] == "web01.corp"
    assert row[cols.index("asset.type")] == "General Purpose"
    assert row[cols.index("acr")] == "7"
    assert row[cols.index("aes")] == "812"
    assert row[cols.index("repositories")] == "Main"        # list of objects -> names
    assert row[cols.index("host.netbios")] == "WEB01"       # netBios fallback key
    assert row[cols.index("last.seen")].startswith("2020-09-13")
    assert row[cols.index("custom.source")] == "SCAN"       # unmapped field swept


def test_hosts_plain_list_shape():
    # Some releases return a plain list rather than {results:[...]}.
    client = FakeClient(get_rules={"hosts": [{"name": "db01", "ipAddress": "10.0.0.2"}]})
    result = tsc_runner_mod.run_query(client, _q("hosts", "TSC009", "Device Inventory"))
    assert result.rows[0][result.column_names.index("host.name")] == "db01"


# --------------------------------------------------------------------------- #
# Findings (vulndetails)
# --------------------------------------------------------------------------- #

VULNDETAILS = [
    {"ip": "10.0.0.1", "dnsName": "web01.corp", "macAddress": "aa:bb:cc:00:00:01",
     "pluginID": "19506", "pluginName": "Nessus Scan Information",
     "severity": {"id": "3", "name": "High"}, "family": {"name": "General"},
     "port": "443", "protocol": "TCP", "repository": {"name": "Main"},
     "cve": "CVE-2021-1234", "baseScore": "7.5", "cvssV3BaseScore": "8.1",
     "vprScore": "6.4", "riskFactor": "High", "synopsis": "A finding.",
     "solution": "Patch it.", "firstSeen": "1600000000", "lastSeen": "1600000500",
     "pluginText": "<plugin_output>huge blob that must NOT become a column</plugin_output>"},
]


def test_findings_flatten_objects_and_skip_plugintext():
    client = FakeClient(analysis_rules={"vulndetails": VULNDETAILS})
    result = tsc_runner_mod.run_query(client, _q("findings", "TSC002", "Security Findings"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("host.name")] == "web01.corp"
    assert row[cols.index("severity")] == "High"      # nested object -> name
    assert row[cols.index("family")] == "General"
    assert row[cols.index("cvss.v3.base")] == "8.1"
    assert row[cols.index("first.seen")].startswith("2020-09-13")
    # The large pluginText field is excluded from the custom.* sweep.
    assert "custom.pluginText" not in cols


# --------------------------------------------------------------------------- #
# Software (listsoftware)
# --------------------------------------------------------------------------- #

def test_software_listing():
    records = [{"name": "OpenSSH 8.0", "count": "42"},
               {"name": "nginx 1.20", "count": "7"}]
    client = FakeClient(analysis_rules={"listsoftware": records})
    result = tsc_runner_mod.run_query(client, _q("software", "TSC003", "Software"))
    cols = result.column_names
    assert cols[0] == "software.name"
    assert "host.name" not in cols  # software rows are not host-keyed
    rows = {r[0]: r for r in result.rows}
    assert rows["OpenSSH 8.0"][cols.index("host.count")] == "42"


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def test_users_listing_objects_and_epoch():
    users = [{"id": "5", "username": "jdoe", "firstname": "Jane", "lastname": "Doe",
              "email": "jane@corp", "title": "Analyst",
              "role": {"id": "2", "name": "Security Manager"},
              "group": {"id": "1", "name": "Full Access"}, "orgName": "Corp",
              "authType": "tns", "locked": "false", "status": "0",
              "lastLogin": "1600000000"}]
    client = FakeClient(get_rules={"user": users})
    result = tsc_runner_mod.run_query(client, _q("users", "TSC004", "Users"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("host.name")] == "jdoe"     # username folds into Users view
    assert row[cols.index("full.name")] == "Jane Doe"
    assert row[cols.index("role")] == "Security Manager"
    assert row[cols.index("group")] == "Full Access"
    assert row[cols.index("last.login")].startswith("2020-09-13")


# --------------------------------------------------------------------------- #
# Asset lists (tags), alerts, incidents, saas
# --------------------------------------------------------------------------- #

def test_asset_lists_expose_tags():
    client = FakeClient(get_rules={"asset": ASSET_LISTS})
    result = tsc_runner_mod.run_query(client, _q("asset_lists", "TSC005", "Asset Tags"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("asset.name")] == "Web Servers"
    assert row[cols.index("tags")] == "prod,web"
    assert row[cols.index("ip.count")] == "1"
    assert row[cols.index("owner")] == "admin"


def test_alerts_merge_usable_manageable_dedup():
    resp = {
        "usable": [{"id": "1", "name": "Crit alert", "triggerName": "sumip",
                    "triggerOperator": ">", "triggerValue": "0", "status": "0",
                    "lastTriggered": "1600000000",
                    "action": [{"type": "email"}, {"type": "syslog"}]}],
        "manageable": [{"id": "1", "name": "Crit alert"}],  # duplicate id
    }
    client = FakeClient(get_rules={"alert": resp})
    result = tsc_runner_mod.run_query(client, _q("alerts", "TSC006", "Alerts & Incidents"))
    assert len(result.rows) == 1  # de-duplicated by id
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("trigger")] == "sumip > 0"
    assert row[cols.index("actions")] == "email, syslog"


def test_incidents_listing():
    resp = {"usable": [{"id": "9", "name": "Investigate host",
                        "status": {"name": "Assigned"}, "classification": "Malware",
                        "assignee": {"username": "jdoe"}, "owner": {"username": "admin"},
                        "createdTime": "1600000000"}]}
    client = FakeClient(get_rules={"ticket": resp})
    result = tsc_runner_mod.run_query(client, _q("incidents", "TSC007", "Alerts & Incidents"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("incident.name")] == "Investigate host"
    assert row[cols.index("status")] == "Assigned"
    assert row[cols.index("assignee")] == "jdoe"


def test_saas_applications_placeholder_empty():
    result = tsc_runner_mod.run_query(FakeClient(), _q("saas_applications", "TSC008", "SaaS Applications"))
    assert result.rows == []
    assert "application.name" in result.column_names


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        tsc_runner_mod.run_query(FakeClient(), _q("nope"))


# --------------------------------------------------------------------------- #
# Helpers: _listing, _epoch
# --------------------------------------------------------------------------- #

def test_listing_handles_list_and_buckets():
    assert tsc_runner_mod._listing([{"id": "1"}]) == [{"id": "1"}]
    merged = tsc_runner_mod._listing(
        {"usable": [{"id": "1"}, {"id": "2"}], "manageable": [{"id": "2"}, {"id": "3"}]}
    )
    assert [r["id"] for r in merged] == ["1", "2", "3"]


def test_epoch_conversion():
    assert tsc_runner_mod._epoch("0") == ""
    assert tsc_runner_mod._epoch("-1") == ""
    assert tsc_runner_mod._epoch(None) == ""
    assert tsc_runner_mod._epoch("1600000000").startswith("2020-09-13")
    # A non-epoch date string is left as-is rather than mangled.
    assert tsc_runner_mod._epoch("2026-01-01") == "2026-01-01"


# --------------------------------------------------------------------------- #
# Client construction / auth / envelope
# --------------------------------------------------------------------------- #

def test_build_client_requires_host_and_creds():
    with pytest.raises(tsc_client_mod.TenableScConfigError):
        tsc_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(tsc_client_mod.TenableScConfigError):
        tsc_client_mod.build_client(host="sc", username="", password="")
    # Access/secret key alone is a valid credential style.
    c = tsc_client_mod.build_client(host="sc", access_key="ak", secret_key="sk")
    assert c.host == "sc"


def test_clean_host_strips_scheme_and_path():
    assert tsc_client_mod.clean_host("https://sc.example.com/rest/") == "sc.example.com"
    assert tsc_client_mod.clean_host("  sc.example.com  ") == "sc.example.com"


def test_url_for_with_prefix():
    c = tsc_client_mod.build_client(host="sc", username="u", password="p", api_prefix="gw")
    assert c.url_for("analysis") == "https://sc/gw/rest/analysis"
    c2 = tsc_client_mod.build_client(host="sc", username="u", password="p")
    assert c2.url_for("user") == "https://sc/rest/user"


def test_unwrap_raises_on_error_code():
    with pytest.raises(RuntimeError):
        tsc_client_mod.TenableScClient._unwrap(
            {"error_code": 74, "error_msg": "boom", "response": {}}
        )
    assert tsc_client_mod.TenableScClient._unwrap(
        {"error_code": 0, "response": {"x": 1}}
    ) == {"x": 1}


def test_apikey_auth_sets_header_and_skips_login():
    c = tsc_client_mod.build_client(host="sc", access_key="ak", secret_key="sk")
    headers = c._base_headers()
    assert headers["x-apikey"] == "accesskey=ak; secretkey=sk"
    c.login()  # session-less: must be a no-op that leaves no token
    assert c._token is None


def test_analysis_paginates(monkeypatch):
    c = tsc_client_mod.build_client(host="sc", username="u", password="p")
    pages = {}

    def fake_post(path, body):
        start = body["query"]["startOffset"]
        # Two full pages then a short page.
        if start == 0:
            return {"results": [{"ip": f"p1-{i}"} for i in range(tsc_client_mod.ANALYSIS_PAGE_SIZE)],
                    "totalRecords": tsc_client_mod.ANALYSIS_PAGE_SIZE + 3}
        return {"results": [{"ip": "p2-0"}, {"ip": "p2-1"}, {"ip": "p2-2"}],
                "totalRecords": tsc_client_mod.ANALYSIS_PAGE_SIZE + 3}

    monkeypatch.setattr(c, "post", fake_post)
    records = c.analysis("sumip")
    assert len(records) == tsc_client_mod.ANALYSIS_PAGE_SIZE + 3


def test_build_client_from_env(monkeypatch):
    for var in ("TENABLE_SC_USERNAME", "TENABLE_SC_PASSWORD",
                "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TENABLE_SC_HOST", "sc.example.com")
    monkeypatch.setenv("TENABLE_SC_USERNAME", "svc")
    monkeypatch.setenv("TENABLE_SC_PASSWORD", "secret")
    client = tsc_client_mod.build_client_from_env()
    assert client.host == "sc.example.com"
    assert client.username == "svc"


def test_build_client_from_env_missing(monkeypatch):
    for var in ("TENABLE_SC_HOST", "TENABLE_SC_HOSTNAME", "SECURITYCENTER_HOST",
                "TENABLE_SC_USERNAME", "TENABLE_SC_PASSWORD",
                "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(tsc_client_mod.TenableScConfigError):
        tsc_client_mod.build_client_from_env()


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_default_manager_has_tenable_sc():
    manager = adapters_mod.default_manager()
    a = manager.get("tenable_sc")
    assert a.info.kind == "tenable_sc"
    assert a.info.category == "Vulnerability Management"


def test_adapter_env_for_form_userpass_and_keys():
    manager = adapters_mod.default_manager()
    adapter = manager.get("tenable_sc")
    env = adapter.env_for_form(
        {"host": "https://sc.example.com/", "username": "svc", "password": "secret"}
    )
    assert env["TENABLE_SC_HOST"] == "sc.example.com"
    assert env["TENABLE_SC_USERNAME"] == "svc"
    assert env["TENABLE_SC_VERIFY_CERTS"] == "true"
    env2 = adapter.env_for_form(
        {"host": "sc", "access_key": "ak", "secret_key": "sk"}
    )
    assert env2["TENABLE_SC_ACCESS_KEY"] == "ak"
    assert "TENABLE_SC_USERNAME" not in env2


def test_adapter_run_before_connect_raises():
    manager = adapters_mod.default_manager()
    adapter = manager.get("tenable_sc")
    q = adapter.registry.get_query("TSC001")
    with pytest.raises(tsc_client_mod.TenableScConfigError):
        adapter.run(q)


def test_adapter_connect_form(monkeypatch):
    manager = adapters_mod.default_manager()
    adapter = manager.get("tenable_sc")
    monkeypatch.setattr(tsc_client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(
        tsc_client_mod, "ping",
        lambda cl: {"product": "Tenable.sc (SecurityCenter)", "summary": "Tenable.sc @ sc"},
    )
    info = adapter.connect_form(
        {"host": "sc.example.com", "username": "svc", "password": "secret",
         "verify_certs": True, "request_timeout": 60}
    )
    assert info["product"] == "Tenable.sc (SecurityCenter)"
    assert adapter.connected is True
