"""Tests for the BMC Remedy adapter, registry, and AR-response normalization.

No live Remedy is contacted: a FakeClient returns canned AR entries keyed by
form name, mirroring how the real client's ``get_entries`` behaves.
"""

from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import remedy_client as remedy_client_mod
from assetflow import remedy_runner as remedy_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry

REMEDY_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "remedy_registry.yaml"


class FakeClient:
    """Form -> list-of-entries map; each entry is ``{"values": {...}}``."""

    def __init__(self, entries_by_form):
        self.entries_by_form = entries_by_form
        self.host = "remedy.test"

    def get_entries(self, form, **kwargs):
        return self.entries_by_form.get(form, [])


def _q(resource: str) -> Query:
    return Query(
        id="RMD999",
        category="Computer Systems",
        name="test",
        status=Status.partially_validated,
        purpose="test",
        resource=resource,
    )


def _entries(*value_dicts):
    return [{"values": v} for v in value_dicts]


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_remedy_registry_loads_and_validates():
    reg = load_registry(str(REMEDY_REGISTRY))
    assert reg.metadata.version == 1
    assert len(reg.queries) == 6
    resources = {q.resource for q in reg.queries}
    assert {
        "computer_systems", "software", "business_services",
        "people", "incidents", "changes",
    } <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(REMEDY_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


# --------------------------------------------------------------------------- #
# Computer systems (CMDB CIs)
# --------------------------------------------------------------------------- #

CS_FORM = "BMC.CORE:BMC_ComputerSystem"


def test_computer_systems_standard_fields_and_asset_type():
    client = FakeClient({CS_FORM: _entries(
        {"Name": "web01", "SystemRole": "Server", "HostName": "web01.corp",
         "IPAddress": "10.0.0.21", "Manufacturer": "Dell", "Model": "R740",
         "SerialNumber": "SN1", "Category": "Hardware", "Type": "Server",
         "Item": "Server", "AssetLifecycleStatus": "Deployed", "Company": "Acme"},
        {"Name": "laptop02", "SystemRole": "Client"},
        {"Name": "thing03"},
    )})
    result = remedy_runner_mod.run_query(client, _q("computer_systems"))
    cols = result.column_names
    assert cols[:2] == ["host.name", "asset.type"]
    rows = {r[0]: r for r in result.rows}
    assert rows["web01"][cols.index("asset.type")] == "Server"
    assert rows["web01"][cols.index("host.ip")] == "10.0.0.21"
    assert rows["web01"][cols.index("serial_number")] == "SN1"
    assert rows["laptop02"][cols.index("asset.type")] == "Workstation"
    # No SystemRole and no CTI Item/Type -> generic classification.
    assert rows["thing03"][cols.index("asset.type")] == "Computer System"


def test_computer_systems_custom_fields_prefixed_and_plumbing_dropped():
    client = FakeClient({CS_FORM: _entries(
        {"Name": "web01", "SystemRole": "Server",
         "Cost Center": "CC-100", "Owner Group": "Web",
         "Request ID": "RE0001", "zTmpWork": "ignore-me", "Modified Date": "x"},
        {"Name": "web02", "SystemRole": "Server", "Cost Center": "CC-200"},
    )})
    result = remedy_runner_mod.run_query(client, _q("computer_systems"))
    cols = result.column_names
    # Site-added fields become sorted, prefixed custom columns.
    assert "custom.Cost Center" in cols
    assert "custom.Owner Group" in cols
    assert cols.index("custom.Cost Center") < cols.index("custom.Owner Group")
    # AR plumbing and z* workflow fields never surface.
    assert not any(c in ("custom.Request ID", "custom.zTmpWork",
                         "custom.Modified Date") for c in cols)
    rows = {r[0]: r for r in result.rows}
    assert rows["web01"][cols.index("custom.Cost Center")] == "CC-100"
    # web02 has no Owner Group -> padded blank, not misaligned.
    assert rows["web02"][cols.index("custom.Owner Group")] == ""
    assert rows["web02"][cols.index("custom.Cost Center")] == "CC-200"


# --------------------------------------------------------------------------- #
# Software / business services / people
# --------------------------------------------------------------------------- #

def test_software_version_fallback_and_type():
    client = FakeClient({"BMC.CORE:BMC_Product": _entries(
        {"Name": "nginx", "VersionNumber": "1.24", "Manufacturer": "F5"},
        {"Name": "office", "MarketVersion": "2021", "VersionNumber": "16.0"},
    )})
    result = remedy_runner_mod.run_query(client, _q("software"))
    cols = result.column_names
    rows = {r[0]: r for r in result.rows}
    assert rows["nginx"][cols.index("asset.type")] == "Software"
    assert rows["nginx"][cols.index("version")] == "1.24"
    # MarketVersion is preferred over VersionNumber.
    assert rows["office"][cols.index("version")] == "2021"


def test_business_services_type_and_status():
    client = FakeClient({"BMC.CORE:BMC_BusinessService": _entries(
        {"Name": "Payroll", "Description": "HR payroll", "Status": "Deployed",
         "Company": "Acme", "OwnerName": "Finance"},
    )})
    result = remedy_runner_mod.run_query(client, _q("business_services"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("host.name")] == "Payroll"
    assert row[cols.index("asset.type")] == "Business Service"
    assert row[cols.index("status")] == "Deployed"
    assert row[cols.index("owner")] == "Finance"


def test_people_full_name_fallback():
    client = FakeClient({"CTM:People": _entries(
        {"Full Name": "Alice A", "Corporate ID": "C1",
         "Internet E-mail": "a@x", "Support Staff": "Yes"},
        {"First Name": "Bob", "Last Name": "B", "Corporate ID": "C2"},
    )})
    result = remedy_runner_mod.run_query(client, _q("people"))
    cols = result.column_names
    names = [r[cols.index("host.name")] for r in result.rows]
    assert "Alice A" in names
    # No Full Name -> First + Last.
    assert "Bob B" in names
    rows = {r[cols.index("host.name")]: r for r in result.rows}
    assert rows["Alice A"][cols.index("asset.type")] == "Person"
    assert rows["Alice A"][cols.index("email")] == "a@x"


# --------------------------------------------------------------------------- #
# Incidents / changes (operational context)
# --------------------------------------------------------------------------- #

def test_incidents_fields_and_affected_ci():
    client = FakeClient({"HPD:Help Desk": _entries(
        {"Incident Number": "INC001", "Description": "disk full",
         "Status": "Assigned", "Priority": "High", "Impact": "2-Significant",
         "Urgency": "2-High", "Service Type": "Restoration",
         "HPD_CI": "web01", "Assignee": "Alice"},
    )})
    result = remedy_runner_mod.run_query(client, _q("incidents"))
    cols = result.column_names
    assert "host.name" not in cols  # operational record, not an asset row
    row = result.rows[0]
    assert row[cols.index("incident.id")] == "INC001"
    assert row[cols.index("asset.type")] == "Incident"
    assert row[cols.index("ci.name")] == "web01"
    assert row[cols.index("summary")] == "disk full"


def test_changes_id_fallback():
    client = FakeClient({"CHG:Infrastructure Change": _entries(
        {"Infrastructure Change ID": "CRQ001", "Description": "patch",
         "Change Request Status": "Scheduled", "Risk Level": "Risk Level 2",
         "Priority": "Medium", "Change Coordinator Group": "Net Ops",
         "Scheduled Start Date": "2026-01-01"},
        {"Change Request ID": "CRQ002", "Description": "fallback id"},
    )})
    result = remedy_runner_mod.run_query(client, _q("changes"))
    cols = result.column_names
    ids = [r[cols.index("change.id")] for r in result.rows]
    assert "CRQ001" in ids
    assert "CRQ002" in ids  # fell back to Change Request ID
    rows = {r[cols.index("change.id")]: r for r in result.rows}
    assert rows["CRQ001"][cols.index("asset.type")] == "Change Request"
    assert rows["CRQ001"][cols.index("coordinator_group")] == "Net Ops"


# --------------------------------------------------------------------------- #
# Dispatch / resource mapping
# --------------------------------------------------------------------------- #

def test_form_for_resource_mapping():
    assert remedy_runner_mod.form_for_resource("computer_systems") == CS_FORM
    assert remedy_runner_mod.form_for_resource("incidents") == "HPD:Help Desk"
    with pytest.raises(ValueError):
        remedy_runner_mod.form_for_resource("nope")


def test_unknown_and_empty_resource_raise():
    with pytest.raises(ValueError):
        remedy_runner_mod.run_query(FakeClient({}), _q("nope"))
    with pytest.raises(ValueError):
        remedy_runner_mod.run_query(FakeClient({}), _q(""))


def test_limit_caps_rows():
    client = FakeClient({CS_FORM: _entries(
        {"Name": "a"}, {"Name": "b"}, {"Name": "c"},
    )})
    result = remedy_runner_mod.run_query(client, _q("computer_systems"), limit=2)
    assert result.row_count == 2


# --------------------------------------------------------------------------- #
# Client construction / env
# --------------------------------------------------------------------------- #

def test_build_client_requires_host_and_creds():
    with pytest.raises(remedy_client_mod.RemedyConfigError):
        remedy_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(remedy_client_mod.RemedyConfigError):
        remedy_client_mod.build_client(host="remedy", username="", password="")


def test_clean_host_and_scheme():
    assert remedy_client_mod.clean_host("https://remedy.example.com/arsys/") == "remedy.example.com"
    assert remedy_client_mod.clean_host("  remedy.example.com  ") == "remedy.example.com"
    assert remedy_client_mod.scheme_of("http://h:8008") == "http"
    assert remedy_client_mod.scheme_of("remedy.example.com") == ""


def test_base_url_default_and_custom_port():
    c = remedy_client_mod.build_client(
        host="remedy.example.com", username="u", password="p", port=443
    )
    assert c.base_url == "https://remedy.example.com"
    c2 = remedy_client_mod.build_client(
        host="remedy.example.com", username="u", password="p", port=8443
    )
    assert c2.base_url == "https://remedy.example.com:8443"


def test_http_host_forces_plain_and_keeps_embedded_port():
    c = remedy_client_mod.build_client(
        host="http://remedy.example.com:8008", username="u", password="p"
    )
    assert c.use_ssl is False
    assert c.base_url == "http://remedy.example.com:8008"


def test_build_client_from_env(monkeypatch):
    monkeypatch.setenv("REMEDY_HOST", "remedy.example.com")
    monkeypatch.setenv("REMEDY_USERNAME", "svc")
    monkeypatch.setenv("REMEDY_PASSWORD", "secret")
    monkeypatch.setenv("REMEDY_PORT", "8443")
    client = remedy_client_mod.build_client_from_env()
    assert client.host == "remedy.example.com"
    assert client.port == 8443
    assert client.base_url == "https://remedy.example.com:8443"


def test_build_client_from_env_missing(monkeypatch):
    for var in ("REMEDY_HOST", "AR_HOST", "BMC_REMEDY_HOST",
                "REMEDY_USERNAME", "AR_USERNAME", "BMC_REMEDY_USERNAME",
                "REMEDY_PASSWORD", "AR_PASSWORD", "BMC_REMEDY_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(remedy_client_mod.RemedyConfigError):
        remedy_client_mod.build_client_from_env()


def test_get_entries_walks_pages_and_caps(monkeypatch):
    client = remedy_client_mod.build_client(
        host="remedy.example.com", username="u", password="p",
        page_size=2, max_records=5,
    )
    client._token = "tok"  # skip network login
    pages = {
        0: [{"values": {"Name": "a"}}, {"values": {"Name": "b"}}],
        2: [{"values": {"Name": "c"}}, {"values": {"Name": "d"}}],
        4: [{"values": {"Name": "e"}}, {"values": {"Name": "f"}}],
    }

    def fake_get_page(form, params):
        return pages.get(params["offset"], [])

    monkeypatch.setattr(client, "_get_page", fake_get_page)
    out = client.get_entries("BMC.CORE:BMC_ComputerSystem")
    # max_records caps the total at 5 even though more pages exist.
    assert len(out) == 5
    assert [e["values"]["Name"] for e in out] == ["a", "b", "c", "d", "e"]


def test_get_entries_stops_on_short_page(monkeypatch):
    client = remedy_client_mod.build_client(
        host="remedy.example.com", username="u", password="p", page_size=10,
    )
    client._token = "tok"
    calls = []

    def fake_get_page(form, params):
        calls.append(params["offset"])
        return [{"values": {"Name": "only"}}]  # short page -> stop

    monkeypatch.setattr(client, "_get_page", fake_get_page)
    out = client.get_entries("CTM:People")
    assert len(out) == 1
    assert calls == [0]  # no second page fetched


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_default_manager_has_remedy():
    manager = adapters_mod.default_manager()
    ids = [a.info.id for a in manager.list()]
    assert "remedy" in ids
    r = manager.get("remedy")
    assert r.info.category == "IT Asset Management / CMDB"
    assert r.info.kind == "remedy"
    assert len(r.registry.queries) == 6


def test_remedy_adapter_env_for_form():
    manager = adapters_mod.default_manager()
    adapter = manager.get("remedy")
    env = adapter.env_for_form(
        {"host": "https://remedy.example.com/", "username": "svc",
         "password": "secret", "port": 443}
    )
    assert env["REMEDY_HOST"] == "remedy.example.com"
    assert env["REMEDY_USERNAME"] == "svc"
    assert env["REMEDY_VERIFY_CERTS"] == "true"


def test_remedy_adapter_env_for_form_keeps_http_scheme():
    manager = adapters_mod.default_manager()
    adapter = manager.get("remedy")
    env = adapter.env_for_form(
        {"host": "http://remedy.corp:8008", "username": "svc", "password": "p"}
    )
    assert env["REMEDY_HOST"] == "http://remedy.corp:8008"


def test_remedy_adapter_run_before_connect_raises():
    manager = adapters_mod.default_manager()
    adapter = manager.get("remedy")
    q = adapter.registry.get_query("RMD001")
    with pytest.raises(remedy_client_mod.RemedyConfigError):
        adapter.run(q)


def test_remedy_adapter_connect_form(monkeypatch):
    manager = adapters_mod.default_manager()
    adapter = manager.get("remedy")
    monkeypatch.setattr(remedy_client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(
        remedy_client_mod, "ping",
        lambda cl: {"product": "BMC Remedy AR System", "summary": "BMC Remedy @ h"},
    )
    info = adapter.connect_form(
        {"host": "remedy.example.com", "username": "svc", "password": "secret",
         "port": 443, "verify_certs": True, "request_timeout": 60}
    )
    assert info["product"] == "BMC Remedy AR System"
    assert adapter.connected is True
