"""Tests for the VMware adapter, registry, and REST-response normalization.

No live vCenter is contacted and pyVmomi is not required: a FakeClient returns
canned REST payloads keyed by path and canned custom-field / host-hardware maps,
mirroring how the real client's ``get`` / ``custom_values`` / ``host_hardware``
behave.
"""

from pathlib import Path

import pytest

from assetflow import adapters as adapters_mod
from assetflow import vmware_client as vmware_client_mod
from assetflow import vmware_runner as vmware_runner_mod
from assetflow.models import Query, Status
from assetflow.registry import load_registry

VMWARE_REGISTRY = Path(__file__).resolve().parent.parent / "config" / "vmware_registry.yaml"


class FakeClient:
    """Path -> payload map; unknown paths raise so fallbacks are exercised.

    Optionally carries ``custom_values`` / ``host_hardware`` / ``custom_field_defs``
    to stand in for the pyVmomi-backed enrichment.
    """

    def __init__(self, mapping, custom=None, hardware=None, defs=None):
        self.mapping = mapping
        self.host = "vc.test"
        self._custom = custom
        self._hardware = hardware
        self._defs = defs

    def get(self, path):
        if path in self.mapping:
            return self.mapping[path]
        raise RuntimeError(f"404 {path}")

    # Only present when configured, so tests can exercise the "pyVmomi absent"
    # path by omitting them.
    def custom_values(self):
        if self._custom is None:
            raise RuntimeError("pyVmomi not installed")
        return self._custom

    def host_hardware(self):
        return self._hardware or {}

    def custom_field_defs(self):
        return self._defs or []


def _q(resource: str) -> Query:
    return Query(
        id="VMW999",
        category="Virtual Servers",
        name="test",
        status=Status.partially_validated,
        purpose="test",
        resource=resource,
    )


VM_MAP = {
    "vcenter/vm": [
        {"vm": "vm-1", "name": "web01", "power_state": "POWERED_ON",
         "cpu_count": 4, "memory_size_MiB": 8192},
        {"vm": "vm-2", "name": "db01", "power_state": "POWERED_OFF",
         "cpu_count": 8, "memory_size_MiB": 16384},
    ],
    "vcenter/vm/vm-1": {"guest_OS": "UBUNTU_64"},
    "vcenter/vm/vm-1/guest/identity": {
        "host_name": "web01.corp", "ip_address": "10.0.0.21", "family": "LINUX"
    },
    "vcenter/vm/vm-2": {"guest_OS": "WINDOWS_2019_64"},
    "vcenter/vm/vm-2/guest/identity": {
        "host_name": "db01.corp", "ip_address": "10.0.0.22", "family": "WINDOWS"
    },
}


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_vmware_registry_loads_and_validates():
    reg = load_registry(str(VMWARE_REGISTRY))
    assert reg.metadata.version == 1
    assert len(reg.queries) == 6
    resources = {q.resource for q in reg.queries}
    assert {"virtual_machines", "hosts", "clusters", "datastores",
            "datacenters", "custom_attributes"} <= resources


def test_every_feed_references_known_queries():
    reg = load_registry(str(VMWARE_REGISTRY))
    ids = {q.id for q in reg.queries}
    for feed in reg.feeds:
        for qid in feed.query_ids:
            assert qid in ids


# --------------------------------------------------------------------------- #
# Virtual machines (virtual servers)
# --------------------------------------------------------------------------- #

def test_virtual_machines_standard_fields():
    client = FakeClient(VM_MAP)  # no custom_values -> no custom.* columns
    result = vmware_runner_mod.run_query(client, _q("virtual_machines"))
    cols = result.column_names
    assert cols[:3] == ["host.name", "vm.id", "asset.type"]
    assert not any(c.startswith("custom.") for c in cols)
    rows = {r[0]: r for r in result.rows}
    assert rows["web01"][cols.index("asset.type")] == "Virtual Machine"
    assert rows["web01"][cols.index("host.ip")] == "10.0.0.21"
    assert rows["web01"][cols.index("guest.family")] == "LINUX"
    assert rows["db01"][cols.index("power_state")] == "POWERED_OFF"


def test_virtual_machines_merge_custom_fields_prefixed():
    custom = {
        "vm-1": {"System Owner": "alice", "Department": "Web"},
        "vm-2": {"System Owner": "bob"},
    }
    client = FakeClient(VM_MAP, custom=custom)
    result = vmware_runner_mod.run_query(client, _q("virtual_machines"))
    cols = result.column_names
    # Custom columns are appended, sorted, and prefixed to distinguish them.
    assert "custom.System Owner" in cols
    assert "custom.Department" in cols
    assert cols.index("custom.Department") < cols.index("custom.System Owner")
    rows = {r[0]: r for r in result.rows}
    assert rows["web01"][cols.index("custom.System Owner")] == "alice"
    assert rows["web01"][cols.index("custom.Department")] == "Web"
    # vm-2 has no Department -> padded blank, not misaligned.
    assert rows["db01"][cols.index("custom.Department")] == ""
    assert rows["db01"][cols.index("custom.System Owner")] == "bob"


def test_vm_detail_scan_bounds_per_vm_calls():
    # With scan=0, no per-VM detail/identity calls are made; summary still lists.
    client = FakeClient({"vcenter/vm": VM_MAP["vcenter/vm"]})
    result = vmware_runner_mod.run_query(
        client, _q("virtual_machines"), vm_detail_scan=0
    )
    cols = result.column_names
    rows = {r[0]: r for r in result.rows}
    assert len(result.rows) == 2
    assert rows["web01"][cols.index("host.ip")] == ""
    assert rows["web01"][cols.index("guest.os")] == ""


# --------------------------------------------------------------------------- #
# Hosts (physical servers)
# --------------------------------------------------------------------------- #

def test_hosts_classified_physical_with_hardware_and_custom():
    host_map = {
        "vcenter/host": [
            {"host": "host-9", "name": "esxi01",
             "connection_state": "CONNECTED", "power_state": "POWERED_ON"},
        ]
    }
    hardware = {
        "host-9": {"vendor": "Dell", "model": "R740", "cpu_model": "Xeon",
                   "cpu_cores": "32", "memory_gib": "512", "version": "8.0.2",
                   "build": "12345", "cluster": "CL1"},
    }
    custom = {"host-9": {"System Owner": "bob"}}
    client = FakeClient(host_map, custom=custom, hardware=hardware)
    result = vmware_runner_mod.run_query(client, _q("hosts"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("asset.type")] == "Physical Host (ESXi)"
    assert row[cols.index("hardware.vendor")] == "Dell"
    assert row[cols.index("memory.gib")] == "512"
    assert row[cols.index("cluster")] == "CL1"
    assert row[cols.index("custom.System Owner")] == "bob"


# --------------------------------------------------------------------------- #
# Clusters / datastores / datacenters
# --------------------------------------------------------------------------- #

def test_datastores_bytes_to_gib():
    ds_map = {
        "vcenter/datastore": [
            {"datastore": "datastore-1", "name": "ds01", "type": "VMFS",
             "capacity": 1024 ** 3 * 100, "free_space": 1024 ** 3 * 40},
        ]
    }
    result = vmware_runner_mod.run_query(FakeClient(ds_map), _q("datastores"))
    cols = result.column_names
    row = result.rows[0]
    assert row[cols.index("asset.type")] == "Datastore"
    assert row[cols.index("capacity.gib")] == "100.0"
    assert row[cols.index("free.gib")] == "40.0"


def test_clusters_and_datacenters():
    m = {
        "vcenter/cluster": [
            {"cluster": "domain-c7", "name": "CL1", "ha_enabled": True, "drs_enabled": False}
        ],
        "vcenter/datacenter": [{"datacenter": "datacenter-2", "name": "DC1"}],
    }
    cl = vmware_runner_mod.run_query(FakeClient(m), _q("clusters"))
    assert cl.rows[0][cl.column_names.index("asset.type")] == "Compute Cluster"
    assert cl.rows[0][cl.column_names.index("ha_enabled")] == "true"
    dc = vmware_runner_mod.run_query(FakeClient(m), _q("datacenters"))
    assert dc.rows[0][dc.column_names.index("asset.type")] == "Datacenter"


def test_custom_attribute_definitions():
    defs = [
        {"key": 101, "name": "System Owner", "object_type": "VirtualMachine"},
        {"key": 102, "name": "PR/DR Site", "object_type": ""},
    ]
    client = FakeClient({}, defs=defs)
    result = vmware_runner_mod.run_query(client, _q("custom_attributes"))
    cols = result.column_names
    rows = {r[cols.index("custom_field.name")]: r for r in result.rows}
    assert rows["System Owner"][cols.index("applies_to")] == "VirtualMachine"
    assert rows["PR/DR Site"][cols.index("applies_to")] == "Global"


# --------------------------------------------------------------------------- #
# Legacy /rest {"value": …} envelope handling
# --------------------------------------------------------------------------- #

def test_unwrap_handles_value_envelope():
    wrapped = {"vcenter/vm": {"value": VM_MAP["vcenter/vm"]}}
    result = vmware_runner_mod.run_query(
        FakeClient(wrapped), _q("virtual_machines"), vm_detail_scan=0
    )
    assert len(result.rows) == 2


def test_unknown_resource_raises():
    with pytest.raises(ValueError):
        vmware_runner_mod.run_query(FakeClient({}), _q("nope"))


# --------------------------------------------------------------------------- #
# Client construction / env
# --------------------------------------------------------------------------- #

def test_build_client_requires_host_and_creds():
    with pytest.raises(vmware_client_mod.VMwareConfigError):
        vmware_client_mod.build_client(host="", username="u", password="p")
    with pytest.raises(vmware_client_mod.VMwareConfigError):
        vmware_client_mod.build_client(host="vc", username="", password="")


def test_clean_host_strips_scheme_and_path():
    assert vmware_client_mod.clean_host("https://vc.example.com/ui/") == "vc.example.com"
    assert vmware_client_mod.clean_host("  vc.example.com  ") == "vc.example.com"


def test_build_client_from_env(monkeypatch):
    monkeypatch.setenv("VC_HOSTNAME", "vc.example.com")
    monkeypatch.setenv("VC_USERNAME", "svc")
    monkeypatch.setenv("VC_PASSWORD", "secret")
    monkeypatch.setenv("VCENTER_PORT", "8443")
    client = vmware_client_mod.build_client_from_env()
    assert client.host == "vc.example.com"
    assert client.port == 8443
    assert client.base_url == "https://vc.example.com:8443"


def test_build_client_from_env_missing(monkeypatch):
    for var in ("VC_HOSTNAME", "VCENTER_HOST", "VMWARE_HOST",
                "VC_USERNAME", "VC_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(vmware_client_mod.VMwareConfigError):
        vmware_client_mod.build_client_from_env()


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_vmware_adapter_env_for_form():
    manager = adapters_mod.default_manager()
    adapter = manager.get("vmware")
    env = adapter.env_for_form(
        {"host": "https://vc.example.com/", "username": "svc",
         "password": "secret", "port": 443}
    )
    assert env["VC_HOSTNAME"] == "vc.example.com"
    assert env["VC_USERNAME"] == "svc"
    assert env["VCENTER_VERIFY_CERTS"] == "true"


def test_vmware_adapter_run_before_connect_raises():
    manager = adapters_mod.default_manager()
    adapter = manager.get("vmware")
    q = adapter.registry.get_query("VMW001")
    with pytest.raises(vmware_client_mod.VMwareConfigError):
        adapter.run(q)


def test_vmware_adapter_connect_form(monkeypatch):
    manager = adapters_mod.default_manager()
    adapter = manager.get("vmware")
    monkeypatch.setattr(vmware_client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(
        vmware_client_mod, "ping",
        lambda cl: {"product": "VMware vCenter", "summary": "vCenter @ vc"},
    )
    info = adapter.connect_form(
        {"host": "vc.example.com", "username": "svc", "password": "secret",
         "port": 443, "verify_certs": True, "request_timeout": 60}
    )
    assert info["product"] == "VMware vCenter"
    assert adapter.connected is True
