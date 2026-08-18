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
    assert len(reg.queries) == 8
    assert len(reg.feeds) == 7
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


def test_rules_flatten_nested_fields():
    mapping = dict(DEVICES)
    mapping["devices/1/rules.json"] = {
        "rules": [
            {
                "uid": "{abc}",
                "name": "Allow web",
                "source": [{"name": "net-a"}, {"name": "net-b"}],
                "destination": {"ip": "10.10.10.10"},
                "service": "tcp/443",
                "action": "accept",
            }
        ]
    }
    result = tufin_runner_mod.run_query(FakeClient(mapping), _q("rules"))
    row = dict(zip(result.column_names, result.rows[0]))
    assert row["host.name"] == "HQ-Perimeter-FW"
    assert row["source"] == "net-a, net-b"
    assert row["destination"] == "10.10.10.10"
    assert row["action"] == "accept"


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


# --------------------------------------------------------------------------- #
# Adapter wiring
# --------------------------------------------------------------------------- #

def test_tufin_adapter_registered():
    manager = adapters_mod.default_manager()
    a = manager.get("tufin")
    assert a.info.kind == "tufin"
    assert a.info.category == "Network Security Policy"
    assert len(a.registry.queries) == 8


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
