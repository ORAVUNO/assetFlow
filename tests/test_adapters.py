"""Tests for the adapter layer (Elasticsearch mocked)."""

import pytest

from assetflow import adapters as adapters_mod
from assetflow import client as client_mod
from assetflow import runner as runner_mod
from assetflow.runner import QueryResult

RESULT = QueryResult(columns=[{"name": "host.name"}], rows=[["h"]])


@pytest.fixture
def manager():
    return adapters_mod.default_manager()


def test_default_manager_has_elasticsearch_and_tufin(manager):
    ids = [a.info.id for a in manager.list()]
    assert "elasticsearch" in ids
    assert "tufin" in ids
    a = manager.get("elasticsearch")
    assert a.info.category == "SIEM / Log Analytics"
    assert len(a.registry.queries) == 27


def test_by_category(manager):
    cats = manager.by_category()
    assert "SIEM / Log Analytics" in cats
    assert "Network Security Policy" in cats


def test_connect_and_run(manager, monkeypatch):
    a = manager.get("elasticsearch")
    monkeypatch.setattr(client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(client_mod, "ping", lambda cl: {"cluster_name": "c", "version": "8.13"})
    monkeypatch.setattr(runner_mod, "run_query", lambda cl, q, limit=None, time_range=None: RESULT)

    assert a.connected is False
    info = a.connect(url="https://h:9200", username="u", password="p")
    assert info["cluster_name"] == "c"
    assert a.connected is True

    q = a.registry.get_query("AI001")
    out = a.run(q, limit=10, time_range="7d")
    assert out.row_count == 1


def test_run_before_connect_raises(manager):
    a = manager.get("elasticsearch")
    q = a.registry.get_query("AI001")
    with pytest.raises(client_mod.ConnectionConfigError):
        a.run(q)


def test_unknown_adapter(manager):
    with pytest.raises(KeyError):
        manager.get("nope")


def test_multiple_instances_of_same_kind(manager):
    a = manager.add_instance("tufin", "Tufin HQ")
    b = manager.add_instance("tufin", "Tufin DR")
    assert a.info.id != b.info.id
    assert a.info.kind == b.info.kind == "tufin"
    # both share the kind's registry but are distinct instances
    assert a.registry is b.registry
    ids = [x.info.id for x in manager.list()]
    assert a.info.id in ids and b.info.id in ids
    # slug derives from the label
    assert manager.get(a.info.id).info.name == "Tufin HQ"


def test_unique_labels_are_suffixed(manager):
    a = manager.add_instance("tufin", "Prod")
    b = manager.add_instance("tufin", "Prod")
    assert a.info.name == "Prod"
    assert b.info.name == "Prod (2)"


def test_rename_and_remove_instance(manager):
    a = manager.add_instance("elasticsearch", "Cluster A")
    manager.rename(a.info.id, "Cluster B")
    assert manager.get(a.info.id).info.name == "Cluster B"
    manager.remove(a.info.id)
    with pytest.raises(KeyError):
        manager.get(a.info.id)


def test_add_instance_unknown_kind(manager):
    with pytest.raises(KeyError):
        manager.add_instance("vmware", "vCenter")
