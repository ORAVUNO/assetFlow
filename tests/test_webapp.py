"""Web API tests (adapter-scoped) with Elasticsearch mocked and a temp DB."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assetflow import client as client_mod
from assetflow import runner as runner_mod
from assetflow import webapp
from assetflow.runner import QueryResult

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "config" / "asset_intelligence_registry.yaml"

FAKE_RESULT = QueryResult(
    columns=[{"name": "host.name", "type": "keyword"}, {"name": "LoginCount", "type": "long"}],
    rows=[["host-a", 5], ["host-b", 2]],
)
A = "elasticsearch"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(client_mod, "build_client_from_env", lambda: object())
    monkeypatch.setattr(
        client_mod, "ping", lambda cl: {"cluster_name": "test", "version": "8.13.0"}
    )
    monkeypatch.setattr(runner_mod, "run_query", lambda c, q, limit=None, time_range=None: FAKE_RESULT)
    app = webapp.create_app(str(REGISTRY_PATH), db_url=f"sqlite:///{tmp_path}/t.db")
    return TestClient(app)


def test_index_served(client):
    assert "assetFlow" in client.get("/").text


def test_adapters_listing(client):
    d = client.get("/api/adapters").json()
    cats = d["categories"]
    assert any(a["id"] == "elasticsearch" for c in cats for a in c["adapters"])


def test_adapter_detail(client):
    d = client.get(f"/api/adapters/{A}").json()
    assert d["id"] == "elasticsearch"
    assert len(d["queries"]) == 27
    assert len(d["feeds"]) == 9
    # auto-connected from env in the fixture
    assert d["connected"] is True


def test_connect(client):
    r = client.post(f"/api/adapters/{A}/connect",
                    json={"host": "10.0.0.5", "port": "9243", "username": "u", "password": "p"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["resolved_url"] == "https://10.0.0.5:9243"


def test_run_saves_and_exports(client):
    run = client.post(f"/api/adapters/{A}/run/AI001?limit=10&range=7d")
    assert run.status_code == 200
    body = run.json()
    assert body["row_count"] == 2 and body["time_range"] == "7d"

    latest = client.get(f"/api/adapters/{A}/latest/AI001")
    assert latest.status_code == 200 and latest.json()["query_id"] == "AI001"

    # detail now shows the query as fetched
    detail = client.get(f"/api/adapters/{A}").json()
    ai001 = next(q for q in detail["queries"] if q["id"] == "AI001")
    assert ai001["last_fetch"]["row_count"] == 2

    assert "host.name" in client.get(f"/api/adapters/{A}/export/AI001.csv").text
    assert client.get(f"/api/adapters/{A}/export/AI001.json").json()[0]["host.name"] == "host-a"


def test_platform_and_adapter_export(client):
    import io
    import json
    import zipfile

    # populate a couple of saved results
    client.post(f"/api/adapters/{A}/run/AI001?limit=5")
    client.post(f"/api/adapters/{A}/run/AI002?limit=5")

    # platform JSON
    pj = client.get("/api/export-all.json")
    assert pj.status_code == 200
    body = pj.json()
    assert body["scope"] == "platform"
    qids = {q["query_id"] for a in body["adapters"] for q in a["queries"]}
    assert {"AI001", "AI002"} <= qids

    # adapter ZIP
    az = client.get(f"/api/adapters/{A}/export-all.zip")
    assert az.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(az.content))
    assert "manifest.json" in zf.namelist()
    assert f"{A}/AI001.csv" in zf.namelist()

    # bad format
    assert client.get("/api/export-all.xml").status_code == 400


def test_merged_view_and_export(client):
    client.post(f"/api/adapters/{A}/run/AI001?limit=5")  # host-keyed (host.name column)
    d = client.get(f"/api/adapters/{A}/merged").json()
    assert "main" in d and "sheets" in d
    assert "AI001" in d["main"]["contributing"]
    assert d["main"]["host_count"] >= 1
    # sheets group by feed and mark fetched vs not
    ai001 = None
    for sh in d["sheets"]:
        for q in sh["queries"]:
            if q["query_id"] == "AI001":
                ai001 = q
    assert ai001 is not None and ai001["has_data"] is True

    csv = client.get(f"/api/adapters/{A}/merged.csv")
    assert csv.status_code == 200 and "host.name" in csv.text
    assert client.get(f"/api/adapters/{A}/merged.json").status_code == 200


def test_unified_inventory(client):
    # host-keyed fetch feeds the cross-adapter inventory
    client.post(f"/api/adapters/{A}/run/AI001?limit=5")
    d = client.get("/api/inventory").json()
    cols = [c["name"] for c in d["columns"]]
    assert cols[:6] == [
        "host.name", "aliases", "host.ip", "seen_by", "adapter_count", "correlated_by",
    ]
    assert "Elasticsearch" in cols
    assert d["asset_count"] >= 1
    # only one adapter has data here, so nothing is multi-adapter
    assert d["multi_adapter_count"] == 0
    assert any(a["id"] == "elasticsearch" for a in d["adapters"])

    hosts = {r[0] for r in d["rows"]}
    assert {"host-a", "host-b"} <= hosts

    # exports
    csv = client.get("/api/inventory.csv")
    assert csv.status_code == 200 and "seen_by" in csv.text
    assert client.get("/api/inventory.json").status_code == 200
    assert client.get("/api/inventory.xml").status_code == 400


def test_inventory_asset_detail(client):
    client.post(f"/api/adapters/{A}/run/AI001?limit=5")  # host.name + LoginCount
    d = client.get("/api/inventory/asset?host=host-a").json()
    assert d["found"] is True and d["host"] == "host-a"
    assert any(a["id"] == "elasticsearch" for a in d["adapters"])
    # LoginCount is a field of this single-adapter asset -> specific
    lc = next((f for f in d["fields"] if f["name"] == "LoginCount"), None)
    assert lc is not None and lc["scope"] == "specific"
    # the AI001 result is available as a mini table
    assert any(t["query_id"] == "AI001" for t in d["tables"])
    # unknown host -> 404
    assert client.get("/api/inventory/asset?host=nope").status_code == 404


def test_kinds_listing(client):
    d = client.get("/api/kinds").json()
    kinds = {k["kind"] for k in d["kinds"]}
    assert "elasticsearch" in kinds and "tufin" in kinds


def test_multiple_connections_lifecycle(client):
    # default per-kind connections are seeded on a fresh db
    cats = client.get("/api/adapters").json()["categories"]
    ids = {a["id"] for c in cats for a in c["adapters"]}
    assert {"elasticsearch", "tufin"} <= ids

    # add a second Tufin instance with a label
    r = client.post("/api/connections", json={"kind": "tufin", "label": "Tufin HQ"})
    assert r.status_code == 200
    new_id = r.json()["id"]
    assert new_id != "tufin" and r.json()["name"] == "Tufin HQ"

    # it shows up in the gallery and has its own workspace
    cats = client.get("/api/adapters").json()["categories"]
    ids = {a["id"] for c in cats for a in c["adapters"]}
    assert new_id in ids
    assert client.get(f"/api/adapters/{new_id}").json()["name"] == "Tufin HQ"

    # rename it
    rn = client.patch(f"/api/connections/{new_id}", json={"label": "Tufin HQ – EU"})
    assert rn.status_code == 200 and rn.json()["name"] == "Tufin HQ – EU"

    # remove it
    assert client.delete(f"/api/connections/{new_id}").status_code == 200
    ids = {a["id"] for c in client.get("/api/adapters").json()["categories"] for a in c["adapters"]}
    assert new_id not in ids

    # unknown kind rejected
    assert client.post("/api/connections", json={"kind": "vmware", "label": "x"}).status_code == 404


def test_inventory_spans_multiple_instances(client):
    # two Elasticsearch instances, each with its own saved data
    r = client.post("/api/connections", json={"kind": "elasticsearch", "label": "Elastic EU"})
    eu = r.json()["id"]
    # connect the new instance (build_client/ping are mocked in the fixture)
    assert client.post(f"/api/adapters/{eu}/connect", json={"host": "10.0.0.9"}).json()["ok"]

    client.post(f"/api/adapters/{A}/run/AI001?limit=5")   # default Elasticsearch
    client.post(f"/api/adapters/{eu}/run/AI001?limit=5")  # Elastic EU

    d = client.get("/api/inventory").json()
    cols = [c["name"] for c in d["columns"]]
    # both instances contribute their own per-connection column, by label
    assert "Elasticsearch" in cols and "Elastic EU" in cols
    # same hosts reported by both instances -> seen by 2 "adapters"
    assert d["multi_adapter_count"] >= 1


def test_remembered_connection_persists_secrets(client):
    r = client.post(f"/api/adapters/{A}/connect",
                    json={"host": "10.0.0.5", "username": "u", "password": "p", "remember": True})
    assert r.status_code == 200 and r.json()["saved"] is True
    # detail now reports saved credentials
    assert client.get(f"/api/adapters/{A}").json()["has_saved"] is True
    # forget clears them
    assert client.delete(f"/api/adapters/{A}/saved-connection").status_code == 200
    assert client.get(f"/api/adapters/{A}").json()["has_saved"] is False


def test_run_placeholder_rejected(client):
    # All shipped queries are now runnable, so force one non-runnable to exercise
    # the 422 "no query defined" branch.
    q = webapp._manager().get(A).registry.get_query("AI016")
    original = q.esql_query
    q.esql_query = ""
    try:
        assert client.post(f"/api/adapters/{A}/run/AI016").status_code == 422
    finally:
        q.esql_query = original


def test_latest_missing_is_404(client):
    assert client.get(f"/api/adapters/{A}/latest/AI012").status_code == 404


def test_unknown_adapter_404(client):
    assert client.get("/api/adapters/nope").status_code == 404


def test_run_timeout_hint(client, monkeypatch):
    def boom(c, q, limit=None, time_range=None):
        raise Exception("Connection timeout caused by: ReadTimeoutError")

    monkeypatch.setattr(runner_mod, "run_query", boom)
    r = client.post(f"/api/adapters/{A}/run/AI001")
    assert r.status_code == 502
    assert "raise the Timeout" in r.json()["detail"]
