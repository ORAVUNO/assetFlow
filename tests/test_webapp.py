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
    assert len(d["queries"]) == 26
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
