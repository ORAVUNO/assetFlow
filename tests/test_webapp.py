"""Web API tests using FastAPI's TestClient with Elasticsearch mocked out."""

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


@pytest.fixture
def client(monkeypatch, tmp_path):
    # Isolate the on-disk cache into a temp dir.
    monkeypatch.chdir(tmp_path)
    # Never build/contact a real Elasticsearch.
    monkeypatch.setattr(client_mod, "build_client_from_env", lambda: object())
    monkeypatch.setattr(
        client_mod, "ping", lambda c: {"name": "n", "cluster_name": "test", "version": "8.13.0"}
    )
    monkeypatch.setattr(runner_mod, "run_query", lambda c, q, limit=None, time_range=None: FAKE_RESULT)
    webapp._state.update({"client": None, "registry": None})
    app = webapp.create_app(str(REGISTRY_PATH))
    return TestClient(app)


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "assetFlow" in r.text


def test_registry_endpoint(client):
    r = client.get("/api/registry")
    assert r.status_code == 200
    data = r.json()
    assert len(data["queries"]) == 17
    assert len(data["feeds"]) == 6


def test_connection_endpoint(client):
    r = client.get("/api/connection")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_run_then_cache_then_export(client):
    run = client.post("/api/run/AI001?limit=10")
    assert run.status_code == 200
    assert run.json()["row_count"] == 2

    cached = client.get("/api/cache/AI001")
    assert cached.status_code == 200
    assert cached.json()["query_id"] == "AI001"

    csv = client.get("/api/export/AI001.csv")
    assert csv.status_code == 200
    assert "host.name" in csv.text

    js = client.get("/api/export/AI001.json")
    assert js.status_code == 200
    assert js.json()[0]["host.name"] == "host-a"


def test_run_placeholder_rejected(client):
    r = client.post("/api/run/AI016")  # not_validated, empty ES|QL
    assert r.status_code == 422


def test_cache_missing_is_404(client):
    r = client.get("/api/cache/AI012")
    assert r.status_code == 404


def test_connect_success(client, monkeypatch):
    captured = {}

    def fake_build_client(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(client_mod, "build_client", fake_build_client)
    r = client.post(
        "/api/connect",
        json={"host": "10.0.0.5", "username": "elastic", "password": "pw", "verify_certs": False},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    # bare host was normalized to an https URL with the default port
    assert captured["url"] == "https://10.0.0.5:9200"
    assert captured["verify_certs"] is False


def test_connect_uses_separate_port_field(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(client_mod, "build_client", lambda **kw: captured.update(kw) or object())
    r = client.post(
        "/api/connect",
        json={"host": "kibana.example.com", "port": "9243", "username": "u", "password": "p"},
    )
    assert r.status_code == 200
    assert captured["url"] == "https://kibana.example.com:9243"


def test_connect_port_ignored_when_host_has_port(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(client_mod, "build_client", lambda **kw: captured.update(kw) or object())
    r = client.post(
        "/api/connect",
        json={"host": "es.example.com:9200", "port": "9243", "username": "u", "password": "p"},
    )
    assert r.status_code == 200
    # host already carried a port, so the separate field is ignored
    assert captured["url"] == "https://es.example.com:9200"


def test_connect_passes_timeout(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(client_mod, "build_client", lambda **kw: captured.update(kw) or object())
    r = client.post(
        "/api/connect",
        json={"host": "h", "username": "u", "password": "p", "request_timeout": 180},
    )
    assert r.status_code == 200
    assert captured["request_timeout"] == 180


def test_run_timeout_hint(client, monkeypatch):
    def boom(cl, q, limit=None, time_range=None):
        raise Exception("Connection timeout caused by: ReadTimeoutError")

    monkeypatch.setattr(runner_mod, "run_query", boom)
    r = client.post("/api/run/AI001")
    assert r.status_code == 502
    assert "raise the Timeout" in r.json()["detail"]


def test_connect_failure_reports_error(client, monkeypatch):
    def boom(cl):
        raise ValueError("auth failed")

    monkeypatch.setattr(client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(client_mod, "ping", boom)
    r = client.post("/api/connect", json={"host": "h", "username": "u", "password": "p"})
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "auth failed" in r.json()["error"]
