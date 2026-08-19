"""Tests for the opt-in 'Remember on this machine' credential persistence (.env)."""

from pathlib import Path

from dotenv import dotenv_values
from fastapi.testclient import TestClient

from assetflow import adapters as adapters_mod
from assetflow import client as client_mod
from assetflow import credstore
from assetflow import webapp

REGISTRY = Path(__file__).resolve().parent.parent / "config" / "asset_intelligence_registry.yaml"


def test_credstore_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSETFLOW_ENV_FILE", str(tmp_path / ".env"))
    keys = ["TOS_HOSTNAME", "TOS_USERNAME", "TOS_PASSWORD"]
    assert credstore.has_saved(keys) is False
    credstore.save(keys, {"TOS_HOSTNAME": "h", "TOS_USERNAME": "u", "TOS_PASSWORD": "p"})
    assert credstore.has_saved(keys) is True
    assert dotenv_values(str(tmp_path / ".env"))["TOS_HOSTNAME"] == "h"
    credstore.forget(keys)
    assert credstore.has_saved(keys) is False


def test_tufin_env_for_form():
    a = adapters_mod.default_manager().get("tufin")
    env = a.env_for_form({"host": "https://securetrack.example.com/", "username": "u",
                          "password": "p", "verify_certs": False})
    assert env["TOS_HOSTNAME"] == "securetrack.example.com"
    assert env["TOS_PASSWORD"] == "p"
    assert env["TUFIN_VERIFY_CERTS"] == "false"


def test_es_env_for_form_url_and_auth_styles():
    a = adapters_mod.default_manager().get("elasticsearch")
    env = a.env_for_form({"host": "10.0.0.5", "port": "9243", "username": "u", "password": "p"})
    assert env["ELASTICSEARCH_URL"] == "https://10.0.0.5:9243"
    assert env["ELASTIC_USERNAME"] == "u" and env["ELASTIC_PASSWORD"] == "p"
    env2 = a.env_for_form({"host": "h", "api_key": "k"})
    assert env2["ELASTIC_API_KEY"] == "k"
    assert "ELASTIC_USERNAME" not in env2


def test_connect_remember_persists_per_connection(tmp_path, monkeypatch):
    # 'Remember' now persists per-connection credentials in the local database
    # (so each instance reconnects on restart), not in a shared .env file.
    from assetflow import db as db_mod

    monkeypatch.setattr(client_mod, "build_client", lambda **kw: object())
    monkeypatch.setattr(client_mod, "ping", lambda cl: {"cluster_name": "c", "version": "8.13"})
    c = TestClient(webapp.create_app(str(REGISTRY), db_url=f"sqlite:///{tmp_path}/t.db"))

    # No remember -> nothing persisted.
    r = c.post("/api/adapters/elasticsearch/connect",
               json={"host": "10.0.0.5", "port": "9243", "username": "u", "password": "p"})
    assert r.json()["ok"] is True and r.json()["saved"] is False
    assert c.get("/api/adapters/elasticsearch").json()["has_saved"] is False

    # Remember -> stored against this connection and reflected in the detail.
    r = c.post("/api/adapters/elasticsearch/connect",
               json={"host": "10.0.0.5", "port": "9243", "username": "u", "password": "p", "remember": True})
    assert r.json()["saved"] is True
    secrets = db_mod.get_connection_secrets("elasticsearch")
    assert secrets["host"] == "10.0.0.5" and secrets["username"] == "u"
    assert c.get("/api/adapters/elasticsearch").json()["has_saved"] is True

    # Forget clears it.
    assert c.request("DELETE", "/api/adapters/elasticsearch/saved-connection").json()["ok"] is True
    assert c.get("/api/adapters/elasticsearch").json()["has_saved"] is False
    assert db_mod.get_connection_secrets("elasticsearch") is None
