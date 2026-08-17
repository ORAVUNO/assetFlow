"""Tests for bundle export builders and db.latest_all."""

import io
import json
import zipfile

from assetflow import db, export
from assetflow.models import Query, Status
from assetflow.runner import QueryResult


def _q(qid):
    return Query(id=qid, category="Identity Intelligence", name=qid + " name",
                 status=Status.validated, purpose="x", esql_query="FROM logs-*", validated=True)


def _result(rows):
    return QueryResult(columns=[{"name": "host.name"}, {"name": "n"}], rows=rows)


def test_latest_all_scoping(tmp_path):
    db.init_engine(f"sqlite:///{tmp_path}/t.db")
    db.save_fetch("elasticsearch", _q("AI001"), _result([["a", 1]]), 10, None)
    db.save_fetch("elasticsearch", _q("AI002"), _result([["b", 2]]), 10, None)
    db.save_fetch("other", _q("X1"), _result([["c", 3]]), 10, None)

    all_recs = db.latest_all()
    assert {r["query_id"] for r in all_recs} == {"AI001", "AI002", "X1"}
    es_recs = db.latest_all("elasticsearch")
    assert {r["query_id"] for r in es_recs} == {"AI001", "AI002"}


def test_build_json_bundle():
    info = {"id": "elasticsearch", "name": "Elasticsearch", "category": "SIEM"}
    recs = [db_record("AI001", [["a", 1], ["b", 2]])]
    out = json.loads(export.build_json("platform", [(info, recs)]))
    assert out["scope"] == "platform"
    ad = out["adapters"][0]
    assert ad["id"] == "elasticsearch" and ad["query_count"] == 1
    assert ad["queries"][0]["rows"] == [["a", 1], ["b", 2]]


def test_build_zip_bundle():
    info = {"id": "elasticsearch", "name": "Elasticsearch", "category": "SIEM"}
    recs = [db_record("AI001", [["a", 1]]), db_record("AI002", [["b", 2]])]
    data = export.build_zip("adapter:elasticsearch", [(info, recs)])
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = set(zf.namelist())
    assert "manifest.json" in names
    assert "elasticsearch/AI001.csv" in names
    assert "elasticsearch/AI002.csv" in names
    assert "host.name" in zf.read("elasticsearch/AI001.csv").decode()
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["scope"] == "adapter:elasticsearch"


def db_record(qid, rows):
    return {
        "query_id": qid, "name": qid, "status": "validated", "ran_at": "2026-01-01T00:00:00Z",
        "limit": 10, "time_range": None, "row_count": len(rows),
        "columns": [{"name": "host.name"}, {"name": "n"}], "rows": rows,
    }
