"""Tests for result normalization and the query runner (no live ES needed)."""

import pytest

from assetflow.models import Query, Status
from assetflow.runner import QueryResult, apply_time_range, run_esql, run_query


class FakeEsql:
    def __init__(self, body):
        self._body = body
        self.last_query = None

    def query(self, query):
        self.last_query = query
        return self._body


class FakeClient:
    def __init__(self, body):
        self.esql = FakeEsql(body)


SAMPLE_BODY = {
    "columns": [{"name": "host.name", "type": "keyword"}, {"name": "LoginCount", "type": "long"}],
    "values": [["host-a", 5], ["host-b", 2]],
}


def test_result_normalization():
    r = QueryResult(columns=SAMPLE_BODY["columns"], rows=SAMPLE_BODY["values"])
    assert r.column_names == ["host.name", "LoginCount"]
    assert r.row_count == 2
    assert r.to_dicts()[0] == {"host.name": "host-a", "LoginCount": 5}
    assert "host.name,LoginCount" in r.to_csv()
    assert '"host.name": "host-a"' in r.to_json()


def test_run_esql_passes_query_and_limit():
    client = FakeClient(SAMPLE_BODY)
    result = run_esql(client, "FROM logs-*", limit=10)
    assert result.row_count == 2
    assert client.esql.last_query.endswith("| LIMIT 10")


def test_run_esql_rejects_empty():
    client = FakeClient(SAMPLE_BODY)
    with pytest.raises(ValueError):
        run_esql(client, "   ")


def test_run_query_rejects_placeholder():
    client = FakeClient(SAMPLE_BODY)
    placeholder = Query(
        id="AI999",
        category="Application Discovery",
        name="Placeholder",
        status=Status.not_validated,
        purpose="x",
        esql_query="",
    )
    with pytest.raises(ValueError, match="no ES|QL"):
        run_query(client, placeholder)


def test_apply_time_range_inserts_after_from():
    esql = 'FROM logs-*\n| WHERE user.name IS NOT NULL\n| STATS c = COUNT() BY host.name'
    out = apply_time_range(esql, "7d")
    lines = out.splitlines()
    assert lines[0].startswith("FROM")
    assert lines[1] == "| WHERE @timestamp >= NOW() - 7 days"
    assert "| WHERE user.name IS NOT NULL" in out


def test_apply_time_range_noop_for_all():
    esql = "FROM logs-*\n| STATS c = COUNT()"
    assert apply_time_range(esql, "all") == esql
    assert apply_time_range(esql, None) == esql
    assert apply_time_range(esql, "") == esql


def test_run_query_applies_range():
    client = FakeClient(SAMPLE_BODY)
    q = Query(id="AI001", category="Identity Intelligence", name="x", status=Status.validated,
              purpose="x", esql_query="FROM logs-*\n| STATS c = COUNT()", validated=True)
    run_query(client, q, time_range="24h")
    assert "NOW() - 24 hours" in client.esql.last_query


def test_run_query_runs_real_query():
    client = FakeClient(SAMPLE_BODY)
    q = Query(
        id="AI001",
        category="Identity Intelligence",
        name="User Device Mapping",
        status=Status.validated,
        purpose="x",
        esql_query="FROM logs-*",
        validated=True,
    )
    result = run_query(client, q)
    assert result.row_count == 2
