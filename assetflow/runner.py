"""Execute ES|QL queries and normalize the results."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from typing import Any, List, Optional

from elasticsearch import Elasticsearch

from .models import Query


# Time-range tokens (from the UI) mapped to ES|QL timespan literals.
RANGE_INTERVALS = {
    "24h": "24 hours",
    "7d": "7 days",
    "30d": "30 days",
    "90d": "90 days",
}


def apply_time_range(esql: str, time_range: Optional[str]) -> str:
    """Inject a ``@timestamp`` lower-bound filter right after the FROM command.

    ``time_range`` is a token like "7d"; unknown/empty tokens (e.g. "all")
    leave the query unchanged. The filter is added as its own WHERE command
    immediately after FROM so Elasticsearch prunes early.
    """
    interval = RANGE_INTERVALS.get((time_range or "").lower())
    if not interval:
        return esql
    clause = f"| WHERE @timestamp >= NOW() - {interval}"
    lines = esql.splitlines()
    out: List[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.strip().upper().startswith("FROM "):
            out.append(clause)
            inserted = True
    return "\n".join(out) if inserted else esql


@dataclass
class QueryResult:
    """Normalized ES|QL result: column metadata plus row values."""

    columns: List[dict]
    rows: List[List[Any]]

    @property
    def column_names(self) -> List[str]:
        return [c.get("name", "") for c in self.columns]

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def to_dicts(self) -> List[dict]:
        names = self.column_names
        return [dict(zip(names, row)) for row in self.rows]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dicts(), indent=indent, default=str)

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(self.column_names)
        writer.writerows(self.rows)
        return buf.getvalue()


def run_esql(
    client: Elasticsearch,
    esql: str,
    limit: Optional[int] = None,
) -> QueryResult:
    """Run a raw ES|QL string and return a normalized result.

    A ``limit`` appends a trailing ``| LIMIT n`` processing command, which
    caps the rows returned regardless of any earlier SORT.
    """
    query = esql.strip()
    if not query:
        raise ValueError("cannot run an empty ES|QL query")
    if limit is not None:
        query = f"{query}\n| LIMIT {int(limit)}"

    resp = client.esql.query(query=query)
    body = getattr(resp, "body", resp)
    return QueryResult(
        columns=list(body.get("columns", [])),
        rows=list(body.get("values", [])),
    )


def run_query(
    client: Elasticsearch,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> QueryResult:
    """Run a registry Query, with a clear error for placeholder entries.

    ``time_range`` optionally bounds the query to recent data (see
    ``apply_time_range``) — useful for heavy all-index aggregations.
    """
    if not query.is_runnable:
        raise ValueError(
            f"query {query.id} ({query.name}) has no ES|QL defined "
            f"(status={query.status.value}); nothing to run"
        )
    esql = apply_time_range(query.esql_query, time_range)
    return run_esql(client, esql, limit=limit)
