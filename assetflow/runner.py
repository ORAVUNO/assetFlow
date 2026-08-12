"""Execute ES|QL queries and normalize the results."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from typing import Any, List, Optional

from elasticsearch import Elasticsearch

from .models import Query


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
) -> QueryResult:
    """Run a registry Query, with a clear error for placeholder entries."""
    if not query.is_runnable:
        raise ValueError(
            f"query {query.id} ({query.name}) has no ES|QL defined "
            f"(status={query.status.value}); nothing to run"
        )
    return run_esql(client, query.esql_query, limit=limit)
