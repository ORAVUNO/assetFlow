"""Pydantic models for the Asset Intelligence registry.

These models mirror the structure of ``config/asset_intelligence_registry.yaml``
and validate it on load: every query must carry the required fields, its status
must be one of the supported values, its category must be declared in the
metadata, and every feed must reference queries that actually exist.
"""

from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, Field, model_validator


class Status(str, Enum):
    """Validation status of a query against a live environment."""

    validated = "validated"
    partially_validated = "partially_validated"
    investigation_required = "investigation_required"
    not_validated = "not_validated"


class Metadata(BaseModel):
    version: int
    description: str = ""
    query_language: str = "ES|QL"
    status_values: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)


class Query(BaseModel):
    id: str
    category: str
    name: str
    status: Status
    purpose: str
    esql_query: str = ""
    validated: bool = False
    notes: str = ""
    expected_output_fields: List[str] = Field(default_factory=list)
    recommended_refresh_frequency: str = ""

    @property
    def is_runnable(self) -> bool:
        """True when the query has a non-empty ES|QL body to execute."""
        return bool(self.esql_query.strip())


class Feed(BaseModel):
    id: str
    name: str
    category: str
    description: str = ""
    query_ids: List[str] = Field(default_factory=list)
    recommended_refresh_frequency: str = ""


class Registry(BaseModel):
    metadata: Metadata
    feeds: List[Feed] = Field(default_factory=list)
    queries: List[Query]

    # -- integrity checks ---------------------------------------------------

    @model_validator(mode="after")
    def _check_integrity(self) -> "Registry":
        ids = [q.id for q in self.queries]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate query ids: {sorted(dupes)}")

        id_set = set(ids)
        categories = set(self.metadata.categories)
        if categories:
            for q in self.queries:
                if q.category not in categories:
                    raise ValueError(
                        f"query {q.id} has category {q.category!r} "
                        f"not declared in metadata.categories"
                    )

        for feed in self.feeds:
            for qid in feed.query_ids:
                if qid not in id_set:
                    raise ValueError(
                        f"feed {feed.id} references unknown query {qid!r}"
                    )
        return self

    # -- lookups ------------------------------------------------------------

    def get_query(self, query_id: str) -> Query:
        for q in self.queries:
            if q.id == query_id:
                return q
        raise KeyError(f"no query with id {query_id!r}")

    def get_feed(self, feed_id: str) -> Feed:
        for f in self.feeds:
            if f.id == feed_id:
                return f
        raise KeyError(f"no feed with id {feed_id!r}")

    def queries_for_feed(self, feed_id: str) -> List[Query]:
        feed = self.get_feed(feed_id)
        return [self.get_query(qid) for qid in feed.query_ids]
