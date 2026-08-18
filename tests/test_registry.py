"""Tests for loading and validating the shipped registry."""

from pathlib import Path

import pytest

from assetflow.models import Registry, Status
from assetflow.registry import load_registry

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "config" / "asset_intelligence_registry.yaml"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(REGISTRY_PATH)


def test_registry_loads(registry: Registry):
    assert registry.metadata.version >= 1
    assert len(registry.queries) == 25
    assert len(registry.feeds) == 8


def test_all_query_ids_unique(registry: Registry):
    ids = [q.id for q in registry.queries]
    assert len(ids) == len(set(ids))


def test_categories_declared(registry: Registry):
    declared = set(registry.metadata.categories)
    for q in registry.queries:
        assert q.category in declared


def test_validated_flag_matches_status(registry: Registry):
    for q in registry.queries:
        assert q.validated == (q.status is Status.validated)


def test_feeds_reference_real_queries(registry: Registry):
    ids = {q.id for q in registry.queries}
    covered = set()
    for feed in registry.feeds:
        for qid in feed.query_ids:
            assert qid in ids
            covered.add(qid)
    # every query belongs to exactly one feed
    assert covered == ids


def test_validated_queries_are_runnable(registry: Registry):
    for q in registry.queries:
        if q.status is Status.validated:
            assert q.is_runnable, f"{q.id} is validated but has no ES|QL"


def test_runnable_flag_matches_esql_presence(registry: Registry):
    # Every shipped ES query now carries an ES|QL body, so all are runnable;
    # a query is runnable iff its esql_query is non-empty.
    for q in registry.queries:
        assert q.is_runnable == bool(q.esql_query.strip())
    assert all(q.is_runnable for q in registry.queries)


def test_lookup_helpers(registry: Registry):
    assert registry.get_query("AI001").name == "User Device Mapping"
    feed = registry.get_feed("FEED-IDENTITY")
    assert "AI001" in feed.query_ids
    assert registry.queries_for_feed("FEED-USER-MGMT")[0].id == "AI002"
