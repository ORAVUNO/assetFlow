"""Adapter model: pluggable data sources, grouped by category.

An **adapter** is a source assetFlow can fetch assets from. Elasticsearch is
the first one; more (cloud, network, endpoint, CMDB, …) will follow. Each
adapter carries its own metadata, its own query registry, and its own live
connection. The UI lists adapters by category and opens one panel per adapter;
merging data across adapters comes later and builds on this seam.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from . import client as client_mod
from . import runner as runner_mod
from .models import Query, Registry
from .registry import load_registry
from .runner import QueryResult


@dataclass
class AdapterInfo:
    id: str
    name: str
    category: str
    description: str
    kind: str  # e.g. "elasticsearch" — drives which connection fields the UI shows


class Adapter:
    """Base class for a data-source adapter."""

    def __init__(self, info: AdapterInfo, registry: Registry):
        self.info = info
        self.registry = registry
        self._client = None
        self._conn_info: Optional[dict] = None

    @property
    def connected(self) -> bool:
        return self._client is not None

    @property
    def conn_info(self) -> Optional[dict]:
        return self._conn_info

    def connect(self, **cfg) -> dict:  # pragma: no cover - overridden
        raise NotImplementedError

    def ping(self) -> dict:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:  # pragma: no cover
        raise NotImplementedError


class ElasticsearchAdapter(Adapter):
    """Elasticsearch source: runs the ES|QL registry against a live cluster."""

    def connect(
        self,
        *,
        url: Optional[str] = None,
        cloud_id: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_certs: bool = True,
        request_timeout: int = 60,
    ) -> dict:
        candidate = client_mod.build_client(
            url=url,
            cloud_id=cloud_id,
            api_key=api_key,
            username=username,
            password=password,
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def try_connect_from_env(self) -> bool:
        """Best-effort auto-connect from environment variables at startup."""
        try:
            candidate = client_mod.build_client_from_env()
            info = client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def ping(self) -> dict:
        if self._client is None:
            raise client_mod.ConnectionConfigError("adapter is not connected")
        info = client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise client_mod.ConnectionConfigError("adapter is not connected")
        return runner_mod.run_query(self._client, query, limit=limit, time_range=time_range)


class AdapterManager:
    def __init__(self, adapters: List[Adapter]):
        self._by_id: Dict[str, Adapter] = {a.info.id: a for a in adapters}

    def list(self) -> List[Adapter]:
        return list(self._by_id.values())

    def get(self, adapter_id: str) -> Adapter:
        if adapter_id not in self._by_id:
            raise KeyError(f"no adapter with id {adapter_id!r}")
        return self._by_id[adapter_id]

    def by_category(self) -> Dict[str, List[Adapter]]:
        cats: Dict[str, List[Adapter]] = {}
        for a in self._by_id.values():
            cats.setdefault(a.info.category, []).append(a)
        return cats


def default_manager(registry_path: Optional[str] = None) -> AdapterManager:
    """Build the adapter manager. Currently a single Elasticsearch adapter
    backed by the shipped ES|QL registry."""
    reg = load_registry(registry_path)
    elasticsearch = ElasticsearchAdapter(
        AdapterInfo(
            id="elasticsearch",
            name="Elasticsearch",
            category="SIEM / Log Analytics",
            description=(
                "Elastic Security / logs-* — identity, service, application, and "
                "database asset intelligence via ES|QL."
            ),
            kind="elasticsearch",
        ),
        reg,
    )
    return AdapterManager([elasticsearch])
