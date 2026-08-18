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
from . import db as db_mod
from . import runner as runner_mod
from . import tufin_client as tufin_client_mod
from . import tufin_runner as tufin_runner_mod
from .models import Query, Registry
from .registry import load_registry
from .runner import QueryResult


@dataclass
class AdapterInfo:
    id: str
    name: str
    category: str
    description: str
    kind: str  # e.g. "elasticsearch" / "tufin" — drives the UI's connection fields


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

    def connect_form(self, form: dict) -> dict:  # pragma: no cover - overridden
        """Connect using the web UI's raw connection form fields.

        Each adapter interprets the shared form (host, port, username, …) in its
        own terms and returns a connection-info dict (raising on failure).
        """
        raise NotImplementedError

    def try_auto_connect(self) -> bool:
        """Best-effort connect from environment variables at startup."""
        return False

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

    def connect_form(self, form: dict) -> dict:
        """Resolve the shared form into an Elasticsearch URL and connect.

        A bare host plus a port becomes ``host:port``; ``normalize_host`` then
        adds the scheme (and default 9200). Returns the cluster info plus the
        resolved URL.
        """
        target = (form.get("url") or form.get("host") or "").strip()
        port = (form.get("port") or "").strip()
        if target and port and "://" not in target and ":" not in target.split("/", 1)[0]:
            target = f"{target}:{port}"
        url = client_mod.normalize_host(target) if target else None
        info = self.connect(
            url=url,
            cloud_id=(form.get("cloud_id") or None),
            api_key=(form.get("api_key") or None),
            username=(form.get("username") or None),
            password=(form.get("password") or None),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 60)),
        )
        return {"resolved_url": url, **info}

    def try_auto_connect(self) -> bool:
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


class TufinAdapter(Adapter):
    """Tufin SecureTrack source: fetches configuration, revision, and change
    intelligence over the SecureTrack REST API."""

    def connect(
        self,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        base_path: str = "/securetrack/api",
        verify_certs: bool = True,
        request_timeout: int = 30,
    ) -> dict:
        candidate = tufin_client_mod.build_client(
            host=host or "",
            username=username or "",
            password=password or "",
            base_path=base_path or "/securetrack/api",
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = tufin_client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def connect_form(self, form: dict) -> dict:
        return self.connect(
            host=(form.get("host") or form.get("url") or None),
            username=(form.get("username") or None),
            password=(form.get("password") or None),
            base_path=(form.get("base_path") or "/securetrack/api"),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 30)),
        )

    def try_auto_connect(self) -> bool:
        try:
            candidate = tufin_client_mod.build_client_from_env()
            info = tufin_client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def ping(self) -> dict:
        if self._client is None:
            raise tufin_client_mod.TufinConfigError("adapter is not connected")
        info = tufin_client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise tufin_client_mod.TufinConfigError("adapter is not connected")
        # The change-detail "since last seen" mode reads/advances a per-device
        # watermark stored in the database (scoped to this adapter).
        store = db_mod.watermark_store(self.info.id)
        return tufin_runner_mod.run_query(
            self._client, query, limit=limit, time_range=time_range, watermark_store=store
        )


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


def _find_registry(*candidates: str) -> Optional[str]:
    """Return the first registry path that exists, near cwd or the repo root."""
    from pathlib import Path

    roots = [Path.cwd(), Path(__file__).resolve().parent.parent]
    for root in roots:
        for candidate in candidates:
            path = root / candidate
            if path.is_file():
                return str(path)
    return None


def default_manager(registry_path: Optional[str] = None) -> AdapterManager:
    """Build the adapter manager: the Elasticsearch adapter (ES|QL registry) and
    the Tufin adapter (SecureTrack REST registry), grouped by category."""
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

    adapters: List[Adapter] = [elasticsearch]

    tufin_path = _find_registry(
        "config/tufin_registry.yaml", "tufin_registry.yaml"
    )
    if tufin_path:
        tufin = TufinAdapter(
            AdapterInfo(
                id="tufin",
                name="Tufin SecureTrack",
                category="Network Security Policy",
                description=(
                    "Tufin SecureTrack — device inventory, per-revision change "
                    "history (who changed what, when), rulebase, network objects, "
                    "and policy hygiene via the SecureTrack REST API."
                ),
                kind="tufin",
            ),
            load_registry(tufin_path),
        )
        adapters.append(tufin)

    return AdapterManager(adapters)
