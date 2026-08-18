"""Adapter model: pluggable data sources, grouped by category.

An **adapter** is a source assetFlow can fetch assets from. Each adapter *kind*
(Elasticsearch, Tufin, …) is a template carrying its metadata and query
registry; you can create **multiple connection instances** of the same kind —
e.g. two Tufin servers or three Elasticsearch clusters — each with its own
user-chosen label and live connection. Instances are keyed by id, which is what
the database scopes each connection's data by; the unified inventory then
correlates assets across every instance.
"""

from __future__ import annotations

import re
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

    def managed_env_keys(self) -> List[str]:
        """Env var names this adapter reads/writes when a connection is saved."""
        return []

    def env_for_form(self, form: dict) -> Dict[str, str]:
        """Map a UI connection form to the env vars that reproduce it (for the
        opt-in 'Remember on this machine' save to .env)."""
        return {}

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

    def managed_env_keys(self) -> List[str]:
        return [
            "ELASTICSEARCH_URL", "ELASTIC_CLOUD_ID", "ELASTIC_API_KEY",
            "ELASTIC_USERNAME", "ELASTIC_PASSWORD", "ELASTIC_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        target = (form.get("url") or form.get("host") or "").strip()
        port = (form.get("port") or "").strip()
        if target and port and "://" not in target and ":" not in target.split("/", 1)[0]:
            target = f"{target}:{port}"
        env: Dict[str, str] = {}
        if form.get("cloud_id"):
            env["ELASTIC_CLOUD_ID"] = str(form["cloud_id"])
        elif target:
            env["ELASTICSEARCH_URL"] = client_mod.normalize_host(target)
        if form.get("api_key"):
            env["ELASTIC_API_KEY"] = str(form["api_key"])
        elif form.get("username"):
            env["ELASTIC_USERNAME"] = str(form.get("username") or "")
            env["ELASTIC_PASSWORD"] = str(form.get("password") or "")
        env["ELASTIC_VERIFY_CERTS"] = "true" if form.get("verify_certs", True) else "false"
        return env

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

    def managed_env_keys(self) -> List[str]:
        return [
            "TOS_HOSTNAME", "TOS_USERNAME", "TOS_PASSWORD",
            "TUFIN_BASE_PATH", "TUFIN_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        host = (form.get("host") or form.get("url") or "").strip()
        return {
            "TOS_HOSTNAME": tufin_client_mod.clean_host(host),
            "TOS_USERNAME": str(form.get("username") or ""),
            "TOS_PASSWORD": str(form.get("password") or ""),
            "TUFIN_BASE_PATH": str(form.get("base_path") or "/securetrack/api"),
            "TUFIN_VERIFY_CERTS": "true" if form.get("verify_certs", True) else "false",
        }

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


@dataclass
class AdapterKind:
    """A *type* of data source (Elasticsearch, Tufin, …) — the template from
    which connection instances are made. Its registry is shared by every
    instance of the kind; each instance carries its own label and connection."""

    kind: str          # machine id, e.g. "elasticsearch"
    name: str          # human name, e.g. "Elasticsearch"
    category: str
    description: str
    registry: Registry
    adapter_cls: type  # Adapter subclass to instantiate


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text).strip().lower()).strip("-")
    return s or "connection"


class AdapterManager:
    """Holds the available adapter *kinds* and the live *instances* (connections).

    Multiple instances of the same kind can coexist — e.g. two Tufin servers —
    each with its own id, label, and connection. Instances are keyed by id; the
    id is what the database scopes fetched data by.
    """

    def __init__(self, kinds: Optional[Dict[str, AdapterKind]] = None):
        self._kinds: Dict[str, AdapterKind] = dict(kinds or {})
        self._by_id: Dict[str, Adapter] = {}

    # -- kinds --------------------------------------------------------------

    def kinds(self) -> List[AdapterKind]:
        return list(self._kinds.values())

    def get_kind(self, kind_id: str) -> AdapterKind:
        if kind_id not in self._kinds:
            raise KeyError(f"no adapter kind {kind_id!r}")
        return self._kinds[kind_id]

    # -- instances ----------------------------------------------------------

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

    def unique_label(self, label: str, exclude: Optional[str] = None) -> str:
        """Return ``label``, suffixed if another instance already uses it, so
        connection labels stay distinct (they key the unified-inventory columns)."""
        label = (label or "").strip() or "Connection"
        existing = {a.info.name for a in self._by_id.values() if a.info.id != exclude}
        if label not in existing:
            return label
        n = 2
        while f"{label} ({n})" in existing:
            n += 1
        return f"{label} ({n})"

    def add_instance(
        self, kind_id: str, label: str, instance_id: Optional[str] = None
    ) -> Adapter:
        kind = self.get_kind(kind_id)
        label = self.unique_label(label or kind.name)
        if instance_id is None:
            base = _slugify(label) or kind_id
            instance_id, n = base, 2
            while instance_id in self._by_id:
                instance_id = f"{base}-{n}"
                n += 1
        info = AdapterInfo(
            id=instance_id,
            name=label,
            category=kind.category,
            description=kind.description,
            kind=kind.kind,
        )
        adapter = kind.adapter_cls(info, kind.registry)
        self._by_id[instance_id] = adapter
        return adapter

    def rename(self, adapter_id: str, label: str) -> Adapter:
        a = self.get(adapter_id)
        a.info.name = self.unique_label(label, exclude=adapter_id)
        return a

    def remove(self, adapter_id: str) -> None:
        self._by_id.pop(adapter_id, None)


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


def available_kinds(registry_path: Optional[str] = None) -> Dict[str, AdapterKind]:
    """Build the adapter kinds available on this machine: Elasticsearch (its
    ES|QL registry) and — when its registry is present — Tufin SecureTrack."""
    kinds: Dict[str, AdapterKind] = {
        "elasticsearch": AdapterKind(
            kind="elasticsearch",
            name="Elasticsearch",
            category="SIEM / Log Analytics",
            description=(
                "Elastic Security / logs-* — identity, service, application, and "
                "database asset intelligence via ES|QL."
            ),
            registry=load_registry(registry_path),
            adapter_cls=ElasticsearchAdapter,
        )
    }

    tufin_path = _find_registry("config/tufin_registry.yaml", "tufin_registry.yaml")
    if tufin_path:
        kinds["tufin"] = AdapterKind(
            kind="tufin",
            name="Tufin SecureTrack",
            category="Network Security Policy",
            description=(
                "Tufin SecureTrack — device inventory, per-revision change "
                "history (who changed what, when), rulebase, network objects, "
                "and policy hygiene via the SecureTrack REST API."
            ),
            registry=load_registry(tufin_path),
            adapter_cls=TufinAdapter,
        )
    return kinds


def default_manager(registry_path: Optional[str] = None) -> AdapterManager:
    """A manager seeded with one default instance per available kind (instance
    id == kind). This is the in-memory default used outside the web app; the web
    app persists instances in the database instead (see ``webapp.create_app``)."""
    kinds = available_kinds(registry_path)
    manager = AdapterManager(kinds)
    for kind in kinds.values():
        manager.add_instance(kind.kind, kind.name, instance_id=kind.kind)
    return manager
