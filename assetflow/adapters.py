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

from . import assetexplorer_client as assetexplorer_client_mod
from . import assetexplorer_runner as assetexplorer_runner_mod
from . import client as client_mod
from . import db as db_mod
from . import runner as runner_mod
from . import solarwinds_client as solarwinds_client_mod
from . import solarwinds_runner as solarwinds_runner_mod
from . import tenable_sc_client as tenable_sc_client_mod
from . import tenable_sc_runner as tenable_sc_runner_mod
from . import tufin_client as tufin_client_mod
from . import tufin_runner as tufin_runner_mod
from . import vmware_client as vmware_client_mod
from . import vmware_runner as vmware_runner_mod
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
            self._client, query, limit=limit, time_range=time_range,
            device_scan_limit=tufin_runner_mod.resolve_device_scan(),  # None = whole estate
            watermark_store=store,
        )


class VMwareAdapter(Adapter):
    """VMware vCenter source: fetches full inventory — virtual machines
    (virtual servers), ESXi hosts (physical servers), clusters, datastores, and
    datacenters — over the vCenter REST API, enriched with vCenter Custom
    Attributes (prefixed ``custom.``) read via pyVmomi."""

    def connect(
        self,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_certs: bool = True,
        request_timeout: int = 60,
    ) -> dict:
        candidate = vmware_client_mod.build_client(
            host=host or "",
            username=username or "",
            password=password or "",
            port=port or 443,
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = vmware_client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def connect_form(self, form: dict) -> dict:
        return self.connect(
            host=(form.get("host") or form.get("url") or None),
            username=(form.get("username") or None),
            password=(form.get("password") or None),
            port=int(form.get("port") or 443),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 60)),
        )

    def try_auto_connect(self) -> bool:
        try:
            candidate = vmware_client_mod.build_client_from_env()
            info = vmware_client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def managed_env_keys(self) -> List[str]:
        return [
            "VC_HOSTNAME", "VC_USERNAME", "VC_PASSWORD",
            "VCENTER_PORT", "VCENTER_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        host = (form.get("host") or form.get("url") or "").strip()
        return {
            "VC_HOSTNAME": vmware_client_mod.clean_host(host),
            "VC_USERNAME": str(form.get("username") or ""),
            "VC_PASSWORD": str(form.get("password") or ""),
            "VCENTER_PORT": str(form.get("port") or 443),
            "VCENTER_VERIFY_CERTS": "true" if form.get("verify_certs", True) else "false",
        }

    def ping(self) -> dict:
        if self._client is None:
            raise vmware_client_mod.VMwareConfigError("adapter is not connected")
        info = vmware_client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise vmware_client_mod.VMwareConfigError("adapter is not connected")
        return vmware_runner_mod.run_query(
            self._client, query, limit=limit, time_range=time_range
        )


class SolarWindsAdapter(Adapter):
    """SolarWinds Orion source: fetches full, typed device inventory (routers,
    switches, firewalls, servers, …) with custom properties (prefixed
    ``custom.``) over the SWIS query API, plus NCM configuration posture — the
    current config per device, per-device config change history, and policy
    compliance — via SWQL."""

    def connect(
        self,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = solarwinds_client_mod.DEFAULT_PORT,
        verify_certs: bool = True,
        request_timeout: int = 120,
    ) -> dict:
        candidate = solarwinds_client_mod.build_client(
            host=host or "",
            username=username or "",
            password=password or "",
            port=port or solarwinds_client_mod.DEFAULT_PORT,
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = solarwinds_client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def connect_form(self, form: dict) -> dict:
        return self.connect(
            host=(form.get("host") or form.get("url") or None),
            username=(form.get("username") or None),
            password=(form.get("password") or None),
            port=int(form.get("port") or solarwinds_client_mod.DEFAULT_PORT),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 120)),
        )

    def try_auto_connect(self) -> bool:
        try:
            candidate = solarwinds_client_mod.build_client_from_env()
            info = solarwinds_client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def managed_env_keys(self) -> List[str]:
        return [
            "SWIS_HOSTNAME", "SWIS_USERNAME", "SWIS_PASSWORD",
            "SWIS_PORT", "SWIS_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        host = (form.get("host") or form.get("url") or "").strip()
        return {
            "SWIS_HOSTNAME": solarwinds_client_mod.clean_host(host),
            "SWIS_USERNAME": str(form.get("username") or ""),
            "SWIS_PASSWORD": str(form.get("password") or ""),
            "SWIS_PORT": str(form.get("port") or solarwinds_client_mod.DEFAULT_PORT),
            "SWIS_VERIFY_CERTS": "true" if form.get("verify_certs", True) else "false",
        }

    def ping(self) -> dict:
        if self._client is None:
            raise solarwinds_client_mod.SolarWindsConfigError("adapter is not connected")
        info = solarwinds_client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise solarwinds_client_mod.SolarWindsConfigError("adapter is not connected")
        # The config change-detail "since last check" mode reads/advances a
        # per-node watermark stored in the database (scoped to this adapter).
        store = db_mod.watermark_store(self.info.id)
        return solarwinds_runner_mod.run_query(
            self._client, query, limit=limit, time_range=time_range, watermark_store=store
        )


class TenableScAdapter(Adapter):
    """Tenable.sc (SecurityCenter) source: fetches the device inventory, aggregated
    security findings, installed software, users, asset lists (asset tags),
    alerts, and tickets (incidents) over the Tenable.sc REST API. Device and
    finding rows carry any unmapped Tenable field under a ``custom.`` prefix and
    each device is stamped with the asset-list tags it belongs to."""

    def connect(
        self,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        api_prefix: str = "",
        verify_certs: bool = True,
        request_timeout: int = 60,
    ) -> dict:
        candidate = tenable_sc_client_mod.build_client(
            host=host or "",
            username=username or "",
            password=password or "",
            access_key=access_key or "",
            secret_key=secret_key or "",
            api_prefix=api_prefix or "",
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = tenable_sc_client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def connect_form(self, form: dict) -> dict:
        return self.connect(
            host=(form.get("host") or form.get("url") or None),
            username=(form.get("username") or None),
            password=(form.get("password") or None),
            access_key=(form.get("access_key") or None),
            secret_key=(form.get("secret_key") or None),
            api_prefix=(form.get("base_path") or form.get("api_prefix") or ""),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 60)),
        )

    def try_auto_connect(self) -> bool:
        try:
            candidate = tenable_sc_client_mod.build_client_from_env()
            info = tenable_sc_client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def managed_env_keys(self) -> List[str]:
        return [
            "TENABLE_SC_HOST", "TENABLE_SC_USERNAME", "TENABLE_SC_PASSWORD",
            "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY",
            "TENABLE_SC_API_PREFIX", "TENABLE_SC_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        host = (form.get("host") or form.get("url") or "").strip()
        env: Dict[str, str] = {
            "TENABLE_SC_HOST": tenable_sc_client_mod.clean_host(host),
            "TENABLE_SC_VERIFY_CERTS": "true" if form.get("verify_certs", True) else "false",
        }
        # Persist whichever credential style was supplied.
        if form.get("access_key") and form.get("secret_key"):
            env["TENABLE_SC_ACCESS_KEY"] = str(form.get("access_key") or "")
            env["TENABLE_SC_SECRET_KEY"] = str(form.get("secret_key") or "")
        else:
            env["TENABLE_SC_USERNAME"] = str(form.get("username") or "")
            env["TENABLE_SC_PASSWORD"] = str(form.get("password") or "")
        prefix = (form.get("base_path") or form.get("api_prefix") or "").strip()
        if prefix:
            env["TENABLE_SC_API_PREFIX"] = prefix
        return env

    def ping(self) -> dict:
        if self._client is None:
            raise tenable_sc_client_mod.TenableScConfigError("adapter is not connected")
        info = tenable_sc_client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise tenable_sc_client_mod.TenableScConfigError("adapter is not connected")
        return tenable_sc_runner_mod.run_query(
            self._client, query, limit=limit, time_range=time_range
        )


class AssetExplorerAdapter(Adapter):
    """ManageEngine AssetExplorer source: fetches the full asset inventory —
    bucketed into its asset types (servers, workstations, routers, switches,
    firewalls, access points, printers, storage, UPS, …) — plus the CMDB
    configuration items, contracts, and purchase orders over the AssetExplorer v3
    REST API. Each asset carries its default fields and every custom (UDF) field
    under a ``custom.`` prefix."""

    def connect(
        self,
        *,
        host: Optional[str] = None,
        portal: str = "",
        access_token: str = "",
        refresh_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        api_key: str = "",
        accounts_url: str = "https://accounts.zoho.com",
        verify_certs: bool = True,
        request_timeout: int = 60,
    ) -> dict:
        candidate = assetexplorer_client_mod.build_client(
            host=host or "",
            portal=portal or "",
            access_token=access_token or "",
            refresh_token=refresh_token or "",
            client_id=client_id or "",
            client_secret=client_secret or "",
            api_key=api_key or "",
            accounts_url=accounts_url or "https://accounts.zoho.com",
            verify_certs=verify_certs,
            request_timeout=request_timeout,
        )
        info = assetexplorer_client_mod.ping(candidate)  # raises on failure
        self._client = candidate
        self._conn_info = info
        return info

    def connect_form(self, form: dict) -> dict:
        """Resolve the shared connection form into AssetExplorer credentials.

        AssetExplorer has no single username/password: the UI supplies the host,
        an optional portal (Cloud), and either an OAuth token (the ``password``
        field doubles as the access token, or the ``api_key`` field carries a
        refresh token / on-prem technician key) as interpreted below.
        """
        # The UI sends OAuth material and the on-prem key under dedicated keys when
        # present, and falls back to the shared password field for the token.
        access_token = (form.get("access_token") or "").strip()
        refresh_token = (form.get("refresh_token") or "").strip()
        api_key = (form.get("api_key") or "").strip()
        password = (form.get("password") or "").strip()
        # A bare token pasted into the password field is treated as an access token
        # unless client id/secret are also given (then it is the refresh token).
        client_id = (form.get("client_id") or "").strip()
        client_secret = (form.get("client_secret") or "").strip()
        if password and not (access_token or refresh_token or api_key):
            if client_id and client_secret:
                refresh_token = password
            else:
                access_token = password
        return self.connect(
            host=(form.get("host") or form.get("url") or None),
            portal=(form.get("portal") or form.get("base_path") or ""),
            access_token=access_token,
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            api_key=api_key,
            accounts_url=(form.get("accounts_url") or "https://accounts.zoho.com"),
            verify_certs=bool(form.get("verify_certs", True)),
            request_timeout=max(1, int(form.get("request_timeout") or 60)),
        )

    def try_auto_connect(self) -> bool:
        try:
            candidate = assetexplorer_client_mod.build_client_from_env()
            info = assetexplorer_client_mod.ping(candidate)
        except Exception:
            return False
        self._client = candidate
        self._conn_info = info
        return True

    def managed_env_keys(self) -> List[str]:
        return [
            "AE_HOST", "AE_PORTAL", "AE_ACCESS_TOKEN", "AE_REFRESH_TOKEN",
            "AE_CLIENT_ID", "AE_CLIENT_SECRET", "AE_API_KEY",
            "AE_ACCOUNTS_URL", "AE_VERIFY_CERTS",
        ]

    def env_for_form(self, form: dict) -> Dict[str, str]:
        host = (form.get("host") or form.get("url") or "").strip()
        cleaned_host = assetexplorer_client_mod.clean_host(host)
        # Preserve an explicit http:// scheme (on-prem often runs plain HTTP on a
        # custom port); https is the default and needs no prefix.
        if assetexplorer_client_mod.scheme_of(host) == "http" and cleaned_host:
            cleaned_host = "http://" + cleaned_host
        env: Dict[str, str] = {
            "AE_HOST": cleaned_host,
            "AE_VERIFY_CERTS": "true" if form.get("verify_certs", True) else "false",
        }
        portal = (form.get("portal") or form.get("base_path") or "").strip()
        if portal:
            env["AE_PORTAL"] = assetexplorer_client_mod.clean_portal(portal)
        # Persist whichever credential style was supplied.
        access_token = (form.get("access_token") or "").strip()
        refresh_token = (form.get("refresh_token") or "").strip()
        api_key = (form.get("api_key") or "").strip()
        password = (form.get("password") or "").strip()
        client_id = (form.get("client_id") or "").strip()
        client_secret = (form.get("client_secret") or "").strip()
        if password and not (access_token or refresh_token or api_key):
            if client_id and client_secret:
                refresh_token = password
            else:
                access_token = password
        if api_key:
            env["AE_API_KEY"] = api_key
        if access_token:
            env["AE_ACCESS_TOKEN"] = access_token
        if refresh_token:
            env["AE_REFRESH_TOKEN"] = refresh_token
        if client_id:
            env["AE_CLIENT_ID"] = client_id
        if client_secret:
            env["AE_CLIENT_SECRET"] = client_secret
        accounts_url = (form.get("accounts_url") or "").strip()
        if accounts_url:
            env["AE_ACCOUNTS_URL"] = accounts_url
        return env

    def ping(self) -> dict:
        if self._client is None:
            raise assetexplorer_client_mod.AssetExplorerConfigError(
                "adapter is not connected"
            )
        info = assetexplorer_client_mod.ping(self._client)
        self._conn_info = info
        return info

    def run(self, query: Query, limit=None, time_range=None) -> QueryResult:
        if self._client is None:
            raise assetexplorer_client_mod.AssetExplorerConfigError(
                "adapter is not connected"
            )
        return assetexplorer_runner_mod.run_query(
            self._client, query, limit=limit, time_range=time_range
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

    vmware_path = _find_registry("config/vmware_registry.yaml", "vmware_registry.yaml")
    if vmware_path:
        kinds["vmware"] = AdapterKind(
            kind="vmware",
            name="VMware vCenter",
            category="Virtualization / Infrastructure",
            description=(
                "VMware vCenter — full inventory of virtual machines (virtual "
                "servers), ESXi hosts (physical servers), clusters, datastores, "
                "and datacenters via the vSphere REST API, enriched with vCenter "
                "Custom Attributes (prefixed 'custom.') via pyVmomi."
            ),
            registry=load_registry(vmware_path),
            adapter_cls=VMwareAdapter,
        )

    solarwinds_path = _find_registry(
        "config/solarwinds_registry.yaml", "solarwinds_registry.yaml"
    )
    if solarwinds_path:
        kinds["solarwinds"] = AdapterKind(
            kind="solarwinds",
            name="SolarWinds Orion",
            category="Network Monitoring / NCM",
            description=(
                "SolarWinds Orion — full, typed device inventory (routers, "
                "switches, firewalls, servers, …) with custom properties "
                "(prefixed 'custom.') via the SWIS query API, plus NCM "
                "configuration posture: the current config per device, per-device "
                "config change history, and policy compliance."
            ),
            registry=load_registry(solarwinds_path),
            adapter_cls=SolarWindsAdapter,
        )

    tenable_sc_path = _find_registry(
        "config/tenable_sc_registry.yaml", "tenable_sc_registry.yaml"
    )
    if tenable_sc_path:
        kinds["tenable_sc"] = AdapterKind(
            kind="tenable_sc",
            name="Tenable.sc (SecurityCenter)",
            category="Vulnerability Management",
            description=(
                "Tenable.sc (SecurityCenter) — device inventory, aggregated "
                "security findings, installed software, users, asset lists (asset "
                "tags), alerts, and tickets (incidents) via the Tenable.sc REST "
                "API. Device and finding rows carry extra fields under 'custom.' "
                "and devices are stamped with their asset-list tags."
            ),
            registry=load_registry(tenable_sc_path),
            adapter_cls=TenableScAdapter,
        )

    assetexplorer_path = _find_registry(
        "config/assetexplorer_registry.yaml", "assetexplorer_registry.yaml"
    )
    if assetexplorer_path:
        kinds["assetexplorer"] = AdapterKind(
            kind="assetexplorer",
            name="ManageEngine AssetExplorer",
            category="IT Asset Management / CMDB",
            description=(
                "ManageEngine AssetExplorer — the full asset inventory bucketed "
                "into its asset types (servers, workstations, routers, switches, "
                "firewalls, access points, printers, storage, UPS, …) with all "
                "default and custom (UDF) fields (extra fields prefixed 'custom.'), "
                "plus the CMDB configuration items, contracts, and purchase orders "
                "via the AssetExplorer v3 REST API."
            ),
            registry=load_registry(assetexplorer_path),
            adapter_cls=AssetExplorerAdapter,
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
