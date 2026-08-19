"""VMware vCenter connection, built from a form or environment.

This is the VMware analogue of ``client.py`` / ``tufin_client.py``. vCenter
exposes two complementary interfaces, and this client speaks both:

* the **vCenter REST API** (vSphere Automation API) rooted at::

      https://<vcenter_host>/api/

  — session-authenticated, used for the standard VM / host / cluster /
  datastore inventory. This is the stdlib-only path (urllib, or ``requests``
  when installed), so the adapter has no hard third-party dependency.

* the **vCenter SOAP SDK** through **pyVmomi**, used *only* for vCenter Custom
  Attributes (custom fields), which the REST inventory calls do not return.
  pyVmomi is an **optional** dependency: when it is not installed the standard
  inventory still works and custom fields are simply skipped (with a clear
  note), exactly as the integration note describes.

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    VC_HOSTNAME / VCENTER_HOST     the vCenter host or IP
    VC_USERNAME / VCENTER_USERNAME a vCenter read-only user (e.g. an SSO user)
    VC_PASSWORD / VCENTER_PASSWORD that user's password

Optional:
    VCENTER_PORT             HTTPS port (default 443)
    VCENTER_VERIFY_CERTS     "false" to disable TLS verification (lab only)
    VCENTER_REQUEST_TIMEOUT  seconds (default 60)

Only the connection/session primitives live here; ``vmware_runner.py`` turns
registry resources into endpoint calls and normalizes the responses.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# The REST client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class VMwareConfigError(RuntimeError):
    """Raised when required vCenter connection/credential settings are missing."""


def _first_env(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _as_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in ("false", "0", "no", "off")


def clean_host(host: str) -> str:
    """Strip scheme, whitespace, and trailing slash from a host/URL."""
    host = (host or "").strip().rstrip("/")
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
    # Drop any path/port the user may have pasted after the host.
    host = host.split("/", 1)[0]
    return host


def pyvmomi_available() -> bool:
    """True when pyVmomi is importable (custom fields require it)."""
    try:  # pragma: no cover - import availability is environment dependent
        import pyVim.connect  # noqa: F401
        import pyVmomi  # noqa: F401
    except Exception:
        return False
    return True


class VMwareClient:
    """Minimal vCenter client: REST session for inventory, pyVmomi for custom
    fields.

    The REST session token is fetched lazily on the first ``get`` (or eagerly by
    ``ping``). The pyVmomi SOAP connection is established lazily the first time
    custom fields are requested and cached for the client's lifetime.
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_certs: bool = True,
        request_timeout: int = 60,
    ):
        host = clean_host(host)
        if not host:
            raise VMwareConfigError(
                "no vCenter host — provide the vCenter hostname or IP"
            )
        if not (username and password):
            raise VMwareConfigError(
                "no credentials — provide a vCenter username and password"
            )
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 443)
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout
        self._session_id: Optional[str] = None
        self._si = None  # pyVmomi ServiceInstance (lazy)
        self._content = None  # pyVmomi ServiceInstanceContent (lazy)

    # -- REST ---------------------------------------------------------------

    @property
    def base_url(self) -> str:
        suffix = "" if self.port in (443, None) else f":{self.port}"
        return f"https://{self.host}{suffix}"

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        return None if self.verify_certs else ssl._create_unverified_context()

    def _http(self, url: str, *, method: str, headers: dict) -> Any:
        """Perform an HTTP request and return the parsed JSON body (or None)."""
        if requests is not None:
            resp = requests.request(
                method,
                url,
                headers=headers,
                verify=self.verify_certs,
                timeout=self.request_timeout,
            )
            resp.raise_for_status()
            text = resp.text
            return json.loads(text) if text else None

        request = Request(url, headers=headers, method=method)
        context = self._ssl_context()
        with urlopen(request, timeout=self.request_timeout, context=context) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else None

    def login(self) -> str:
        """Create a vCenter REST session and cache its token.

        POST /api/session with HTTP Basic auth returns the session id as a bare
        JSON string; it is sent on subsequent calls as ``vmware-api-session-id``.
        """
        token = base64.b64encode(
            f"{self.username}:{self.password}".encode("utf-8")
        ).decode("ascii")
        url = f"{self.base_url}/api/session"
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        body = self._http(url, method="POST", headers=headers)
        # /api/session returns the session id as a JSON string; the legacy
        # /rest/com/vmware/cis/session wraps it as {"value": "..."}.
        if isinstance(body, dict):
            body = body.get("value", "")
        session_id = str(body or "").strip().strip('"')
        if not session_id:
            raise VMwareConfigError(
                "vCenter did not return a session id — check credentials and URL"
            )
        self._session_id = session_id
        return session_id

    def get(self, path: str) -> Any:
        """GET a vCenter REST resource and return the parsed JSON body.

        Logs in on demand, and retries once after a fresh login if the session
        has expired (HTTP 401). REST responses come back either raw (``/api``)
        or wrapped as ``{"value": …}`` (legacy ``/rest``); callers unwrap.
        """
        if self._session_id is None:
            self.login()
        url = f"{self.base_url}/api/{path.lstrip('/')}"

        def _do() -> Any:
            headers = {
                "vmware-api-session-id": self._session_id or "",
                "Accept": "application/json",
            }
            return self._http(url, method="GET", headers=headers)

        try:
            return _do()
        except HTTPError as exc:  # pragma: no cover - network dependent
            if exc.code == 401:
                self.login()
                return _do()
            raise
        except Exception as exc:  # pragma: no cover - network dependent
            # ``requests`` raises HTTPError subclasses with a ``response``.
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 401:
                self.login()
                return _do()
            raise

    # -- pyVmomi (custom fields) -------------------------------------------

    def _soap_content(self):
        """Return a cached pyVmomi ServiceInstanceContent, connecting if needed.

        Raises ``VMwareConfigError`` when pyVmomi is not installed so callers
        can surface actionable guidance for the (optional) custom-fields path.
        """
        if self._content is not None:
            return self._content
        try:  # pragma: no cover - import availability is environment dependent
            from pyVim.connect import SmartConnect
        except Exception as exc:  # pragma: no cover
            raise VMwareConfigError(
                "pyVmomi is not installed — vCenter Custom Attributes need the "
                "pyVmomi SOAP SDK. Install it (pip install pyvmomi) or, offline, "
                "from a local wheel; standard inventory works without it."
            ) from exc
        context = self._ssl_context() or ssl.create_default_context()
        si = SmartConnect(
            host=self.host,
            user=self.username,
            pwd=self.password,
            port=self.port,
            sslContext=context,
        )
        self._si = si
        self._content = si.RetrieveContent()
        return self._content

    def custom_field_defs(self) -> List[Dict[str, Any]]:
        """List vCenter Custom Attribute definitions via pyVmomi.

        Returns one dict per field: ``key`` (numeric), ``name``, and
        ``object_type`` (the managed-object type the field applies to, e.g.
        VirtualMachine / HostSystem / '' for global).
        """
        content = self._soap_content()  # pragma: no cover - needs pyVmomi/live
        defs: List[Dict[str, Any]] = []
        for field_def in getattr(content.customFieldsManager, "field", None) or []:
            mo_type = getattr(field_def, "managedObjectType", None)
            defs.append(
                {
                    "key": field_def.key,
                    "name": field_def.name or "",
                    "object_type": getattr(mo_type, "__name__", "") if mo_type else "",
                }
            )
        return defs

    def custom_values(
        self, only: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, str]]:
        """Map each managed object's moid to its custom-field name→value dict.

        Uses pyVmomi to read Custom Attributes off every VirtualMachine and
        HostSystem. ``only`` optionally restricts to a set of field names (all
        fields when empty/None). The moid (``_moId``, e.g. ``vm-123`` /
        ``host-45``) matches the REST object id, which is how custom values are
        joined onto the REST inventory rows.
        """
        # pragma: no cover - exercised only against a live vCenter with pyVmomi
        from pyVmomi import vim  # type: ignore

        content = self._soap_content()
        names_by_key: Dict[int, str] = {}
        wanted = set(only or [])
        for field_def in getattr(content.customFieldsManager, "field", None) or []:
            name = field_def.name or ""
            if wanted and name not in wanted:
                continue
            names_by_key[field_def.key] = name

        object_types = [vim.VirtualMachine, vim.HostSystem]
        view = content.viewManager.CreateContainerView(
            content.rootFolder, object_types, True
        )
        values_by_moid: Dict[str, Dict[str, str]] = {}
        try:
            for obj in view.view:
                values: Dict[str, str] = {}
                for custom_value in getattr(obj, "customValue", None) or []:
                    field_name = names_by_key.get(custom_value.key)
                    if field_name:
                        values[field_name] = custom_value.value or ""
                if values:
                    values_by_moid[obj._moId] = values
        finally:
            try:
                view.Destroy()
            except Exception:
                pass
        return values_by_moid

    def host_hardware(self) -> Dict[str, Dict[str, str]]:
        """Map each ESXi host's moid to physical-hardware detail via pyVmomi.

        The REST Automation API is thin on host hardware, so these physical
        attributes (vendor, model, CPU, memory, ESXi build, parent cluster) come
        from the SOAP ``HostSystem.summary``. Returns ``{}`` when pyVmomi is
        unavailable so host inventory degrades to the REST-only fields.
        """
        # pragma: no cover - exercised only against a live vCenter with pyVmomi
        from pyVmomi import vim  # type: ignore

        content = self._soap_content()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        out: Dict[str, Dict[str, str]] = {}
        try:
            for host in view.view:
                summary = getattr(host, "summary", None)
                hw = getattr(summary, "hardware", None)
                product = getattr(getattr(summary, "config", None), "product", None)
                parent = getattr(host, "parent", None)
                mem_bytes = getattr(hw, "memorySize", 0) or 0
                out[host._moId] = {
                    "vendor": getattr(hw, "vendor", "") or "",
                    "model": getattr(hw, "model", "") or "",
                    "cpu_model": getattr(hw, "cpuModel", "") or "",
                    "cpu_packages": str(getattr(hw, "numCpuPkgs", "") or ""),
                    "cpu_cores": str(getattr(hw, "numCpuCores", "") or ""),
                    "cpu_threads": str(getattr(hw, "numCpuThreads", "") or ""),
                    "memory_gib": str(round(mem_bytes / (1024 ** 3), 1)) if mem_bytes else "",
                    "version": getattr(product, "version", "") or "",
                    "build": getattr(product, "build", "") or "",
                    "cluster": getattr(parent, "name", "") or "",
                }
        finally:
            try:
                view.Destroy()
            except Exception:
                pass
        return out

    def close(self) -> None:  # pragma: no cover - best effort cleanup
        if self._si is not None:
            try:
                from pyVim.connect import Disconnect

                Disconnect(self._si)
            except Exception:
                pass
            self._si = None
            self._content = None


def build_client(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 443,
    verify_certs: bool = True,
    request_timeout: int = 60,
) -> VMwareClient:
    """Construct a VMwareClient from explicit settings (no network contact)."""
    return VMwareClient(
        host=host,
        username=username,
        password=password,
        port=port,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
    )


def build_client_from_env() -> VMwareClient:
    """Construct a VMwareClient from environment variables.

    Raises VMwareConfigError with actionable guidance when the required host or
    credentials are absent.
    """
    host = _first_env("VC_HOSTNAME", "VCENTER_HOST", "VMWARE_HOST")
    username = _first_env("VC_USERNAME", "VCENTER_USERNAME", "VMWARE_USERNAME")
    password = _first_env("VC_PASSWORD", "VCENTER_PASSWORD", "VMWARE_PASSWORD")
    if not (host and username and password):
        raise VMwareConfigError(
            "no vCenter credentials found — set them in the UI, or export "
            "VC_HOSTNAME, VC_USERNAME and VC_PASSWORD; see .env.example"
        )
    return build_client(
        host=host,
        username=username,
        password=password,
        port=int(_first_env("VCENTER_PORT") or "443"),
        verify_certs=_as_bool(_first_env("VCENTER_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("VCENTER_REQUEST_TIMEOUT") or "60"),
    )


def _about(client: VMwareClient) -> Tuple[str, str]:
    """Best-effort (version, build) from the appliance system version endpoint."""
    try:
        payload = client.get("appliance/system/version")
    except Exception:  # pragma: no cover - optional/permission dependent
        return "", ""
    if isinstance(payload, dict):
        root = payload.get("value", payload)
        if isinstance(root, dict):
            return str(root.get("version", "")), str(root.get("build", ""))
    return "", ""


# REST endpoints used to confirm connectivity, tried in order. A capped VM/host
# listing is the lightest liveness probe once a session exists.
_PING_PATHS = ("vcenter/datacenter", "vcenter/host", "vcenter/vm")


def ping(client: VMwareClient) -> dict:
    """Verify connectivity and return a short connection summary.

    Establishes a REST session (surfacing a 401/403 as an authentication
    error) and reads a lightweight inventory listing to confirm access.
    """
    try:
        client.login()
    except HTTPError as exc:  # pragma: no cover - network dependent
        if exc.code in (401, 403):
            raise VMwareConfigError(
                f"authentication/permission failed (HTTP {exc.code}) — "
                "check the vCenter username, password, and API access"
            )
        raise VMwareConfigError(f"could not reach vCenter at {client.host} — HTTP {exc.code}")
    except URLError as exc:  # pragma: no cover - network dependent
        raise VMwareConfigError(
            f"could not reach vCenter at {client.host} — {getattr(exc, 'reason', exc)}"
        )

    last_error: Optional[str] = None
    for path in _PING_PATHS:
        try:
            client.get(path)
        except HTTPError as exc:  # pragma: no cover - network dependent
            if exc.code in (401, 403):
                raise VMwareConfigError(
                    f"authenticated but not authorized (HTTP {exc.code}) — the "
                    "vCenter user needs read access to the inventory"
                )
            last_error = f"HTTP {exc.code}"
            continue
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
            continue
        version, build = _about(client)
        summary = f"vCenter @ {client.host}"
        if version:
            summary += f" · v{version}"
            if build:
                summary += f" (build {build})"
        if not pyvmomi_available():
            summary += " · custom fields off (pyVmomi not installed)"
        return {
            "product": "VMware vCenter",
            "host": client.host,
            "version": version,
            "build": build,
            "pyvmomi": pyvmomi_available(),
            "summary": summary,
        }
    raise VMwareConfigError(
        f"could not read the vCenter inventory at {client.host} — {last_error or 'no response'}"
    )
