"""SolarWinds Orion / SWIS connection, built from a form or environment.

This is the SolarWinds analogue of ``client.py`` / ``tufin_client.py`` /
``vmware_client.py``. SolarWinds exposes its whole data model — nodes,
interfaces, NCM config archive, NCM compliance — through a single query
interface, the **SolarWinds Information Service (SWIS)**, rather than a REST
resource tree. So where the other clients offer ``get(path)``, this client's one
primitive is :meth:`SolarWindsClient.query`, which POSTs a **SWQL** (SolarWinds
Query Language) statement to::

    POST https://<host>:17774/SolarWinds/InformationService/v3/Json/Query

and returns the parsed ``{"results": [...]}`` body. Authentication is HTTP Basic
auth (an Orion account with read access to the entities you query). Only the
connection/query primitives live here; ``solarwinds_runner.py`` turns registry
resources into SWQL and normalizes the responses.

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    SWIS_HOSTNAME / SOLARWINDS_HOST    the Orion/SWIS host or IP
    SWIS_USERNAME / SOLARWINDS_USER    an Orion account with read access
    SWIS_PASSWORD / SOLARWINDS_PASS    that account's password

Optional:
    SWIS_PORT                  SWIS query port (default 17774; older 17778)
    SWIS_VERIFY_CERTS          "false" to disable TLS verification (lab only)
    SWIS_REQUEST_TIMEOUT       seconds (default 120 — config text can be large)
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# The client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None

# The SWIS JSON query endpoint, appended to the base URL.
QUERY_PATH = "/SolarWinds/InformationService/v3/Json/Query"

# SWIS query ports, tried in order when the configured one does not answer.
# 17774 is the SolarWinds Platform (Orion) SWIS port introduced in 2020.2; 17778
# is the older port still used by many deployments.
DEFAULT_PORT = 17774
FALLBACK_PORTS = (17778,)


class SolarWindsConfigError(RuntimeError):
    """Raised when required SolarWinds connection/credential settings are missing,
    or when SWIS cannot be reached / authenticated."""


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
    """Strip scheme, whitespace, trailing slash, and any pasted port/path."""
    host = (host or "").strip().rstrip("/")
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
    host = host.split("/", 1)[0]
    # Drop a pasted ":port" — the port is configured separately.
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


class SolarWindsClient:
    """Minimal SWIS client: HTTP Basic auth, one SWQL ``query`` primitive.

    The port that first answers a trivial query is remembered so subsequent
    queries do not re-probe the fallback ports.
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        port: int = DEFAULT_PORT,
        verify_certs: bool = True,
        request_timeout: int = 120,
    ):
        host = clean_host(host)
        if not host:
            raise SolarWindsConfigError(
                "no SolarWinds host — provide the Orion/SWIS hostname or IP"
            )
        if not (username and password):
            raise SolarWindsConfigError(
                "no credentials — provide a SolarWinds username and password"
            )
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or DEFAULT_PORT)
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout
        self._token = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        # The port confirmed to answer; set lazily by the first successful query.
        self._active_port: Optional[int] = None

    # -- URLs / ports -------------------------------------------------------

    def _url_for_port(self, port: int) -> str:
        return f"https://{self.host}:{port}{QUERY_PATH}"

    @property
    def base_url(self) -> str:
        return self._url_for_port(self._active_port or self.port)

    def _candidate_ports(self) -> List[int]:
        if self._active_port is not None:
            return [self._active_port]
        ordered = [self.port] + [p for p in FALLBACK_PORTS if p != self.port]
        return ordered

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        return None if self.verify_certs else ssl._create_unverified_context()

    # -- query --------------------------------------------------------------

    def _post(self, url: str, swql: str) -> Any:
        body = json.dumps({"query": swql}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {self._token}",
        }
        if requests is not None:
            resp = requests.post(
                url,
                data=body,
                headers=headers,
                verify=self.verify_certs,
                timeout=self.request_timeout,
            )
            resp.raise_for_status()
            text = resp.text
            return json.loads(text) if text else {}

        request = Request(url, data=body, headers=headers, method="POST")
        context = self._ssl_context()
        with urlopen(request, timeout=self.request_timeout, context=context) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}

    def query(self, swql: str) -> Dict[str, Any]:
        """Run a SWQL statement and return the parsed SWIS JSON body.

        On the first call the configured port is tried, then any fallback ports,
        until one answers; that port is then reused. An HTTP 400 (a SWQL/entity
        error, not a connectivity problem) is raised with the server's message so
        the runner can fall back to an alternate entity/field set.
        """
        errors: List[str] = []
        for port in self._candidate_ports():
            url = self._url_for_port(port)
            try:
                result = self._post(url, swql)
            except HTTPError as exc:  # pragma: no cover - network dependent
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="ignore")[:500]
                except Exception:
                    pass
                if exc.code in (401, 403):
                    raise SolarWindsConfigError(
                        f"authentication/permission failed (HTTP {exc.code}) — "
                        "check the SolarWinds username, password, and access"
                    )
                if exc.code == 400:
                    # A malformed/unsupported SWQL — surface it; the port is fine.
                    self._active_port = port
                    raise RuntimeError(
                        f"HTTP 400 from SWIS: {detail or 'invalid SWQL query'}"
                    )
                errors.append(f":{port} HTTP {exc.code}")
                continue
            except URLError as exc:  # pragma: no cover - network dependent
                errors.append(f":{port} {getattr(exc, 'reason', exc)}")
                continue
            except Exception as exc:  # pragma: no cover - network dependent
                # The ``requests`` path raises HTTPError subclasses carrying a
                # ``response``; mirror the urllib branch above off its status.
                response = getattr(exc, "response", None)
                status = getattr(response, "status_code", None)
                if status in (401, 403):
                    raise SolarWindsConfigError(
                        f"authentication/permission failed (HTTP {status}) — "
                        "check the SolarWinds username, password, and access"
                    )
                if status == 400:
                    # A malformed/unsupported SWQL — the port is a live SWIS
                    # endpoint, so surface the query error rather than probing on.
                    detail = ""
                    try:
                        detail = (getattr(response, "text", "") or "")[:500]
                    except Exception:
                        pass
                    self._active_port = port
                    raise RuntimeError(
                        f"HTTP 400 from SWIS: {detail or 'invalid SWQL query'}"
                    )
                errors.append(f":{port} {exc}")
                continue
            self._active_port = port
            return result if isinstance(result, dict) else {}
        raise SolarWindsConfigError(
            f"could not reach SWIS at {self.host} — tried "
            + ", ".join(errors or ["no ports"])
        )

    def query_rows(self, swql: str) -> List[Dict[str, Any]]:
        """Return just the ``results`` list from a SWQL query."""
        data = self.query(swql)
        rows = data.get("results") if isinstance(data, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def build_client(
    *,
    host: str,
    username: str,
    password: str,
    port: int = DEFAULT_PORT,
    verify_certs: bool = True,
    request_timeout: int = 120,
) -> SolarWindsClient:
    """Construct a SolarWindsClient from explicit settings (no network contact)."""
    return SolarWindsClient(
        host=host,
        username=username,
        password=password,
        port=port,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
    )


def build_client_from_env() -> SolarWindsClient:
    """Construct a SolarWindsClient from environment variables.

    Raises SolarWindsConfigError with actionable guidance when the required host
    or credentials are absent.
    """
    host = _first_env("SWIS_HOSTNAME", "SOLARWINDS_HOST", "ORION_HOST")
    username = _first_env("SWIS_USERNAME", "SOLARWINDS_USER", "ORION_USERNAME")
    password = _first_env("SWIS_PASSWORD", "SOLARWINDS_PASS", "ORION_PASSWORD")
    if not (host and username and password):
        raise SolarWindsConfigError(
            "no SolarWinds credentials found — set them in the UI, or export "
            "SWIS_HOSTNAME, SWIS_USERNAME and SWIS_PASSWORD; see .env.example"
        )
    return build_client(
        host=host,
        username=username,
        password=password,
        port=int(_first_env("SWIS_PORT") or str(DEFAULT_PORT)),
        verify_certs=_as_bool(_first_env("SWIS_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("SWIS_REQUEST_TIMEOUT") or "120"),
    )


def ping(client: SolarWindsClient) -> dict:
    """Verify connectivity and return a short connection summary.

    Runs a trivial, universally-valid SWQL statement against the SWIS metadata,
    so a 401/403 surfaces as an authentication error and an unreachable host as a
    connectivity error. Reports the Orion version (best effort) and whether the
    NCM module appears present, so the UI can hint when config-posture resources
    will be empty.
    """
    try:
        # Metadata.Entity is present on every SWIS instance; FullName is the
        # entity's name (e.g. "Orion.Nodes"). This is the minimal valid probe —
        # it needs no module and no special read grant.
        client.query_rows("SELECT TOP 1 FullName FROM Metadata.Entity")
    except SolarWindsConfigError:
        raise
    except Exception as exc:  # pragma: no cover - network dependent
        raise SolarWindsConfigError(
            f"could not query SWIS at {client.host} — {exc}"
        )

    version = _orion_version(client)
    ncm = _ncm_available(client)
    summary = f"SolarWinds SWIS @ {client.host}:{client._active_port or client.port}"
    if not ncm:
        summary += " · NCM not detected (config posture resources may be empty)"
    return {
        "product": "SolarWinds Orion (SWIS)",
        "host": client.host,
        "port": client._active_port or client.port,
        "swis_version": version,
        "ncm": ncm,
        "summary": summary,
    }


def _orion_version(client: SolarWindsClient) -> str:
    """Best-effort Orion Platform version (Orion.Info.Version); '' if unavailable."""
    try:
        rows = client.query_rows("SELECT TOP 1 Version FROM Orion.Info")
    except Exception:  # pragma: no cover - permission/module dependent
        return ""
    return str(rows[0].get("Version", "") or "") if rows else ""


def _ncm_available(client: SolarWindsClient) -> bool:
    """Best-effort check that the NCM (config) entities are present/licensed.

    Queries the SWIS metadata by ``FullName`` (the entity's name) — a row means
    the NCM node entity is registered in this SWIS instance.
    """
    for entity in ("NCM.Nodes", "Cirrus.Nodes"):
        try:
            rows = client.query_rows(
                f"SELECT TOP 1 FullName FROM Metadata.Entity "
                f"WHERE FullName = '{entity}'"
            )
        except Exception:  # pragma: no cover - network dependent
            continue
        if rows:
            return True
    return False
