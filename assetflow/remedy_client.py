"""BMC Remedy (AR System / Atrium CMDB) connection, built from a form or env.

This is the BMC Remedy analogue of ``client.py`` / ``vmware_client.py`` /
``assetexplorer_client.py``. It speaks the **BMC Remedy AR System REST API**
rooted at::

    https://<host>[:<port>]/api/

Authentication is JWT-based, as the AR System REST API prescribes:

* ``POST /api/jwt/login`` with form-encoded ``username`` / ``password`` returns
  a bare JWT token as ``text/plain``; it is then sent on every subsequent call
  as the header ``Authorization: AR-JWT <token>``.
* ``POST /api/jwt/logout`` releases the token (best effort on close).

Records live in AR *forms* (the CMDB CI classes such as
``BMC.CORE:BMC_ComputerSystem`` and the ITSM forms such as ``HPD:Help Desk``)
and are read with::

    GET /api/arsys/v1/entry/<form>?offset=&limit=&q=&fields=&sort=

which returns ``{"entries": [{"values": {<field label>: <value>, ...}}, ...]}``.
Paging is by ``offset`` / ``limit``; this client walks the pages up to a cap.

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    REMEDY_HOST / AR_HOST         the Remedy host or IP (mid-tier / REST host)
    REMEDY_USERNAME / AR_USERNAME an AR System user with read access to the forms
    REMEDY_PASSWORD / AR_PASSWORD that user's password

Optional:
    REMEDY_PORT              HTTPS port (default 443; on-prem often 8443/8008)
    REMEDY_VERIFY_CERTS      "false" to disable TLS verification (lab only)
    REMEDY_REQUEST_TIMEOUT   seconds (default 60)
    REMEDY_PAGE_SIZE         entries fetched per REST call (default 250)
    REMEDY_MAX_RECORDS       cap on entries fetched per form (default 10000)

Only the connection/session primitives live here; ``remedy_runner.py`` turns
registry resources (form names) into endpoint calls and normalizes the
responses into the shared column/row shape.
"""

from __future__ import annotations

import json
import os
import ssl
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

# The client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


# Defaults for paging the AR entry endpoint.
DEFAULT_PAGE_SIZE = 250
DEFAULT_MAX_RECORDS = 10000


class RemedyConfigError(RuntimeError):
    """Raised when required Remedy connection/credential settings are missing."""


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


def scheme_of(host: str) -> str:
    """Return the explicit scheme a user pasted onto a host, or '' if none."""
    host = (host or "").strip().lower()
    if host.startswith("https://"):
        return "https"
    if host.startswith("http://"):
        return "http"
    return ""


def clean_host(host: str) -> str:
    """Strip scheme, whitespace, path, and any trailing slash from a host/URL."""
    host = (host or "").strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    # Drop any path the user may have pasted after the host (keep host[:port]).
    host = host.split("/", 1)[0]
    return host


class RemedyClient:
    """Minimal BMC Remedy AR System REST client.

    The JWT is fetched lazily on the first ``get_entries`` (or eagerly by
    ``ping``) and re-fetched once automatically if a call comes back 401.
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        use_ssl: bool = True,
        verify_certs: bool = True,
        request_timeout: int = 60,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_records: int = DEFAULT_MAX_RECORDS,
    ):
        scheme = scheme_of(host)
        host = clean_host(host)
        if not host:
            raise RemedyConfigError(
                "no Remedy host — provide the AR System host or IP"
            )
        if not (username and password):
            raise RemedyConfigError(
                "no credentials — provide a Remedy username and password"
            )
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 443)
        # An explicit http:// on the host forces plain HTTP (on-prem lab hosts).
        self.use_ssl = use_ssl and scheme != "http"
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout
        self.page_size = max(1, int(page_size or DEFAULT_PAGE_SIZE))
        self.max_records = max(1, int(max_records or DEFAULT_MAX_RECORDS))
        self._token: Optional[str] = None

    # -- URLs / transport ---------------------------------------------------

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        # A host that already carries an explicit port (e.g. an http://h:8008 the
        # user pasted) wins — don't append a second port.
        if ":" in self.host:
            return f"{scheme}://{self.host}"
        default_port = 443 if self.use_ssl else 80
        suffix = "" if self.port in (default_port, None) else f":{self.port}"
        return f"{scheme}://{self.host}{suffix}"

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.use_ssl:
            return None
        return None if self.verify_certs else ssl._create_unverified_context()

    def _http(
        self,
        url: str,
        *,
        method: str,
        headers: dict,
        data: Optional[bytes] = None,
    ) -> Any:
        """Perform an HTTP request and return (status, text)."""
        if requests is not None:
            resp = requests.request(
                method,
                url,
                headers=headers,
                data=data,
                verify=self.verify_certs if self.use_ssl else True,
                timeout=self.request_timeout,
            )
            return resp.status_code, resp.text
        request = Request(url, data=data, headers=headers, method=method)
        context = self._ssl_context()
        try:
            with urlopen(
                request, timeout=self.request_timeout, context=context
            ) as response:
                body = response.read().decode("utf-8")
                return getattr(response, "status", 200) or 200, body
        except HTTPError as exc:  # surface status + body like requests does
            body = exc.read().decode("utf-8", "replace") if exc.fp else ""
            return exc.code, body

    # -- auth ---------------------------------------------------------------

    def login(self) -> str:
        """Create an AR System JWT and cache it.

        ``POST /api/jwt/login`` takes form-encoded credentials and returns the
        token as a bare ``text/plain`` string.
        """
        url = f"{self.base_url}/api/jwt/login"
        data = urlencode(
            {"username": self.username, "password": self.password}
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/plain",
        }
        try:
            status, body = self._http(url, method="POST", headers=headers, data=data)
        except URLError as exc:  # pragma: no cover - network dependent
            raise RemedyConfigError(
                f"could not reach Remedy at {self.host} — {getattr(exc, 'reason', exc)}"
            )
        if status in (401, 403):
            raise RemedyConfigError(
                f"authentication failed (HTTP {status}) — check the Remedy "
                "username and password"
            )
        token = (body or "").strip()
        if status >= 400 or not token:
            raise RemedyConfigError(
                f"Remedy did not return a JWT (HTTP {status}) — check the host, "
                "port, and that the AR System REST API is enabled"
            )
        self._token = token
        return token

    def logout(self) -> None:  # pragma: no cover - best effort cleanup
        if not self._token:
            return
        url = f"{self.base_url}/api/jwt/logout"
        headers = {"Authorization": f"AR-JWT {self._token}"}
        try:
            self._http(url, method="POST", headers=headers)
        except Exception:
            pass
        self._token = None

    close = logout

    # -- entries ------------------------------------------------------------

    def _entry_url(self, form: str, params: Dict[str, Any]) -> str:
        # Form names carry ':' and '.' and spaces (e.g. BMC.CORE:BMC_ComputerSystem);
        # encode the whole segment so those survive intact.
        segment = quote(form, safe="")
        query = urlencode({k: v for k, v in params.items() if v not in (None, "")})
        base = f"{self.base_url}/api/arsys/v1/entry/{segment}"
        return f"{base}?{query}" if query else base

    def _get_page(self, form: str, params: Dict[str, Any]) -> List[dict]:
        if self._token is None:
            self.login()
        url = self._entry_url(form, params)

        def _do() -> Any:
            headers = {
                "Authorization": f"AR-JWT {self._token}",
                "Accept": "application/json",
            }
            return self._http(url, method="GET", headers=headers)

        status, body = _do()
        if status == 401:  # token expired — refresh once and retry
            self.login()
            status, body = _do()
        if status in (401, 403):
            raise RemedyConfigError(
                f"authenticated but not authorized (HTTP {status}) to read "
                f"form {form!r} — the Remedy user needs read access to it"
            )
        if status >= 400:
            raise RemedyConfigError(
                f"Remedy returned HTTP {status} reading form {form!r}"
            )
        try:
            payload = json.loads(body) if body else {}
        except ValueError:  # pragma: no cover - defensive
            payload = {}
        entries = payload.get("entries") if isinstance(payload, dict) else None
        return [e for e in (entries or []) if isinstance(e, dict)]

    def get_entries(
        self,
        form: str,
        *,
        fields: Optional[str] = None,
        qualification: Optional[str] = None,
        sort: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[dict]:
        """Fetch entries from an AR form, walking pages up to the record cap.

        ``fields`` is an AR field selector such as ``values(Name,SerialNumber)``
        — omitted, all readable fields come back (so site-added custom fields are
        captured). ``qualification`` is an AR qualification string passed as the
        ``q`` parameter. ``limit`` caps the total rows returned.
        """
        cap = self.max_records if limit is None else min(int(limit), self.max_records)
        out: List[dict] = []
        offset = 0
        while len(out) < cap:
            page_limit = min(self.page_size, cap - len(out))
            params: Dict[str, Any] = {"offset": offset, "limit": page_limit}
            if fields:
                params["fields"] = fields
            if qualification:
                params["q"] = qualification
            if sort:
                params["sort"] = sort
            page = self._get_page(form, params)
            out.extend(page)
            if len(page) < page_limit:
                break  # last page
            offset += len(page)
        return out[:cap]


def build_client(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 443,
    use_ssl: bool = True,
    verify_certs: bool = True,
    request_timeout: int = 60,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> RemedyClient:
    """Construct a RemedyClient from explicit settings (no network contact)."""
    return RemedyClient(
        host=host,
        username=username,
        password=password,
        port=port,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
        page_size=page_size,
        max_records=max_records,
    )


def build_client_from_env() -> RemedyClient:
    """Construct a RemedyClient from environment variables.

    Raises RemedyConfigError with actionable guidance when the required host or
    credentials are absent.
    """
    host = _first_env("REMEDY_HOST", "AR_HOST", "BMC_REMEDY_HOST")
    username = _first_env("REMEDY_USERNAME", "AR_USERNAME", "BMC_REMEDY_USERNAME")
    password = _first_env("REMEDY_PASSWORD", "AR_PASSWORD", "BMC_REMEDY_PASSWORD")
    if not (host and username and password):
        raise RemedyConfigError(
            "no Remedy credentials found — set them in the UI, or export "
            "REMEDY_HOST, REMEDY_USERNAME and REMEDY_PASSWORD; see .env.example"
        )
    return build_client(
        host=host,
        username=username,
        password=password,
        port=int(_first_env("REMEDY_PORT", "AR_PORT") or "443"),
        use_ssl=_as_bool(_first_env("REMEDY_USE_SSL"), True),
        verify_certs=_as_bool(_first_env("REMEDY_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("REMEDY_REQUEST_TIMEOUT") or "60"),
        page_size=int(_first_env("REMEDY_PAGE_SIZE") or str(DEFAULT_PAGE_SIZE)),
        max_records=int(_first_env("REMEDY_MAX_RECORDS") or str(DEFAULT_MAX_RECORDS)),
    )


# Forms tried in order to confirm read access once a JWT exists. The CMDB
# computer-system class is the primary asset form; the AR user form is a
# near-universal fallback that any authenticated account can read.
_PING_FORMS = (
    "BMC.CORE:BMC_ComputerSystem",
    "AST:ComputerSystem",
    "CTM:People",
    "User",
)


def ping(client: RemedyClient) -> dict:
    """Verify connectivity and return a short connection summary.

    Establishes a JWT session (surfacing a 401/403 as an authentication error)
    and reads a single entry from the first readable probe form to confirm
    access.
    """
    client.login()  # raises RemedyConfigError on auth/reach failure
    last_error: Optional[str] = None
    for form in _PING_FORMS:
        try:
            client.get_entries(form, limit=1)
        except RemedyConfigError as exc:
            last_error = str(exc)
            continue
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
            continue
        summary = f"BMC Remedy @ {client.host}"
        return {
            "product": "BMC Remedy AR System",
            "host": client.host,
            "probe_form": form,
            "summary": summary,
        }
    raise RemedyConfigError(
        f"authenticated to Remedy at {client.host} but could not read any probe "
        f"form — {last_error or 'no response'}; check the user's form permissions"
    )
