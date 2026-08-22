"""Tenable.sc (SecurityCenter) REST connection, built from a form or environment.

This is the Tenable.sc analogue of ``tufin_client.py`` / ``vmware_client.py``.
Tenable.sc (formerly SecurityCenter) exposes a REST API rooted at::

    https://<tenable_sc_host>/rest/

Everything — the device inventory, the aggregated security findings, installed
software, users, asset lists (tags), alerts, and tickets (incidents) — is read
through this one REST tree. Two request shapes cover it:

* the plain resource endpoints — ``GET /rest/user``, ``/rest/asset``,
  ``/rest/alert``, ``/rest/ticket`` — for the object listings, and
* the workhorse ``POST /rest/analysis`` endpoint, which returns vulnerability /
  device / software data through a *tool* (``sumip`` for a per-host device
  summary, ``vulndetails`` for individual findings, ``listsoftware`` for the
  installed-software enumeration, …), paged with ``startOffset`` / ``endOffset``.

**Authentication.** Tenable.sc supports three credential styles; this client
implements the two documented as primary:

* **Username + password** (a *session token*): ``POST /rest/token`` returns a
  numeric ``token`` and sets a ``TNS_SESSIONID`` cookie. Every subsequent
  request carries the token in the ``X-SecurityCenter`` header and the session
  cookie. ``DELETE /rest/token`` logs out. This is the "connect with IP,
  username and password" path.
* **Access key + secret key** (the preferred, session-less style per Tenable's
  docs): every request carries the header
  ``x-apikey: accesskey=<ak>; secretkey=<sk>`` and no login round-trip is needed.

The account used must have the **Security Manager** role with access to the
required repositories (see the developer guide).

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    TENABLE_SC_HOST            the Tenable.sc host or IP
    TENABLE_SC_USERNAME        a Security Manager user
    TENABLE_SC_PASSWORD        that user's password
      -- or --
    TENABLE_SC_ACCESS_KEY      an API access key (preferred)
    TENABLE_SC_SECRET_KEY      the matching secret key

Optional:
    TENABLE_SC_API_PREFIX      path prefix in front of /rest (default none)
    TENABLE_SC_VERIFY_CERTS    "false" to disable TLS verification (lab only)
    TENABLE_SC_REQUEST_TIMEOUT seconds (default 60)

Only the connection/query primitives live here; ``tenable_sc_runner.py`` turns
registry resources into the endpoint/analysis calls and normalizes responses.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import ssl
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, Request, build_opener

# The REST client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


# Tenable.sc analysis pagination page size (records per POST /rest/analysis).
ANALYSIS_PAGE_SIZE = 1000

# Hard cap on records pulled from one analysis fetch, so a huge estate cannot
# fan out into an unbounded number of pages / rows.
ANALYSIS_MAX_RECORDS = 200000


class TenableScConfigError(RuntimeError):
    """Raised when required Tenable.sc connection/credential settings are missing,
    or when the server cannot be reached / authenticated."""


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
    """Strip scheme, whitespace, trailing slash, and any pasted path from a host/URL."""
    host = (host or "").strip().rstrip("/")
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
    # Drop any pasted path (e.g. someone pastes ``host/rest``) but keep host:port.
    host = host.split("/", 1)[0]
    return host


class TenableScClient:
    """Minimal Tenable.sc REST client.

    Exposes ``get`` / ``post`` primitives plus an ``analysis`` helper that paginates
    the ``POST /rest/analysis`` endpoint. Handles both credential styles and the
    Tenable.sc response envelope (``{"error_code", "error_msg", "response"}``),
    where an API error is reported *in the body with HTTP 200* — so the body's
    ``error_code`` is always checked, not just the HTTP status.
    """

    def __init__(
        self,
        *,
        host: str,
        username: str = "",
        password: str = "",
        access_key: str = "",
        secret_key: str = "",
        api_prefix: str = "",
        verify_certs: bool = True,
        request_timeout: int = 60,
    ):
        host = clean_host(host)
        if not host:
            raise TenableScConfigError(
                "no Tenable.sc host — provide the SecurityCenter hostname or IP"
            )
        has_userpass = bool(username and password)
        has_keys = bool(access_key and secret_key)
        if not (has_userpass or has_keys):
            raise TenableScConfigError(
                "no credentials — provide a Tenable.sc username and password, "
                "or an access key and secret key"
            )
        self.host = host
        self.username = username
        self.password = password
        self.access_key = access_key
        self.secret_key = secret_key
        # Optional prefix in front of ``/rest`` (Axonius's "API Optional Prefix").
        self.api_prefix = "/" + api_prefix.strip("/") if api_prefix.strip("/") else ""
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout

        # Session state (username/password style). ``_token`` is the numeric
        # X-SecurityCenter token; the cookie jar / session hold TNS_SESSIONID.
        self._token: Optional[str] = None
        self._session = None  # requests.Session when available
        self._cookies = http.cookiejar.CookieJar()  # urllib fallback
        self._opener = None

    # -- URLs ---------------------------------------------------------------

    def url_for(self, path: str) -> str:
        return f"https://{self.host}{self.api_prefix}/rest/{path.lstrip('/')}"

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        return None if self.verify_certs else ssl._create_unverified_context()

    def _base_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.access_key and self.secret_key:
            headers["x-apikey"] = (
                f"accesskey={self.access_key}; secretkey={self.secret_key}"
            )
        elif self._token:
            headers["X-SecurityCenter"] = str(self._token)
        return headers

    # -- envelope handling --------------------------------------------------

    @staticmethod
    def _unwrap(payload: Any) -> Any:
        """Return the ``response`` body, raising on a non-zero ``error_code``.

        Tenable.sc wraps every reply as ``{"error_code": N, "error_msg": "...",
        "response": ...}`` and — unhelpfully — often returns HTTP 200 even for API
        errors, signalling failure only through ``error_code``. So the envelope is
        always inspected here.
        """
        if not isinstance(payload, dict):
            return payload
        code = payload.get("error_code")
        if code not in (None, 0, "0"):
            msg = payload.get("error_msg") or f"error_code {code}"
            raise RuntimeError(f"Tenable.sc API error: {msg}")
        return payload.get("response", payload)

    # -- low-level request --------------------------------------------------

    def _request(
        self, method: str, path: str, body: Optional[dict] = None, *, login: bool = False
    ) -> Any:
        """Issue one HTTP request and return the unwrapped ``response`` body.

        ``login`` requests skip the auth headers (they *establish* the session)
        and capture the returned token / session cookie.
        """
        url = self.url_for(path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if not login:
            headers.update(self._base_headers())

        if requests is not None:
            session = self._session or requests
            resp = session.request(
                method,
                url,
                data=data,
                headers=headers,
                verify=self.verify_certs,
                timeout=self.request_timeout,
            )
            if resp.status_code in (401, 403):
                raise TenableScConfigError(
                    f"authentication/permission failed (HTTP {resp.status_code}) — "
                    "check the Tenable.sc credentials, the Security Manager role, "
                    "and repository access"
                )
            resp.raise_for_status()
            text = resp.text
            parsed = json.loads(text) if text else {}
            if login:
                return parsed  # caller inspects token / cookies directly
            return self._unwrap(parsed)

        # urllib fallback (keeps a cookie jar for the session cookie).
        if self._opener is None:
            self._opener = build_opener(HTTPCookieProcessor(self._cookies))
        request = Request(url, data=data, headers=headers, method=method)
        context = self._ssl_context()
        try:
            with self._opener.open(request, timeout=self.request_timeout) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as exc:  # pragma: no cover - network dependent
            if exc.code in (401, 403):
                raise TenableScConfigError(
                    f"authentication/permission failed (HTTP {exc.code}) — "
                    "check the Tenable.sc credentials and permissions"
                )
            raise
        parsed = json.loads(payload) if payload else {}
        if login:
            return parsed
        return self._unwrap(parsed)

    # -- session lifecycle --------------------------------------------------

    def login(self) -> None:
        """Establish a session for username/password auth (no-op for API keys).

        POSTs ``/rest/token`` and stores the returned ``token`` plus the
        ``TNS_SESSIONID`` cookie for subsequent requests.
        """
        if self.access_key and self.secret_key:
            return  # key auth is session-less
        if self._token:
            return  # already logged in
        if requests is not None and self._session is None:
            self._session = requests.Session()
        raw = self._request(
            "POST", "token",
            {"username": self.username, "password": self.password},
            login=True,
        )
        # Login errors surface in the envelope with HTTP 200; check it explicitly.
        if isinstance(raw, dict) and raw.get("error_code") not in (None, 0, "0"):
            raise TenableScConfigError(
                f"Tenable.sc login failed: {raw.get('error_msg') or 'invalid credentials'}"
            )
        response = raw.get("response", {}) if isinstance(raw, dict) else {}
        token = response.get("token")
        if not token:
            raise TenableScConfigError(
                "Tenable.sc login did not return a session token — "
                "check the username and password"
            )
        self._token = str(token)

    def logout(self) -> None:
        """Best-effort session teardown (``DELETE /rest/token``)."""
        if self._token is None:
            return
        try:
            self._request("DELETE", "token")
        except Exception:  # pragma: no cover - teardown is best-effort
            pass
        self._token = None

    # -- public primitives --------------------------------------------------

    def get(self, path: str) -> Any:
        """GET a Tenable.sc resource; returns the unwrapped ``response`` body."""
        return self._request("GET", path)

    def post(self, path: str, body: dict) -> Any:
        """POST to a Tenable.sc endpoint; returns the unwrapped ``response`` body."""
        return self._request("POST", path, body)

    def analysis(
        self,
        tool: str,
        *,
        analysis_type: str = "vuln",
        source_type: str = "cumulative",
        filters: Optional[List[dict]] = None,
        page_size: int = ANALYSIS_PAGE_SIZE,
        max_records: int = ANALYSIS_MAX_RECORDS,
    ) -> List[Dict[str, Any]]:
        """Run ``POST /rest/analysis`` for ``tool`` and return every result record.

        Pages through with ``startOffset`` / ``endOffset`` until the server reports
        no more records (``returnedRecords`` < page size, or ``totalRecords``
        reached), or ``max_records`` is hit. Works for any vuln analysis tool
        (``sumip``, ``vulndetails``, ``listsoftware``, …).
        """
        records: List[Dict[str, Any]] = []
        start = 0
        while True:
            end = start + page_size
            query = {
                "type": analysis_type,
                "tool": tool,
                "sourceType": source_type,
                "startOffset": start,
                "endOffset": end,
                "filters": filters or [],
            }
            body = {"type": analysis_type, "sourceType": source_type, "query": query}
            response = self.post("analysis", body)
            if not isinstance(response, dict):
                break
            page = response.get("results")
            page = [r for r in page if isinstance(r, dict)] if isinstance(page, list) else []
            records.extend(page)
            if len(records) >= max_records:
                break
            try:
                total = int(response.get("totalRecords") or 0)
            except (TypeError, ValueError):
                total = 0
            if len(page) < page_size:
                break
            if total and len(records) >= total:
                break
            start = end
        return records[:max_records]


def build_client(
    *,
    host: str,
    username: str = "",
    password: str = "",
    access_key: str = "",
    secret_key: str = "",
    api_prefix: str = "",
    verify_certs: bool = True,
    request_timeout: int = 60,
) -> TenableScClient:
    """Construct a TenableScClient from explicit settings (no network contact)."""
    return TenableScClient(
        host=host,
        username=username,
        password=password,
        access_key=access_key,
        secret_key=secret_key,
        api_prefix=api_prefix,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
    )


def build_client_from_env() -> TenableScClient:
    """Construct a TenableScClient from environment variables.

    Raises TenableScConfigError with actionable guidance when the required host or
    credentials are absent.
    """
    host = _first_env("TENABLE_SC_HOST", "TENABLE_SC_HOSTNAME", "SECURITYCENTER_HOST")
    username = _first_env("TENABLE_SC_USERNAME", "SECURITYCENTER_USERNAME") or ""
    password = _first_env("TENABLE_SC_PASSWORD", "SECURITYCENTER_PASSWORD") or ""
    access_key = _first_env("TENABLE_SC_ACCESS_KEY", "SECURITYCENTER_ACCESS_KEY") or ""
    secret_key = _first_env("TENABLE_SC_SECRET_KEY", "SECURITYCENTER_SECRET_KEY") or ""
    if not host or not ((username and password) or (access_key and secret_key)):
        raise TenableScConfigError(
            "no Tenable.sc credentials found — set them in the UI, or export "
            "TENABLE_SC_HOST plus either TENABLE_SC_USERNAME/TENABLE_SC_PASSWORD "
            "or TENABLE_SC_ACCESS_KEY/TENABLE_SC_SECRET_KEY; see .env.example"
        )
    return build_client(
        host=host,
        username=username,
        password=password,
        access_key=access_key,
        secret_key=secret_key,
        api_prefix=_first_env("TENABLE_SC_API_PREFIX") or "",
        verify_certs=_as_bool(_first_env("TENABLE_SC_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("TENABLE_SC_REQUEST_TIMEOUT") or "60"),
    )


def ping(client: TenableScClient) -> dict:
    """Verify connectivity/credentials and return a short connection summary.

    Logs in (for username/password auth), then reads ``/rest/currentUser`` and the
    server version from ``/rest/system`` so the UI can show who connected and the
    Tenable.sc release. A 401/403 surfaces as an authentication error rather than
    being retried.
    """
    try:
        client.login()
    except TenableScConfigError:
        raise
    except Exception as exc:  # pragma: no cover - network dependent
        raise TenableScConfigError(
            f"could not reach the Tenable.sc API at {client.host} — {exc}"
        )

    who = ""
    role = ""
    try:
        current = client.get("currentUser")
        if isinstance(current, dict):
            who = str(current.get("username") or "")
            role_obj = current.get("role")
            if isinstance(role_obj, dict):
                role = str(role_obj.get("name") or "")
    except TenableScConfigError:
        raise
    except Exception:  # pragma: no cover - permission dependent
        pass

    version = ""
    try:
        system = client.get("system")
        if isinstance(system, dict):
            version = str(system.get("version") or "")
    except Exception:  # pragma: no cover - permission dependent
        pass

    summary = f"Tenable.sc @ {client.host}"
    if version:
        summary += f" · v{version}"
    if who:
        summary += f" · user {who}" + (f" ({role})" if role else "")
    return {
        "product": "Tenable.sc (SecurityCenter)",
        "host": client.host,
        "version": version,
        "user": who,
        "role": role,
        "summary": summary,
    }
