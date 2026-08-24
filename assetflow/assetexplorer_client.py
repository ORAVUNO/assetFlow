"""ManageEngine AssetExplorer REST connection, built from a form or environment.

This is the AssetExplorer analogue of ``tenable_sc_client.py`` / ``vmware_client.py``.
ManageEngine AssetExplorer exposes a REST API (v3) rooted at::

    https://<host>/app/<portal>/api/v3/     (AssetExplorer Cloud)
    https://<host>/api/v3/                   (on-premises AssetExplorer)

Everything the integration asked for is read through this one REST tree:

* ``GET /api/v3/assets``               — the full asset inventory (every asset,
  regardless of product type), one JSON object per asset with its named fields
  plus a ``udf_fields`` object holding the site's custom (UDF) fields.
* ``GET /api/v3/cmdb/{ci_type}``       — the CMDB configuration items, per CI type
  (server, router, switch, access_point, …). The CMDB view of the estate.
* ``GET /api/v3/contracts``            — maintenance / lease / warranty contracts.
* ``GET /api/v3/purchase_orders``      — purchase orders.
* ``GET /api/v3/asset_types`` / ``/products`` — the product-type / product catalog
  that categorizes assets into servers, routers, workstations, access points, …

Every list endpoint follows the same envelope and paging contract:

* the request carries an ``input_data`` query parameter — a JSON string with a
  ``list_info`` block (``row_count``, ``start_index``, ``get_total_count`` …);
* the reply is ``{"response_status": {...}, "list_info": {"has_more_rows": ...,
  "start_index": ..., "row_count": ...}, "<resource>": [ ... ]}``. An API error is
  reported in ``response_status`` (a ``status_code`` other than 2000), often with
  HTTP 200 — so the envelope's status is always inspected, not just the HTTP code.

**Authentication.** AssetExplorer supports two credential styles; this client
implements both:

* **OAuth 2.0 access token** (AssetExplorer *Cloud*, the aecloud-v3 API): every
  request carries ``Authorization: Zoho-oauthtoken <access_token>``. Access tokens
  are short-lived; supply a long-lived **refresh token** (plus the OAuth client id
  / secret) and this client mints a fresh access token on demand from the Zoho
  accounts server, so a connection keeps working past the one-hour token lifetime.
* **Technician API key** (on-premises AssetExplorer): every request carries the
  key in the ``TECHNICIAN_KEY`` and ``authtoken`` headers — the on-prem key issued
  to a technician under Personalize → API.

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    AE_HOST                the AssetExplorer host / service domain
    AE_PORTAL              the portal name (Cloud; e.g. "itdesk") — omit on-prem
    AE_ACCESS_TOKEN        a current OAuth access token (Cloud), or
    AE_REFRESH_TOKEN       a long-lived refresh token (Cloud; preferred), with
    AE_CLIENT_ID           the OAuth client id and
    AE_CLIENT_SECRET       the OAuth client secret
      -- or (on-premises) --
    AE_API_KEY             a technician API key

Optional:
    AE_ACCOUNTS_URL        Zoho accounts server for token refresh
                           (default https://accounts.zoho.com)
    AE_VERIFY_CERTS        "false" to disable TLS verification (lab / on-prem only)
    AE_REQUEST_TIMEOUT     seconds (default 60)

Only the connection/query primitives live here; ``assetexplorer_runner.py`` turns
registry resources into the endpoint calls and normalizes the responses.
"""

from __future__ import annotations

import json
import os
import ssl
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener

# The REST client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


# List pagination page size (records per list request). AssetExplorer caps
# row_count at 100 per page, so that is the default.
LIST_PAGE_SIZE = int(os.getenv("AE_PAGE_SIZE") or 100)


def _max_records() -> int:
    """Safety cap on records pulled from one list fetch, so a runaway paging loop
    cannot grow without bound. "Fetch all" wants everything, so this is set high;
    override with AE_MAX_RECORDS (0 or negative = truly unlimited)."""
    try:
        val = int(os.getenv("AE_MAX_RECORDS") or 1000000)
    except (TypeError, ValueError):
        val = 1000000
    return val if val > 0 else 10**12  # effectively unlimited


LIST_MAX_RECORDS = _max_records()


class AssetExplorerConfigError(RuntimeError):
    """Raised when required AssetExplorer connection/credential settings are missing,
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
    # Drop any pasted path (e.g. someone pastes ``host/app/itdesk``) but keep host:port.
    host = host.split("/", 1)[0]
    return host


def clean_portal(portal: str) -> str:
    """Normalize a portal name to a bare slug (no slashes/whitespace)."""
    return (portal or "").strip().strip("/").split("/", 1)[0]


class AssetExplorerClient:
    """Minimal ManageEngine AssetExplorer REST (v3) client.

    Exposes ``get`` / ``post`` primitives plus a ``list`` helper that paginates any
    v3 list endpoint via the ``input_data`` / ``list_info`` contract. Handles both
    credential styles (OAuth access/refresh token, or an on-prem technician key)
    and the AssetExplorer response envelope (``{"response_status", "list_info",
    "<resource>"}``), where an API error is reported *in the body* through
    ``response_status.status_code`` — so the body's status is always checked, not
    just the HTTP status.
    """

    def __init__(
        self,
        *,
        host: str,
        portal: str = "",
        access_token: str = "",
        refresh_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        api_key: str = "",
        accounts_url: str = "https://accounts.zoho.com",
        verify_certs: bool = True,
        request_timeout: int = 60,
    ):
        host = clean_host(host)
        if not host:
            raise AssetExplorerConfigError(
                "no AssetExplorer host — provide the AssetExplorer service domain or hostname"
            )
        has_oauth = bool(access_token or (refresh_token and client_id and client_secret))
        has_key = bool(api_key)
        if not (has_oauth or has_key):
            raise AssetExplorerConfigError(
                "no credentials — provide an OAuth access token (or a refresh token "
                "with its client id and secret) for AssetExplorer Cloud, or a "
                "technician API key for on-premises AssetExplorer"
            )
        self.host = host
        self.portal = clean_portal(portal)
        self._access_token = access_token
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_key = api_key
        self.accounts_url = (accounts_url or "https://accounts.zoho.com").rstrip("/")
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout

        self._session = None  # requests.Session when available
        self._opener = None   # urllib opener fallback

    # -- URLs ---------------------------------------------------------------

    def url_for(self, path: str) -> str:
        """Build a v3 endpoint URL. A ``portal`` yields the Cloud form
        (``/app/<portal>/api/v3/...``); no portal yields the on-prem form
        (``/api/v3/...``)."""
        base = f"https://{self.host}"
        if self.portal:
            base += f"/app/{self.portal}"
        return f"{base}/api/v3/{path.lstrip('/')}"

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        return None if self.verify_certs else ssl._create_unverified_context()

    # -- auth ---------------------------------------------------------------

    def _ensure_access_token(self) -> None:
        """Mint an OAuth access token from the refresh token when we don't have one.

        No-op for the technician-key style, or when an access token is already held.
        """
        if self.api_key:
            return
        if self._access_token:
            return
        if not (self.refresh_token and self.client_id and self.client_secret):
            raise AssetExplorerConfigError(
                "no OAuth access token and no refresh-token credentials to mint one"
            )
        url = f"{self.accounts_url}/oauth/v2/token"
        params = {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
        }
        body = urlencode(params).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            if requests is not None:
                resp = requests.post(
                    url, data=params, headers=headers,
                    verify=self.verify_certs, timeout=self.request_timeout,
                )
                resp.raise_for_status()
                parsed = resp.json()
            else:  # pragma: no cover - exercised only without requests
                request = Request(url, data=body, headers=headers, method="POST")
                opener = build_opener()
                with opener.open(request, timeout=self.request_timeout) as response:
                    parsed = json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # pragma: no cover - network dependent
            raise AssetExplorerConfigError(
                f"could not refresh the AssetExplorer OAuth access token — {exc}"
            )
        token = parsed.get("access_token") if isinstance(parsed, dict) else None
        if not token:
            err = parsed.get("error") if isinstance(parsed, dict) else parsed
            raise AssetExplorerConfigError(
                f"OAuth token refresh did not return an access token ({err})"
            )
        self._access_token = str(token)

    def refresh_access_token(self) -> None:
        """Force a new access token to be minted on the next request (Cloud/OAuth)."""
        if self.refresh_token and self.client_id and self.client_secret:
            self._access_token = ""

    def _auth_headers(self) -> Dict[str, str]:
        if self.api_key:
            # On-premises technician key. Sent under both header names AssetExplorer
            # accepts across releases so the same key works old and new.
            return {"TECHNICIAN_KEY": self.api_key, "authtoken": self.api_key}
        self._ensure_access_token()
        return {"Authorization": f"Zoho-oauthtoken {self._access_token}"}

    # -- envelope handling --------------------------------------------------

    @staticmethod
    def _check_status(payload: Any) -> Any:
        """Return the payload, raising on a non-success ``response_status``.

        AssetExplorer wraps every reply with ``response_status`` and — like many
        ManageEngine APIs — often returns HTTP 200 even for API errors, signalling
        failure only through ``status_code`` (2000 = success). So the envelope is
        always inspected here.
        """
        if not isinstance(payload, dict):
            return payload
        status = payload.get("response_status")
        # response_status can be a dict or a single-item list of dicts.
        if isinstance(status, list):
            status = status[0] if status else None
        if isinstance(status, dict):
            code = status.get("status_code")
            if code not in (None, 2000, "2000"):
                messages = status.get("messages")
                msg = ""
                if isinstance(messages, list) and messages:
                    first = messages[0]
                    if isinstance(first, dict):
                        msg = first.get("message") or first.get("status_code") or ""
                    else:
                        msg = str(first)
                msg = msg or status.get("status") or f"status_code {code}"
                raise RuntimeError(f"AssetExplorer API error: {msg}")
        return payload

    # -- low-level request --------------------------------------------------

    def _request(self, method: str, path: str, *, params: Optional[dict] = None,
                 body: Optional[dict] = None, retry_auth: bool = True) -> Any:
        """Issue one HTTP request and return the parsed, status-checked body.

        A 401 on an OAuth connection triggers a single token refresh + retry, so an
        access token that expired mid-fetch is transparently renewed.
        """
        url = self.url_for(path)
        query = dict(params or {})
        if query:
            url = f"{url}?{urlencode(query)}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        headers.update(self._auth_headers())
        if data is not None:
            headers["Content-Type"] = "application/json"

        if requests is not None:
            session = self._session or requests
            resp = session.request(
                method, url, data=data, headers=headers,
                verify=self.verify_certs, timeout=self.request_timeout,
            )
            if resp.status_code == 401 and retry_auth and not self.api_key:
                self.refresh_access_token()
                return self._request(method, path, params=params, body=body,
                                     retry_auth=False)
            if resp.status_code in (401, 403):
                raise AssetExplorerConfigError(
                    f"authentication/permission failed (HTTP {resp.status_code}) — "
                    "check the AssetExplorer credentials and the technician's API "
                    "scope / role"
                )
            resp.raise_for_status()
            text = resp.text
            parsed = json.loads(text) if text else {}
            return self._check_status(parsed)

        # urllib fallback.
        if self._opener is None:
            self._opener = build_opener()
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.request_timeout) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as exc:  # pragma: no cover - network dependent
            if exc.code == 401 and retry_auth and not self.api_key:
                self.refresh_access_token()
                return self._request(method, path, params=params, body=body,
                                     retry_auth=False)
            if exc.code in (401, 403):
                raise AssetExplorerConfigError(
                    f"authentication/permission failed (HTTP {exc.code}) — "
                    "check the AssetExplorer credentials and permissions"
                )
            raise
        parsed = json.loads(payload) if payload else {}
        return self._check_status(parsed)

    # -- public primitives --------------------------------------------------

    def get(self, path: str, *, input_data: Optional[dict] = None) -> Any:
        """GET an AssetExplorer resource; returns the status-checked body.

        ``input_data`` (a dict) is JSON-encoded into the ``input_data`` query
        parameter, as the v3 API expects for filtered / paged reads.
        """
        params = {"input_data": json.dumps(input_data)} if input_data is not None else None
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict) -> Any:
        """POST to an AssetExplorer endpoint; returns the status-checked body."""
        return self._request("POST", path, body=body)

    @staticmethod
    def _extract_list(payload: Any, resource_key: str) -> List[Dict[str, Any]]:
        """Pull the record list out of a v3 list response.

        The records live under the resource key (``assets``, ``contracts``, …). Some
        endpoints (notably CMDB CI types) key the list by the CI type name, so when
        the expected key is absent the first list-valued, non-metadata key is used.
        """
        if not isinstance(payload, dict):
            return payload if isinstance(payload, list) else []
        records = payload.get(resource_key)
        if isinstance(records, list):
            return [r for r in records if isinstance(r, dict)]
        for key, value in payload.items():
            if key in ("response_status", "list_info"):
                continue
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return []

    def list(
        self,
        path: str,
        resource_key: str,
        *,
        list_info: Optional[dict] = None,
        page_size: int = LIST_PAGE_SIZE,
        max_records: int = LIST_MAX_RECORDS,
    ) -> List[Dict[str, Any]]:
        """Page a v3 list endpoint and return every record.

        Pages with ``list_info.start_index`` / ``row_count`` until the reply's
        ``list_info.has_more_rows`` is false (or ``max_records`` is hit). Extra
        ``list_info`` keys — ``search_criteria``, ``fields_required``, ``sort_field``
        — are passed through unchanged.

        Resilience mirrors the other adapters: a failure on the **first** page is
        raised (a real error — bad credentials, wrong endpoint, unreachable host);
        a failure on a **later** page returns the records gathered so far, so a big
        estate yields partial data rather than nothing.
        """
        records: List[Dict[str, Any]] = []
        start = 1  # AssetExplorer list_info is 1-indexed
        base_info = dict(list_info or {})
        while True:
            info = dict(base_info)
            info.update({
                "start_index": start,
                "row_count": page_size,
                "get_total_count": True,
            })
            try:
                payload = self.get(path, input_data={"list_info": info})
            except Exception:
                if start == 1:
                    raise  # first page failing is a genuine error — surface it
                break      # later page failed — keep what we already have
            page = self._extract_list(payload, resource_key)
            records.extend(page)
            if len(records) >= max_records:
                break
            has_more = False
            if isinstance(payload, dict):
                li = payload.get("list_info")
                if isinstance(li, dict):
                    has_more = bool(li.get("has_more_rows"))
            if not has_more:
                break
            if len(page) < page_size:
                break
            start += page_size
        return records[:max_records]


def build_client(
    *,
    host: str,
    portal: str = "",
    access_token: str = "",
    refresh_token: str = "",
    client_id: str = "",
    client_secret: str = "",
    api_key: str = "",
    accounts_url: str = "https://accounts.zoho.com",
    verify_certs: bool = True,
    request_timeout: int = 60,
) -> AssetExplorerClient:
    """Construct an AssetExplorerClient from explicit settings (no network contact)."""
    return AssetExplorerClient(
        host=host,
        portal=portal,
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        api_key=api_key,
        accounts_url=accounts_url,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
    )


def build_client_from_env() -> AssetExplorerClient:
    """Construct an AssetExplorerClient from environment variables.

    Raises AssetExplorerConfigError with actionable guidance when the required host
    or credentials are absent.
    """
    host = _first_env("AE_HOST", "ASSETEXPLORER_HOST", "AE_HOSTNAME")
    portal = _first_env("AE_PORTAL", "ASSETEXPLORER_PORTAL") or ""
    access_token = _first_env("AE_ACCESS_TOKEN", "ASSETEXPLORER_ACCESS_TOKEN") or ""
    refresh_token = _first_env("AE_REFRESH_TOKEN", "ASSETEXPLORER_REFRESH_TOKEN") or ""
    client_id = _first_env("AE_CLIENT_ID", "ASSETEXPLORER_CLIENT_ID") or ""
    client_secret = _first_env("AE_CLIENT_SECRET", "ASSETEXPLORER_CLIENT_SECRET") or ""
    api_key = _first_env("AE_API_KEY", "ASSETEXPLORER_API_KEY", "AE_TECHNICIAN_KEY") or ""
    has_oauth = bool(access_token or (refresh_token and client_id and client_secret))
    if not host or not (has_oauth or api_key):
        raise AssetExplorerConfigError(
            "no AssetExplorer credentials found — set them in the UI, or export "
            "AE_HOST plus either AE_ACCESS_TOKEN (or AE_REFRESH_TOKEN with "
            "AE_CLIENT_ID/AE_CLIENT_SECRET) for Cloud, or AE_API_KEY for "
            "on-premises; see .env.example"
        )
    return build_client(
        host=host,
        portal=portal,
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        api_key=api_key,
        accounts_url=_first_env("AE_ACCOUNTS_URL") or "https://accounts.zoho.com",
        verify_certs=_as_bool(_first_env("AE_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("AE_REQUEST_TIMEOUT") or "60"),
    )


def ping(client: AssetExplorerClient) -> dict:
    """Verify connectivity/credentials and return a short connection summary.

    Reads a single asset page (``GET /api/v3/assets`` with row_count=1) — the
    lightest call that exercises auth and returns the estate's total asset count
    from ``list_info.total_count``. A 401/403 surfaces as an authentication error.
    """
    try:
        payload = client.get(
            "assets",
            input_data={"list_info": {"row_count": 1, "start_index": 1,
                                      "get_total_count": True}},
        )
    except AssetExplorerConfigError:
        raise
    except Exception as exc:  # pragma: no cover - network dependent
        raise AssetExplorerConfigError(
            f"could not reach the AssetExplorer API at {client.host} — {exc}"
        )

    total = ""
    if isinstance(payload, dict):
        li = payload.get("list_info")
        if isinstance(li, dict):
            total = li.get("total_count")
            total = "" if total is None else str(total)

    auth = "technician key" if client.api_key else "OAuth"
    summary = f"AssetExplorer @ {client.host}"
    if client.portal:
        summary += f" · portal {client.portal}"
    summary += f" · {auth}"
    if total:
        summary += f" · {total} assets"
    return {
        "product": "ManageEngine AssetExplorer",
        "host": client.host,
        "portal": client.portal,
        "auth": auth,
        "total_assets": total,
        "summary": summary,
    }
