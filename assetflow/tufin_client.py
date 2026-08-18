"""Tufin SecureTrack REST connection, built from a form or environment.

This is the Tufin analogue of ``client.py`` (which builds an Elasticsearch
client). SecureTrack exposes a REST API rooted at::

    https://<securetrack_host>/securetrack/api/

authenticated with HTTP Basic auth (a SecureTrack API user). Credentials are
never hard-coded or committed; supply them via the web UI's Connection panel or
via environment variables (see ``.env.example``):

    TOS_HOSTNAME            the SecureTrack host or IP
    TOS_USERNAME            a SecureTrack API user
    TOS_PASSWORD            that user's password

Optional:
    TUFIN_BASE_PATH         API base path (default ``/securetrack/api``)
    TUFIN_VERIFY_CERTS      "false" to disable TLS verification (lab only)
    TUFIN_REQUEST_TIMEOUT   seconds (default 30)

Only a small ``get`` primitive lives here; ``tufin_runner.py`` turns registry
resources into the endpoint calls and normalizes the responses.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# The REST client uses the standard library (urllib) so the adapter has no hard
# third-party dependency; ``requests`` is used automatically when installed.
try:  # pragma: no cover - exercised indirectly
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class TufinConfigError(RuntimeError):
    """Raised when required Tufin connection/credential settings are missing."""


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
    return host


class TufinClient:
    """Minimal SecureTrack REST client (Basic auth, JSON responses)."""

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        base_path: str = "/securetrack/api",
        verify_certs: bool = True,
        request_timeout: int = 30,
    ):
        host = clean_host(host)
        if not host:
            raise TufinConfigError(
                "no Tufin host — provide the SecureTrack hostname or IP"
            )
        if not (username and password):
            raise TufinConfigError(
                "no credentials — provide a SecureTrack username and password"
            )
        self.host = host
        self.username = username
        self.password = password
        self.base_path = "/" + (base_path or "/securetrack/api").strip("/")
        self.verify_certs = verify_certs
        self.request_timeout = request_timeout
        self._token = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")

    def url_for(self, path: str) -> str:
        return f"https://{self.host}{self.base_path}/{path.strip('/')}"

    def get(self, path: str) -> Any:
        """GET a SecureTrack resource and return the parsed JSON body.

        Raises the underlying HTTP/URL error on failure so callers can decide
        whether to fall back to an alternate endpoint path.
        """
        url = self.url_for(path)
        headers = {
            "Authorization": f"Basic {self._token}",
            "Accept": "application/json",
        }
        if requests is not None:
            resp = requests.get(
                url,
                headers=headers,
                verify=self.verify_certs,
                timeout=self.request_timeout,
            )
            resp.raise_for_status()
            text = resp.text
            return json.loads(text) if text else {}

        request = Request(url, headers=headers, method="GET")
        context = None if self.verify_certs else ssl._create_unverified_context()
        with urlopen(request, timeout=self.request_timeout, context=context) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}


def build_client(
    *,
    host: str,
    username: str,
    password: str,
    base_path: str = "/securetrack/api",
    verify_certs: bool = True,
    request_timeout: int = 30,
) -> TufinClient:
    """Construct a TufinClient from explicit settings (no network contact)."""
    return TufinClient(
        host=host,
        username=username,
        password=password,
        base_path=base_path,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
    )


def build_client_from_env() -> TufinClient:
    """Construct a TufinClient from environment variables.

    Raises TufinConfigError with actionable guidance when the required host or
    credentials are absent.
    """
    host = _first_env("TOS_HOSTNAME", "TUFIN_HOST", "SECURETRACK_HOST")
    username = _first_env("TOS_USERNAME", "ST_API_USERNAME", "TUFIN_USERNAME")
    password = _first_env("TOS_PASSWORD", "ST_API_PASSWORD", "TUFIN_PASSWORD")
    if not (host and username and password):
        raise TufinConfigError(
            "no Tufin credentials found — set them in the UI, or export "
            "TOS_HOSTNAME, TOS_USERNAME and TOS_PASSWORD; see .env.example"
        )
    return build_client(
        host=host,
        username=username,
        password=password,
        base_path=_first_env("TUFIN_BASE_PATH") or "/securetrack/api",
        verify_certs=_as_bool(_first_env("TUFIN_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("TUFIN_REQUEST_TIMEOUT") or "30"),
    )


# SecureTrack endpoints used to confirm connectivity, tried in order. A bare
# device listing capped to one item is the lightest liveness probe.
_PING_PATHS = ("devices.json?count=1", "devices?count=1", "domains.json?count=1")


def ping(client: TufinClient) -> dict:
    """Verify connectivity and return a short connection summary.

    Tries the lightweight device/domain listings the SecureTrack API exposes;
    a 401/403 is surfaced as an authentication error rather than retried.
    """
    last_error: Optional[str] = None
    for path in _PING_PATHS:
        try:
            client.get(path)
        except HTTPError as exc:  # pragma: no cover - network dependent
            if exc.code in (401, 403):
                raise TufinConfigError(
                    f"authentication/permission failed (HTTP {exc.code}) — "
                    "check the SecureTrack username, password, and API access"
                )
            last_error = f"HTTP {exc.code}"
            continue
        except URLError as exc:  # pragma: no cover - network dependent
            last_error = str(getattr(exc, "reason", exc))
            continue
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
            continue
        return {
            "product": "Tufin SecureTrack",
            "host": client.host,
            "summary": f"SecureTrack @ {client.host}",
        }
    raise TufinConfigError(
        f"could not reach the SecureTrack API at {client.host} — {last_error or 'no response'}"
    )
