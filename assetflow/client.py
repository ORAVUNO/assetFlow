"""Elasticsearch connection built from environment variables / .env.

Credentials are never hard-coded or committed. Supply them via environment
variables (see ``.env.example``); ``python-dotenv`` loads a local ``.env`` if
present. Two connection styles and two auth styles are supported:

Connection (one required):
    ELASTICSEARCH_URL   e.g. https://my-host:9200
    ELASTIC_CLOUD_ID    the Cloud ID from Elastic Cloud

Auth (one required):
    ELASTIC_API_KEY                     a base64 API key
    ELASTIC_USERNAME + ELASTIC_PASSWORD basic auth

Optional:
    ELASTIC_CA_CERTS       path to a CA bundle for TLS verification
    ELASTIC_VERIFY_CERTS   "false" to disable TLS verification (not recommended)
    ELASTIC_REQUEST_TIMEOUT  seconds (default 60)
"""

from __future__ import annotations

import os
from typing import Optional

from elasticsearch import Elasticsearch


class ConnectionConfigError(RuntimeError):
    """Raised when required connection/credential settings are missing."""


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


def normalize_host(raw: str) -> str:
    """Turn a hostname/IP (or host:port, or full URL) into a client URL.

    A bare host gets ``https://`` and the default port 9200. A value that
    already includes a scheme is returned unchanged.
    """
    raw = (raw or "").strip()
    if not raw:
        return raw
    if "://" in raw:
        return raw
    hostpart = raw.split("/", 1)[0]
    if ":" in hostpart:  # host:port already given
        return f"https://{raw}"
    return f"https://{raw}:9200"


def build_client(
    *,
    url: Optional[str] = None,
    cloud_id: Optional[str] = None,
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ca_certs: Optional[str] = None,
    verify_certs: bool = True,
    request_timeout: int = 60,
) -> Elasticsearch:
    """Construct an Elasticsearch client from explicit settings.

    Raises ConnectionConfigError if a connection target or credentials are
    missing. This does not contact the cluster — call ``ping`` for that.
    """
    kwargs: dict = {}
    if cloud_id:
        kwargs["cloud_id"] = cloud_id
    elif url:
        kwargs["hosts"] = [url]
    else:
        raise ConnectionConfigError(
            "no connection target — provide a hostname/IP/URL or a Cloud ID"
        )

    if api_key:
        kwargs["api_key"] = api_key
    elif username and password:
        kwargs["basic_auth"] = (username, password)
    else:
        raise ConnectionConfigError(
            "no credentials — provide an API key, or a username and password"
        )

    kwargs["verify_certs"] = verify_certs
    if ca_certs:
        kwargs["ca_certs"] = ca_certs
    kwargs["request_timeout"] = request_timeout

    return Elasticsearch(**kwargs)


def build_client_from_env() -> Elasticsearch:
    """Construct an Elasticsearch client from environment variables.

    Raises ConnectionConfigError with an actionable message if the required
    connection target or credentials are absent.
    """
    try:
        return build_client(
            url=_first_env("ELASTICSEARCH_URL", "ES_URL"),
            cloud_id=_first_env("ELASTIC_CLOUD_ID", "ES_CLOUD_ID"),
            api_key=_first_env("ELASTIC_API_KEY", "ES_API_KEY"),
            username=_first_env("ELASTIC_USERNAME", "ES_USERNAME"),
            password=_first_env("ELASTIC_PASSWORD", "ES_PASSWORD"),
            ca_certs=_first_env("ELASTIC_CA_CERTS", "ES_CA_CERTS"),
            verify_certs=_as_bool(_first_env("ELASTIC_VERIFY_CERTS", "ES_VERIFY_CERTS"), True),
            request_timeout=int(_first_env("ELASTIC_REQUEST_TIMEOUT", "ES_REQUEST_TIMEOUT") or "60"),
        )
    except ConnectionConfigError:
        # Re-raise with env-specific guidance.
        raise ConnectionConfigError(
            "no Elasticsearch credentials found — set them in the UI, or export "
            "ELASTICSEARCH_URL/ELASTIC_CLOUD_ID plus ELASTIC_API_KEY (or "
            "ELASTIC_USERNAME + ELASTIC_PASSWORD); see .env.example"
        )


def ping(client: Elasticsearch) -> dict:
    """Verify connectivity and return basic cluster info.

    Raises the underlying elasticsearch exception on failure.
    """
    info = client.info()
    return {
        "name": info.get("name"),
        "cluster_name": info.get("cluster_name"),
        "version": info.get("version", {}).get("number"),
    }
