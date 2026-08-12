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


def build_client_from_env() -> Elasticsearch:
    """Construct an Elasticsearch client from environment variables.

    Raises ConnectionConfigError with an actionable message if the required
    connection target or credentials are absent.
    """
    url = _first_env("ELASTICSEARCH_URL", "ES_URL")
    cloud_id = _first_env("ELASTIC_CLOUD_ID", "ES_CLOUD_ID")
    api_key = _first_env("ELASTIC_API_KEY", "ES_API_KEY")
    username = _first_env("ELASTIC_USERNAME", "ES_USERNAME")
    password = _first_env("ELASTIC_PASSWORD", "ES_PASSWORD")
    ca_certs = _first_env("ELASTIC_CA_CERTS", "ES_CA_CERTS")
    verify_certs = _as_bool(_first_env("ELASTIC_VERIFY_CERTS", "ES_VERIFY_CERTS"), True)
    timeout = int(_first_env("ELASTIC_REQUEST_TIMEOUT", "ES_REQUEST_TIMEOUT") or "60")

    kwargs: dict = {}
    if cloud_id:
        kwargs["cloud_id"] = cloud_id
    elif url:
        kwargs["hosts"] = [url]
    else:
        raise ConnectionConfigError(
            "no connection target set — export ELASTICSEARCH_URL or "
            "ELASTIC_CLOUD_ID (see .env.example)"
        )

    if api_key:
        kwargs["api_key"] = api_key
    elif username and password:
        kwargs["basic_auth"] = (username, password)
    else:
        raise ConnectionConfigError(
            "no credentials set — export ELASTIC_API_KEY, or both "
            "ELASTIC_USERNAME and ELASTIC_PASSWORD (see .env.example)"
        )

    kwargs["verify_certs"] = verify_certs
    if ca_certs:
        kwargs["ca_certs"] = ca_certs
    kwargs["request_timeout"] = timeout

    return Elasticsearch(**kwargs)


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
