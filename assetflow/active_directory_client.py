"""Microsoft Active Directory (AD DS) LDAP connection, built from a form or env.

This is the Active Directory analogue of ``client.py`` (Elasticsearch) and
``tufin_client.py`` (SecureTrack REST). On-prem AD DS is queried over **LDAP**
(``ldap://dc:389`` or ``ldaps://dc:636``); this module owns the bind, the
RootDSE discovery that resolves the directory's naming contexts, and a single
``search`` primitive. ``active_directory_runner.py`` turns registry resources
(``users``, ``groups``, ``dns_records`` …) into the actual searches and
normalizes the entries into the shared column/row shape.

Credentials are never hard-coded or committed; supply them via the web UI's
Connection panel or via environment variables (see ``.env.example``):

    AD_HOST                a domain controller host or IP
    AD_USERNAME            a bind account (``user@corp.local`` or ``CORP\\user``)
    AD_PASSWORD            that account's password

Optional:
    AD_BASE_DN             search base (default: RootDSE defaultNamingContext)
    AD_PORT                LDAP port (default 636 for LDAPS, else 389)
    AD_USE_SSL             "false" to use plain LDAP instead of LDAPS
    AD_VERIFY_CERTS        "false" to skip LDAPS certificate validation (lab only)
    AD_REQUEST_TIMEOUT     seconds (default 30)
    AD_PAGE_SIZE           LDAP paged-search page size (default 1000)

The LDAP work uses **ldap3**, which is an *optional* dependency: the module
imports and constructs without it, and only ``connect``/``ping``/``search``
require it (raising an actionable error when it is absent), mirroring how the
VMware adapter treats pyVmomi. The runner is driven entirely through the small
``search`` surface, so it is unit-tested with a fake client and no live DC.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - exercised only against a live DC
    import ldap3  # type: ignore
    from ldap3.core.exceptions import LDAPException  # type: ignore
except ImportError:  # pragma: no cover
    ldap3 = None
    LDAPException = Exception  # type: ignore


class ActiveDirectoryConfigError(RuntimeError):
    """Raised when required AD connection/credential settings are missing, or
    when ldap3 is needed but not installed."""


# Search scope tokens the runner passes; mapped to ldap3 constants at call time.
SCOPE_BASE = "base"
SCOPE_LEVEL = "level"
SCOPE_SUBTREE = "subtree"


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
    """Strip scheme, whitespace, port, and trailing slash from a host/URL.

    Accepts ``ldaps://dc.corp.local:636`` or a bare ``dc.corp.local`` and
    returns just the hostname, so the UI can be forgiving about what is pasted.
    """
    host = (host or "").strip().rstrip("/")
    for scheme in ("ldaps://", "ldap://", "https://", "http://"):
        if host.lower().startswith(scheme):
            host = host[len(scheme):]
            break
    # Drop a trailing :port if present (but keep IPv6 brackets intact).
    if not host.startswith("[") and host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def dns_partition_candidates(
    base_dn: str, root_domain_nc: str = "", advertised: Optional[List[str]] = None
) -> List[str]:
    """The DNS application-partition DNs to search for AD-integrated DNS.

    AD-integrated zones live in the **DomainDnsZones** (domain-replicated) and
    **ForestDnsZones** (forest-replicated) application partitions, with a legacy
    ``CN=MicrosoftDNS,CN=System`` container that on a modern DC holds only the
    ``RootDNSServers`` hints. We don't rely on the RootDSE *advertising* the app
    partitions (a plain bind may not, and ldap3 surfaces namingContexts
    separately), so the standard partition DNs are **derived** from the base /
    root-domain NCs and merged with any advertised ``*DnsZones*`` contexts. The
    result is de-duplicated and order-stable (advertised first, then derived,
    then legacy). Non-existent partitions are simply searched and return nothing.
    """
    parts: List[str] = []

    def _add(dn: str) -> None:
        if dn and dn not in parts:
            parts.append(dn)

    for nc in (advertised or []):
        if isinstance(nc, str) and "DnsZones" in nc:
            _add(nc)
    if base_dn:
        _add(f"DC=DomainDnsZones,{base_dn}")
    _add(f"DC=ForestDnsZones,{(root_domain_nc or base_dn)}")
    if base_dn:
        _add(f"CN=MicrosoftDNS,CN=System,{base_dn}")
    return parts


class Entry(dict):
    """A single LDAP entry: its ``dn``, decoded ``attributes`` (string values),
    and ``raw`` (bytes) for binary attributes the runner parses itself
    (``objectSid``, ``objectGUID``, ``userCertificate``, ``dnsRecord`` …).

    Kept as a plain dict subclass so tests can build entries literally.
    """

    def __init__(self, dn: str = "", attributes: Optional[dict] = None, raw: Optional[dict] = None):
        super().__init__(dn=dn, attributes=dict(attributes or {}), raw=dict(raw or {}))


class ActiveDirectoryClient:
    """Minimal AD DS LDAP client: bind, RootDSE discovery, paged search."""

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        base_dn: str = "",
        port: Optional[int] = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
        request_timeout: int = 30,
        page_size: int = 1000,
    ):
        host = clean_host(host)
        if not host:
            raise ActiveDirectoryConfigError(
                "no Active Directory host — provide a domain controller hostname or IP"
            )
        if not (username and password):
            raise ActiveDirectoryConfigError(
                "no credentials — provide a bind account (user@domain or DOMAIN\\user) "
                "and password"
            )
        self.host = host
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs
        self.port = int(port) if port else (636 if use_ssl else 389)
        self.request_timeout = request_timeout
        self.page_size = max(1, int(page_size or 1000))

        # Naming contexts, filled in by ``connect`` from the RootDSE. Callers may
        # pass an explicit base_dn; otherwise defaultNamingContext is used.
        self.base_dn = (base_dn or "").strip()
        self.config_nc = ""
        self.schema_nc = ""
        self.root_domain_nc = ""
        # AD-integrated DNS application partitions (present when DNS is AD-hosted).
        self.dns_partitions: List[str] = []
        self._root_dse: Dict[str, Any] = {}
        self._conn = None

    # -- connection ---------------------------------------------------------

    def _server(self):  # pragma: no cover - requires ldap3 + a live DC
        if ldap3 is None:
            raise ActiveDirectoryConfigError(
                "the Active Directory adapter needs the 'ldap3' package — "
                "install it with `pip install ldap3` (or from an offline wheel)"
            )
        tls = None
        if self.use_ssl:
            import ssl

            validate = ssl.CERT_REQUIRED if self.verify_certs else ssl.CERT_NONE
            tls = ldap3.Tls(validate=validate)
        return ldap3.Server(
            self.host,
            port=self.port,
            use_ssl=self.use_ssl,
            get_info=ldap3.ALL,
            tls=tls,
            connect_timeout=self.request_timeout,
        )

    def connect(self) -> Dict[str, Any]:  # pragma: no cover - live DC only
        """Bind to the DC and read the RootDSE to discover the naming contexts.

        Returns a short connection-info dict; raises ``ActiveDirectoryConfigError``
        with actionable text on any bind/credential/TLS failure.
        """
        if ldap3 is None:
            raise ActiveDirectoryConfigError(
                "the Active Directory adapter needs the 'ldap3' package — "
                "install it with `pip install ldap3`"
            )
        try:
            conn = ldap3.Connection(
                self._server(),
                user=self.username,
                password=self.password,
                authentication=ldap3.NTLM if "\\" in self.username else ldap3.SIMPLE,
                auto_bind=True,
                receive_timeout=self.request_timeout,
            )
        except LDAPException as exc:
            raise ActiveDirectoryConfigError(
                f"could not bind to Active Directory at {self.host}:{self.port} — "
                f"check the host, credentials, and LDAPS/TLS settings ({exc})"
            )
        self._conn = conn
        info = getattr(conn.server, "info", None)
        root = self._read_root_dse(info)
        self._apply_naming_contexts(root)
        return {
            "product": "Microsoft Active Directory",
            "host": self.host,
            "base_dn": self.base_dn,
            "summary": f"Active Directory @ {self.host} ({self.base_dn or 'unknown base'})",
        }

    def _read_root_dse(self, info) -> Dict[str, Any]:  # pragma: no cover - live DC
        """Pull the RootDSE attributes ldap3 already fetched into server.info."""
        root: Dict[str, Any] = {}
        if info is None:
            return root
        for key in (
            "defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
            "rootDomainNamingContext", "dnsHostName", "ldapServiceName",
            "domainFunctionality", "forestFunctionality", "namingContexts",
        ):
            val = getattr(info, key.lower(), None) or (info.other or {}).get(key)
            if val is not None:
                root[key] = val[0] if isinstance(val, list) and len(val) == 1 else val
        # ldap3 parses namingContexts into its own DsaInfo attribute
        # (naming_contexts) rather than leaving it in `other`, so read it there;
        # the app partitions (Domain/ForestDnsZones) are not in `other`.
        nc = getattr(info, "naming_contexts", None)
        if nc:
            root["namingContexts"] = list(nc)
        self._root_dse = root
        return root

    def _apply_naming_contexts(self, root: Dict[str, Any]) -> None:
        """Resolve base/config/schema/DNS partitions from RootDSE values."""
        if not self.base_dn:
            self.base_dn = str(root.get("defaultNamingContext", "") or "")
        self.config_nc = str(root.get("configurationNamingContext", "") or "")
        self.schema_nc = str(root.get("schemaNamingContext", "") or "")
        self.root_domain_nc = str(root.get("rootDomainNamingContext", self.base_dn) or "")
        # AD-integrated DNS lives in the DomainDnsZones / ForestDnsZones
        # application partitions (plus a legacy System container). Derive these
        # rather than trusting the RootDSE to advertise them — see
        # ``dns_partition_candidates``.
        contexts = root.get("namingContexts") or []
        if isinstance(contexts, str):
            contexts = [contexts]
        self.dns_partitions = dns_partition_candidates(
            self.base_dn, self.root_domain_nc, contexts
        )

    def root_dse(self) -> Dict[str, Any]:
        return dict(self._root_dse)

    # -- search -------------------------------------------------------------

    def search(
        self,
        base_dn: str,
        ldap_filter: str,
        attributes: List[str],
        scope: str = SCOPE_SUBTREE,
        size_limit: int = 0,
    ) -> List[Entry]:  # pragma: no cover - requires ldap3 + a live DC
        """Run a paged LDAP search and return normalized :class:`Entry` records.

        Binary attributes come back under each entry's ``raw`` map (bytes), the
        rest under ``attributes`` (already stringified by ldap3). The runner reads
        ``raw`` for the attributes it decodes itself (SIDs, GUIDs, certs, DNS
        blobs) and ``attributes`` for everything else.
        """
        if self._conn is None:
            raise ActiveDirectoryConfigError("adapter is not connected")
        scope_const = {
            SCOPE_BASE: ldap3.BASE,
            SCOPE_LEVEL: ldap3.LEVEL,
            SCOPE_SUBTREE: ldap3.SUBTREE,
        }.get(scope, ldap3.SUBTREE)
        entries: List[Entry] = []
        try:
            generator = self._conn.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=scope_const,
                attributes=attributes,
                paged_size=self.page_size,
                size_limit=size_limit,
                generator=True,
            )
            for item in generator:
                if item.get("type") != "searchResEntry":
                    continue
                entries.append(
                    Entry(
                        dn=item.get("dn", ""),
                        attributes=dict(item.get("attributes", {})),
                        raw=dict(item.get("raw_attributes", {})),
                    )
                )
                if size_limit and len(entries) >= size_limit:
                    break
        except LDAPException as exc:
            raise ActiveDirectoryConfigError(
                f"LDAP search failed under {base_dn!r} — {exc}"
            )
        return entries


def build_client(
    *,
    host: str,
    username: str,
    password: str,
    base_dn: str = "",
    port: Optional[int] = None,
    use_ssl: bool = True,
    verify_certs: bool = True,
    request_timeout: int = 30,
    page_size: int = 1000,
) -> ActiveDirectoryClient:
    """Construct an ActiveDirectoryClient from explicit settings (no network)."""
    return ActiveDirectoryClient(
        host=host,
        username=username,
        password=password,
        base_dn=base_dn,
        port=port,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        request_timeout=request_timeout,
        page_size=page_size,
    )


def build_client_from_env() -> ActiveDirectoryClient:
    """Construct an ActiveDirectoryClient from environment variables.

    Raises ActiveDirectoryConfigError with actionable guidance when the required
    host or credentials are absent.
    """
    host = _first_env("AD_HOST", "AD_HOSTNAME", "ACTIVE_DIRECTORY_HOST", "LDAP_HOST")
    username = _first_env("AD_USERNAME", "AD_USER", "LDAP_USERNAME", "LDAP_BIND_DN")
    password = _first_env("AD_PASSWORD", "AD_PASS", "LDAP_PASSWORD")
    if not (host and username and password):
        raise ActiveDirectoryConfigError(
            "no Active Directory credentials found — set them in the UI, or export "
            "AD_HOST, AD_USERNAME and AD_PASSWORD; see .env.example"
        )
    use_ssl = _as_bool(_first_env("AD_USE_SSL", "AD_LDAPS"), True)
    raw_port = _first_env("AD_PORT", "LDAP_PORT")
    return build_client(
        host=host,
        username=username,
        password=password,
        base_dn=_first_env("AD_BASE_DN", "AD_SEARCH_BASE", "LDAP_BASE_DN") or "",
        port=int(raw_port) if raw_port else None,
        use_ssl=use_ssl,
        verify_certs=_as_bool(_first_env("AD_VERIFY_CERTS"), True),
        request_timeout=int(_first_env("AD_REQUEST_TIMEOUT") or "30"),
        page_size=int(_first_env("AD_PAGE_SIZE") or "1000"),
    )


def ping(client: ActiveDirectoryClient) -> dict:  # pragma: no cover - live DC only
    """Verify connectivity by binding and reading the RootDSE.

    Delegates to ``connect`` (which binds and resolves the naming contexts) and
    returns its short connection summary.
    """
    return client.connect()
