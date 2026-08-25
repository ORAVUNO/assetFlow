"""Fetch Microsoft Active Directory (AD DS) resources over LDAP and normalize
them to ``QueryResult``.

This is the Active Directory analogue of ``runner.py`` / ``tufin_runner.py`` /
``vmware_runner.py``. Each registry query names a ``resource`` (``users``,
``groups``, ``organizational_units``, ``certificate_templates``,
``dns_records`` …); this runner dispatches on that name to a collector that
runs the right LDAP search(es) through the client's ``search`` primitive and
flattens the entries into the shared column/row shape
(:class:`assetflow.runner.QueryResult`) that the database, exports, and unified
inventory already understand.

Two things distinguish AD's data from the other adapters:

* **Identity assets.** User rows emit the identity columns the unified
  inventory keys the *Users* namespace on (``user.name``, ``user.principal_name``,
  ``user.email``, ``user.sid``); computer rows emit ``host.name`` / ``os.name``
  so they fold into the *Devices* namespace; DNS A/AAAA records emit
  ``host.name`` + ``host.ip`` so name→address records correlate to devices too.

* **Binary attributes.** AD returns SIDs, GUIDs, certificates
  (``userCertificate`` / ``cACertificate``), and DNS records (``dnsRecord``) as
  packed bytes. This module decodes them itself (see the parsers below) rather
  than relying on the LDAP layer, so the behaviour is deterministic and unit
  tested against a fake client with no live DC.

Certificate scope note: the LDAP-visible certificate data is the PKI *config*
(templates, enrollment services) plus *published* end-entity certs
(``userCertificate``). The full AD CS **issued-certificate inventory** lives in
the CA database, which is not exposed over LDAP — collect that from the CA
itself (``certutil -view`` / PSPKI). The registry entries say so.
"""

from __future__ import annotations

import binascii
import hashlib
import struct
import warnings
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import active_directory_client as ad_client_mod
from .models import Query
from .runner import QueryResult

# Optional: rich X.509 parsing (subject/issuer/validity/EKU). Without it, certs
# still surface with a SHA-1 thumbprint and byte length — never dropped.
# A broken native backend (e.g. a bad cffi/pyo3 build) can raise a
# BaseException-derived panic rather than ImportError, so guard on BaseException
# and degrade to thumbprint-only certificate summaries.
try:  # pragma: no cover - exercised when cryptography is installed
    from cryptography import x509  # type: ignore
except BaseException:  # pragma: no cover  # noqa: BLE001
    x509 = None


# --------------------------------------------------------------------------- #
# userAccountControl flags, groupType flags, and EKU OID names
# --------------------------------------------------------------------------- #

UAC_ACCOUNTDISABLE = 0x0002

GROUP_SCOPE_FLAGS = [(0x00000002, "Global"), (0x00000004, "Domain Local"), (0x00000008, "Universal")]
GROUP_SECURITY_FLAG = 0x80000000  # set = security group, clear = distribution

# The EKU OIDs that matter for reading a certificate/template's *purpose*. The
# Server Authentication OID is the "this is an SSL/TLS certificate" marker.
EKU_NAMES: Dict[str, str] = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "2.5.29.37.0": "Any Purpose",
}
SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"

# DNS record type numbers (the ones worth naming; others fall back to "TYPE<n>").
DNS_TYPE_NAMES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME", 257: "CAA",
}


# --------------------------------------------------------------------------- #
# Entry field helpers (case-insensitive attribute access)
# --------------------------------------------------------------------------- #

def _attrs(entry: dict) -> dict:
    return entry.get("attributes", {}) if isinstance(entry, dict) else {}


def _raws(entry: dict) -> dict:
    return entry.get("raw", {}) if isinstance(entry, dict) else {}


def _ci_get(mapping: dict, key: str) -> Any:
    """Case-insensitive lookup (LDAP attribute names are case-insensitive)."""
    if key in mapping:
        return mapping[key]
    lk = key.lower()
    for k, v in mapping.items():
        if k.lower() == lk:
            return v
    return None


def _vals(entry: dict, key: str) -> List[Any]:
    """All decoded values for an attribute as a list (empty when absent)."""
    value = _ci_get(_attrs(entry), key)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _val(entry: dict, *keys: str) -> str:
    """First non-empty decoded value across ``keys``, as a string."""
    for key in keys:
        for value in _vals(entry, key):
            text = _text(value)
            if text:
                return text
    return ""


def _raw_vals(entry: dict, key: str) -> List[bytes]:
    """Raw (bytes) values for a binary attribute as a list."""
    value = _ci_get(_raws(entry), key)
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out: List[bytes] = []
    for item in items:
        if isinstance(item, bytes):
            out.append(item)
        elif isinstance(item, str):
            out.append(item.encode("utf-8", "replace"))
    return out


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, list):
        return ", ".join(_text(v) for v in value[:6])
    return str(value)


def _cn_of(dn: str) -> str:
    """The leaf CN/OU/name of a distinguished name (``CN=Bob,OU=…`` → ``Bob``)."""
    head = (dn or "").split(",", 1)[0]
    return head.split("=", 1)[1] if "=" in head else head


# --------------------------------------------------------------------------- #
# Binary attribute parsers (SID, GUID, timestamps, groupType, certs, DNS)
# --------------------------------------------------------------------------- #

def format_sid(blob: bytes) -> str:
    """Render a binary objectSid as ``S-1-5-21-…`` (SDDL form)."""
    if not blob or len(blob) < 8:
        return ""
    revision = blob[0]
    sub_count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    sid = f"S-{revision}-{authority}"
    offset = 8
    for _ in range(sub_count):
        if offset + 4 > len(blob):
            break
        sid += f"-{int.from_bytes(blob[offset:offset + 4], 'little')}"
        offset += 4
    return sid


def format_guid(blob: bytes) -> str:
    """Render a binary objectGUID as its canonical ``{8-4-4-4-12}`` string."""
    if not blob or len(blob) < 16:
        return ""
    a = int.from_bytes(blob[0:4], "little")
    b = int.from_bytes(blob[4:6], "little")
    c = int.from_bytes(blob[6:8], "little")
    d = blob[8:10]
    e = blob[10:16]
    return f"{a:08x}-{b:04x}-{c:04x}-{d.hex()}-{e.hex()}"


def account_enabled(uac_value: Any) -> Optional[bool]:
    """Decode userAccountControl → enabled? (``None`` when the value is absent)."""
    try:
        uac = int(str(uac_value))
    except (TypeError, ValueError):
        return None
    return not bool(uac & UAC_ACCOUNTDISABLE)


def group_type_labels(group_type: Any) -> Tuple[str, str]:
    """Decode groupType → (scope, category), e.g. ("Global", "Security")."""
    try:
        gt = int(str(group_type))
    except (TypeError, ValueError):
        return "", ""
    # groupType is a signed 32-bit value; normalize the sign bit.
    gt &= 0xFFFFFFFF
    scope = next((label for flag, label in GROUP_SCOPE_FLAGS if gt & flag), "")
    category = "Security" if gt & GROUP_SECURITY_FLAG else "Distribution"
    return scope, category


def filetime_to_iso(value: Any) -> str:
    """Convert a Windows FILETIME (100ns ticks since 1601) to an ISO date-time.

    AD uses this for lastLogonTimestamp, pwdLastSet, accountExpires, etc. The
    sentinels 0 and 0x7FFFFFFFFFFFFFFF mean "never"/"unset" → blank. ldap3 with
    ALL info can also hand these back already decoded as datetimes/strings.
    """
    if isinstance(value, datetime):
        return _text(value)
    try:
        ticks = int(str(value))
    except (TypeError, ValueError):
        return _text(value)
    if ticks <= 0 or ticks >= 0x7FFFFFFFFFFFFFFF:
        return ""
    seconds = ticks / 10_000_000 - 11_644_473_600
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def gentime_to_iso(value: Any) -> str:
    """Convert an LDAP generalized time (``20230115080000.0Z``) to ISO.

    ldap3 often decodes whenCreated to a datetime already; handle both.
    """
    if isinstance(value, datetime):
        return _text(value)
    text = str(value or "").strip()
    if not text:
        return ""
    core = text.split(".", 1)[0].rstrip("Z")
    try:
        dt = datetime.strptime(core[:14], "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


def _eku_labels(oids: List[str]) -> List[str]:
    return [EKU_NAMES.get(oid, oid) for oid in oids]


def cert_summary(der: bytes) -> Dict[str, str]:
    """Summarize an X.509 certificate (DER bytes) into flat fields.

    Always yields a SHA-1 thumbprint and byte length; adds subject / issuer /
    serial / validity / EKUs when the optional ``cryptography`` package is
    present. ``is_server_auth`` marks the certs that are SSL/TLS (Server
    Authentication EKU) certificates.
    """
    out: Dict[str, str] = {
        "subject": "", "issuer": "", "serial": "", "not_before": "", "not_after": "",
        "thumbprint_sha1": hashlib.sha1(der).hexdigest().upper() if der else "",
        "ekus": "", "is_server_auth": "",
    }
    if x509 is None or not der:  # pragma: no cover - depends on optional dep
        return out
    try:  # pragma: no cover - exercised only with cryptography installed
        # Real-world certs carry non-standard DN attributes (e.g. a Country
        # value longer than 2 chars), and cryptography warns while still
        # rendering the string. Silence those benign RFC4514 warnings so the
        # server console isn't spammed on a certificate fetch.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cert = x509.load_der_x509_certificate(der)
            out["subject"] = cert.subject.rfc4514_string()
            out["issuer"] = cert.issuer.rfc4514_string()
        out["serial"] = format(cert.serial_number, "x")
        out["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d")
        out["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            oids = [o.dotted_string for o in eku]
            out["ekus"] = ", ".join(_eku_labels(oids))
            out["is_server_auth"] = "true" if SERVER_AUTH_OID in oids else "false"
        except x509.ExtensionNotFound:
            pass
    except Exception:
        pass
    return out


# --- DNS dnsRecord blob parser --------------------------------------------- #
#
# The dnsRecord attribute packs a fixed header then type-specific data:
#   0  DataLength (u16 LE)   2  Type (u16 LE)     4  Version (u8)   5  Rank (u8)
#   6  Flags (u16 LE)        8  Serial (u32 LE)  12  TtlSeconds (u32 BE)
#  16  Reserved (u32)       20  Timestamp (u32)  24  Data (DataLength bytes)
# Names inside RDATA use DNS_COUNT_NAME: u8 total-len, u8 label-count, then each
# label as (u8 len + bytes).

def _read_count_name(data: bytes, offset: int) -> str:
    """Decode a DNS_COUNT_NAME starting at ``offset`` into a dotted name."""
    if offset + 2 > len(data):
        return ""
    label_count = data[offset + 1]
    pos = offset + 2
    labels: List[str] = []
    for _ in range(label_count):
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        labels.append(data[pos:pos + length].decode("utf-8", "replace"))
        pos += length
    return ".".join(labels)


def parse_dns_record(blob: bytes) -> Tuple[str, str, str]:
    """Parse one dnsRecord blob → (type_name, data_text, ttl_seconds).

    Handles the common record types (A, AAAA, NS, CNAME, PTR, MX, SRV, TXT,
    SOA); unknown types fall back to a hex dump of the RDATA so nothing is lost.
    """
    if not blob or len(blob) < 24:
        return "", "", ""
    data_len = struct.unpack_from("<H", blob, 0)[0]
    rtype = struct.unpack_from("<H", blob, 2)[0]
    ttl = struct.unpack_from(">I", blob, 12)[0]
    rdata = blob[24:24 + data_len]
    type_name = DNS_TYPE_NAMES.get(rtype, f"TYPE{rtype}")
    text = _parse_dns_rdata(rtype, rdata)
    return type_name, text, str(ttl)


def _parse_dns_rdata(rtype: int, rdata: bytes) -> str:
    if rtype == 1 and len(rdata) >= 4:  # A
        return ".".join(str(b) for b in rdata[:4])
    if rtype == 28 and len(rdata) >= 16:  # AAAA
        parts = [binascii.hexlify(rdata[i:i + 2]).decode() for i in range(0, 16, 2)]
        return ":".join(parts)
    if rtype in (2, 5, 12, 39):  # NS / CNAME / PTR / DNAME
        return _read_count_name(rdata, 0)
    if rtype == 15 and len(rdata) >= 2:  # MX
        pref = struct.unpack_from(">H", rdata, 0)[0]
        return f"{pref} {_read_count_name(rdata, 2)}"
    if rtype == 33 and len(rdata) >= 6:  # SRV
        priority, weight, port = struct.unpack_from(">HHH", rdata, 0)
        return f"{priority} {weight} {port} {_read_count_name(rdata, 6)}"
    if rtype == 16 and rdata:  # TXT (one or more length-prefixed strings)
        chunks: List[str] = []
        pos = 0
        while pos < len(rdata):
            length = rdata[pos]
            pos += 1
            chunks.append(rdata[pos:pos + length].decode("utf-8", "replace"))
            pos += length
        return " ".join(chunks)
    if rtype == 6 and len(rdata) >= 24:  # SOA — primary server + admin + serial
        primary = _read_count_name(rdata, 20)
        return f"primary={primary}"
    return binascii.hexlify(rdata).decode() if rdata else ""


# --------------------------------------------------------------------------- #
# Result assembly
# --------------------------------------------------------------------------- #

def _result(columns: List[str], rows: List[List[Any]], limit: Optional[int]) -> QueryResult:
    if limit is not None:
        rows = rows[: int(limit)]
    return QueryResult(columns=[{"name": c} for c in columns], rows=rows)


def _search(client, base_dn: str, ldap_filter: str, attributes: List[str],
            scope: str = ad_client_mod.SCOPE_SUBTREE) -> List[dict]:
    """Search helper that tolerates a missing base (returns [] rather than raise).

    A container like the PKI or DNS partitions may not exist on every estate;
    treating an absent subtree as "no rows" keeps a fetch-all robust, the way
    the other adapters degrade optional endpoints to empty results.
    """
    if not base_dn:
        return []
    try:
        return client.search(base_dn, ldap_filter, attributes, scope=scope)
    except ad_client_mod.ActiveDirectoryConfigError:
        raise
    except Exception:  # pragma: no cover - network/endpoint dependent
        return []


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _collect_users(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """Every user account, with the identity columns the Users inventory keys on."""
    columns = [
        "user.name", "user.principal_name", "user.email", "user.display_name",
        "title", "department", "company", "manager", "enabled", "user.sid",
        "when_created", "last_logon", "distinguished_name",
    ]
    base = base_dn or client.base_dn
    entries = _search(
        client, base,
        "(&(objectCategory=person)(objectClass=user))",
        ["sAMAccountName", "userPrincipalName", "mail", "displayName", "title",
         "department", "company", "manager", "userAccountControl", "objectSid",
         "whenCreated", "lastLogonTimestamp", "distinguishedName"],
    )
    rows = []
    for e in entries:
        enabled = account_enabled(_val(e, "userAccountControl"))
        sid_raw = _raw_vals(e, "objectSid")
        rows.append([
            _val(e, "sAMAccountName"),
            _val(e, "userPrincipalName"),
            _val(e, "mail"),
            _val(e, "displayName"),
            _val(e, "title"),
            _val(e, "department"),
            _val(e, "company"),
            _cn_of(_val(e, "manager")),
            "" if enabled is None else ("true" if enabled else "false"),
            format_sid(sid_raw[0]) if sid_raw else "",
            gentime_to_iso(_val(e, "whenCreated")),
            filetime_to_iso(_val(e, "lastLogonTimestamp")),
            _val(e, "distinguishedName") or e.get("dn", ""),
        ])
    return columns, rows


def _collect_groups(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "group.name", "group.scope", "group.category", "description",
        "member.count", "group.sid", "managed_by", "when_created", "distinguished_name",
    ]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(objectClass=group)",
        ["sAMAccountName", "cn", "groupType", "description", "member", "objectSid",
         "managedBy", "whenCreated", "distinguishedName"],
    )
    rows = []
    for e in entries:
        scope, category = group_type_labels(_val(e, "groupType"))
        sid_raw = _raw_vals(e, "objectSid")
        rows.append([
            _val(e, "sAMAccountName", "cn"),
            scope,
            category,
            _val(e, "description"),
            str(len(_vals(e, "member"))),
            format_sid(sid_raw[0]) if sid_raw else "",
            _cn_of(_val(e, "managedBy")),
            gentime_to_iso(_val(e, "whenCreated")),
            _val(e, "distinguishedName") or e.get("dn", ""),
        ])
    return columns, rows


def _collect_group_members(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """One row per (group, member) — the expanded membership edges."""
    columns = ["group.name", "member.name", "member.dn"]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(objectClass=group)",
        ["sAMAccountName", "cn", "member"],
    )
    rows = []
    for e in entries:
        group_name = _val(e, "sAMAccountName", "cn")
        for member_dn in _vals(e, "member"):
            dn = _text(member_dn)
            rows.append([group_name, _cn_of(dn), dn])
    return columns, rows


def _collect_organizational_units(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    columns = ["ou.name", "distinguished_name", "description", "managed_by", "when_created"]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(objectClass=organizationalUnit)",
        ["ou", "name", "description", "managedBy", "whenCreated", "distinguishedName"],
    )
    rows = []
    for e in entries:
        dn = _val(e, "distinguishedName") or e.get("dn", "")
        rows.append([
            _val(e, "ou", "name") or _cn_of(dn),
            dn,
            _val(e, "description"),
            _cn_of(_val(e, "managedBy")),
            gentime_to_iso(_val(e, "whenCreated")),
        ])
    return columns, rows


def _collect_computers(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """Every computer account — a *device*, so it emits host.name / os.name."""
    columns = [
        "host.name", "os.name", "os.version", "dns.hostname", "enabled",
        "host.id", "when_created", "last_logon", "distinguished_name",
    ]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(objectClass=computer)",
        ["dNSHostName", "name", "cn", "operatingSystem", "operatingSystemVersion",
         "userAccountControl", "objectGUID", "whenCreated", "lastLogonTimestamp",
         "distinguishedName"],
    )
    rows = []
    for e in entries:
        enabled = account_enabled(_val(e, "userAccountControl"))
        guid_raw = _raw_vals(e, "objectGUID")
        rows.append([
            _val(e, "dNSHostName", "name", "cn"),
            _val(e, "operatingSystem"),
            _val(e, "operatingSystemVersion"),
            _val(e, "dNSHostName"),
            "" if enabled is None else ("true" if enabled else "false"),
            format_guid(guid_raw[0]) if guid_raw else "",
            gentime_to_iso(_val(e, "whenCreated")),
            filetime_to_iso(_val(e, "lastLogonTimestamp")),
            _val(e, "distinguishedName") or e.get("dn", ""),
        ])
    return columns, rows


def _collect_job_titles(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """Distinct job titles across users with a headcount per title (a summary)."""
    columns = ["title", "user.count"]
    base = base_dn or client.base_dn
    entries = _search(
        client, base,
        "(&(objectCategory=person)(objectClass=user)(title=*))",
        ["title"],
    )
    counts: Dict[str, int] = {}
    for e in entries:
        title = _val(e, "title")
        if title:
            counts[title] = counts.get(title, 0) + 1
    rows = [[title, str(n)] for title, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return columns, rows


def _collect_domain(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """The domain object (the estate's single 'account/tenant' — on-prem = domain)."""
    columns = [
        "domain.dn", "domain.name", "domain.sid", "forest.dn",
        "domain.functional_level", "forest.functional_level", "when_created",
    ]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(objectClass=domainDNS)",
        ["objectSid", "whenCreated", "distinguishedName"],
        scope=ad_client_mod.SCOPE_BASE,
    )
    root = client.root_dse() if hasattr(client, "root_dse") else {}

    def _dn_to_dns(dn: str) -> str:
        return ".".join(p[3:] for p in dn.split(",") if p.upper().startswith("DC="))

    rows = []
    for e in entries:
        dn = _val(e, "distinguishedName") or e.get("dn", "") or base
        sid_raw = _raw_vals(e, "objectSid")
        rows.append([
            dn,
            _dn_to_dns(dn),
            format_sid(sid_raw[0]) if sid_raw else "",
            str(root.get("rootDomainNamingContext", "")),
            str(root.get("domainFunctionality", "")),
            str(root.get("forestFunctionality", "")),
            gentime_to_iso(_val(e, "whenCreated")),
        ])
    if not rows and base:  # degrade to a single row from the base DN alone
        rows.append([base, _dn_to_dns(base), "",
                     str(root.get("rootDomainNamingContext", "")),
                     str(root.get("domainFunctionality", "")),
                     str(root.get("forestFunctionality", "")), ""])
    return columns, rows


def _collect_managed_service_accounts(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """gMSA / sMSA accounts — the on-prem 'managed identities'."""
    columns = ["msa.name", "msa.type", "dns.hostname", "enabled", "when_created", "distinguished_name"]
    base = base_dn or client.base_dn
    entries = _search(
        client, base,
        "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))",
        ["sAMAccountName", "cn", "objectClass", "dNSHostName", "userAccountControl",
         "whenCreated", "distinguishedName"],
    )
    rows = []
    for e in entries:
        classes = [c.lower() for c in (_text(v) for v in _vals(e, "objectClass"))]
        msa_type = "gMSA" if any("group" in c for c in classes) else "sMSA"
        enabled = account_enabled(_val(e, "userAccountControl"))
        rows.append([
            _val(e, "sAMAccountName", "cn"),
            msa_type,
            _val(e, "dNSHostName"),
            "" if enabled is None else ("true" if enabled else "false"),
            gentime_to_iso(_val(e, "whenCreated")),
            _val(e, "distinguishedName") or e.get("dn", ""),
        ])
    return columns, rows


def _pki_base(client, container: str) -> str:
    """A Public Key Services container DN under the Configuration NC."""
    config_nc = getattr(client, "config_nc", "")
    if not config_nc:
        return ""
    return f"CN={container},CN=Public Key Services,CN=Services,{config_nc}"


def _collect_certificate_templates(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """AD CS certificate templates — including which ones issue SSL (Server
    Authentication) certificates. Read from the Configuration NC over LDAP."""
    columns = [
        "template.name", "template.display_name", "schema_version",
        "key_usage", "is_server_auth", "when_created",
    ]
    base = base_dn or _pki_base(client, "Certificate Templates")
    entries = _search(
        client, base, "(objectClass=pKICertificateTemplate)",
        ["cn", "displayName", "msPKI-Template-Schema-Version",
         "pKIExtendedKeyUsage", "whenCreated"],
    )
    rows = []
    for e in entries:
        oids = [_text(v) for v in _vals(e, "pKIExtendedKeyUsage")]
        labels = _eku_labels(oids)
        rows.append([
            _val(e, "cn"),
            _val(e, "displayName"),
            _val(e, "msPKI-Template-Schema-Version"),
            ", ".join(labels),
            "true" if SERVER_AUTH_OID in oids else "false",
            gentime_to_iso(_val(e, "whenCreated")),
        ])
    return columns, rows


def _collect_certificate_authorities(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """Enterprise CAs (enrollment services) published in AD, with the CA cert
    subject and how many templates each offers."""
    columns = [
        "ca.name", "dns.hostname", "ca.subject", "ca.not_after",
        "templates.offered", "distinguished_name",
    ]
    base = base_dn or _pki_base(client, "Enrollment Services")
    entries = _search(
        client, base, "(objectClass=pKIEnrollmentService)",
        ["cn", "dNSHostName", "cACertificate", "certificateTemplates", "distinguishedName"],
    )
    rows = []
    for e in entries:
        ca_raw = _raw_vals(e, "cACertificate")
        summary = cert_summary(ca_raw[0]) if ca_raw else {}
        rows.append([
            _val(e, "cn"),
            _val(e, "dNSHostName"),
            summary.get("subject", ""),
            summary.get("not_after", ""),
            str(len(_vals(e, "certificateTemplates"))),
            _val(e, "distinguishedName") or e.get("dn", ""),
        ])
    return columns, rows


def _collect_published_certificates(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """End-entity certificates published to AD (the ``userCertificate`` attribute
    on users/computers). This is the LDAP-visible cert slice; the full AD CS
    issued inventory lives in the CA database (certutil/PSPKI), not LDAP."""
    columns = [
        "owner", "subject", "issuer", "serial", "not_before", "not_after",
        "is_server_auth", "ekus", "thumbprint_sha1", "distinguished_name",
    ]
    base = base_dn or client.base_dn
    entries = _search(
        client, base, "(userCertificate=*)",
        ["cn", "sAMAccountName", "dNSHostName", "userCertificate", "distinguishedName"],
    )
    rows = []
    for e in entries:
        owner = _val(e, "sAMAccountName", "dNSHostName", "cn")
        dn = _val(e, "distinguishedName") or e.get("dn", "")
        for der in _raw_vals(e, "userCertificate"):
            s = cert_summary(der)
            rows.append([
                owner, s.get("subject", ""), s.get("issuer", ""), s.get("serial", ""),
                s.get("not_before", ""), s.get("not_after", ""), s.get("is_server_auth", ""),
                s.get("ekus", ""), s.get("thumbprint_sha1", ""), dn,
            ])
    return columns, rows


def _dns_bases(client) -> List[str]:
    partitions = list(getattr(client, "dns_partitions", []) or [])
    return partitions


def _collect_dns_zones(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """AD-integrated DNS zones (``dnsZone`` objects) across the DNS partitions."""
    columns = ["zone.name", "dns.partition", "when_created", "distinguished_name"]
    bases = [base_dn] if base_dn else _dns_bases(client)
    rows = []
    for base in bases:
        for e in _search(client, base, "(objectClass=dnsZone)",
                         ["name", "dc", "whenCreated", "distinguishedName"]):
            dn = _val(e, "distinguishedName") or e.get("dn", "")
            rows.append([
                _val(e, "name", "dc") or _cn_of(dn),
                base,
                gentime_to_iso(_val(e, "whenCreated")),
                dn,
            ])
    return columns, rows


def ptr_to_ip(record_name: str, zone: str) -> str:
    """Reconstruct the IP a reverse (PTR) record points at, from its position.

    A PTR node's identity *is* the address, reversed: ``22.168.18`` in zone
    ``172.in-addr.arpa`` is ``172.18.168.22``; an ``ip6.arpa`` name is 32
    reversed nibbles. Returns "" for classless-delegation (RFC 2317) or partial
    names that don't form a complete address.
    """
    parts = [] if record_name in ("@", "") else [record_name]
    full = ".".join(parts + [zone]).strip(".").lower()
    if full.endswith(".in-addr.arpa"):
        octets = full[: -len(".in-addr.arpa")].split(".")
        if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            return ".".join(reversed(octets))
    elif full.endswith(".ip6.arpa"):
        nibbles = full[: -len(".ip6.arpa")].split(".")
        if len(nibbles) == 32 and all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
            rev = list(reversed(nibbles))
            return ":".join("".join(rev[i:i + 4]) for i in range(0, 32, 4))
    return ""


def _collect_dns_records(client, base_dn: str = "") -> Tuple[List[str], List[List[Any]]]:
    """AD-integrated DNS records (``dnsNode`` objects), decoding each dnsRecord
    blob. Forward A/AAAA rows emit host.name/host.ip, and reverse PTR rows emit
    the target host.name plus the IP reconstructed from the reverse-zone name,
    so both directions fold into the Devices inventory."""
    columns = ["zone", "record.name", "record.type", "record.data", "ttl",
               "host.name", "host.ip"]
    bases = [base_dn] if base_dn else _dns_bases(client)
    rows = []
    for base in bases:
        for e in _search(client, base, "(objectClass=dnsNode)",
                         ["name", "dc", "dnsRecord", "distinguishedName"]):
            dn = _val(e, "distinguishedName") or e.get("dn", "")
            name = _val(e, "name", "dc") or _cn_of(dn)
            zone = _zone_from_dn(dn)
            fqdn = name if name in ("@", "") else f"{name}.{zone}" if zone else name
            for blob in _raw_vals(e, "dnsRecord"):
                rtype, data, ttl = parse_dns_record(blob)
                if not rtype:
                    continue
                if rtype in ("A", "AAAA"):
                    host_name, host_ip = fqdn, data
                elif rtype == "PTR":
                    # The PTR target is the host; the address is the reverse name.
                    host_name, host_ip = data, ptr_to_ip(name, zone)
                else:
                    host_name = host_ip = ""
                rows.append([zone, name, rtype, data, ttl, host_name, host_ip])
    return columns, rows


def _zone_from_dn(dn: str) -> str:
    """The zone name from a dnsNode DN (``DC=host,DC=corp.local,CN=MicrosoftDNS…``).

    The first DC= component after the record's own is the zone.
    """
    parts = [p for p in dn.split(",") if p.upper().startswith("DC=")]
    return parts[1][3:] if len(parts) >= 2 else (parts[0][3:] if parts else "")


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

_COLLECTORS: Dict[str, Callable[..., Tuple[List[str], List[List[Any]]]]] = {
    "users": _collect_users,
    "groups": _collect_groups,
    "group_members": _collect_group_members,
    "organizational_units": _collect_organizational_units,
    "computers": _collect_computers,
    "job_titles": _collect_job_titles,
    "domain": _collect_domain,
    "managed_service_accounts": _collect_managed_service_accounts,
    "certificate_templates": _collect_certificate_templates,
    "certificate_authorities": _collect_certificate_authorities,
    "published_certificates": _collect_published_certificates,
    "dns_zones": _collect_dns_zones,
    "dns_records": _collect_dns_records,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> QueryResult:
    """Fetch an Active Directory registry query's resource over LDAP.

    ``time_range`` is accepted for interface parity with the other adapters but
    AD inventory is a point-in-time snapshot, so it does not filter rows.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no Active Directory resource; "
            "nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown Active Directory resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    columns, rows = collector(client)
    return _result(columns, rows, limit)
