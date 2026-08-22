"""Fetch Tenable.sc (SecurityCenter) asset intelligence, normalized to ``QueryResult``.

This is the Tenable.sc analogue of ``tufin_runner.py`` / ``solarwinds_runner.py``.
Each registry query names a ``resource`` that this runner maps to one or more
Tenable.sc REST calls (through :class:`TenableScClient`) and flattens into the
same column/row shape (:class:`assetflow.runner.QueryResult`) the database,
exports, and unified host view already understand.

The resources cover the asset types the integration asked for:

* ``devices`` — the device inventory, from ``POST /rest/analysis`` with the
  ``sumip`` tool: one row per host with its IP / DNS / NetBIOS / MAC, OS,
  repository, vulnerability score and per-severity counts, and last scan times.
  Emits ``host.name`` so it folds into the *All Fetched Results* golden records.
* ``findings`` — aggregated security findings, from the ``vulndetails`` analysis
  tool: one row per (host, plugin) detection with severity, port/protocol,
  synopsis, solution, CVEs, CVSS/VPR scores, and first/last seen.
* ``software`` — installed software **linked to each host** (name / version split
  out), from the software-enumeration plugins (20811 / 22869) via ``vulndetails``.
* ``databases`` — running databases and their versions, **linked to each host**,
  from the "Databases" plugin family via ``vulndetails``.
* ``users`` — the Tenable.sc user accounts (``GET /rest/user``).
* ``asset_lists`` — the asset lists that model **asset tags / groupings** in
  Tenable.sc (``GET /rest/asset``), each with its ``tags`` field, type, owner,
  and member-IP count.
* ``alerts`` — configured alerts (``GET /rest/alert``).
* ``incidents`` — tickets, Tenable.sc's incident objects (``GET /rest/ticket``).
* ``saas_applications`` — a placeholder: Tenable.sc core does not enumerate SaaS
  applications (that is a Tenable One / Tenable.io capability), so this returns no
  rows and is marked accordingly in the registry.
* ``hosts`` — the unified host inventory from the Tenable Security Center 6.x
  *Explore Assets* endpoint (``GET /rest/hosts``): one row per asset in the 6.x
  asset model, carrying ACR / AES, repositories, and system type. The modern
  companion to ``devices`` (``sumip``).

**Custom fields & asset tags.** Two things the integration explicitly asked for:

1. Any field Tenable.sc returns for a device / finding that this runner does not
   map to a named column is still emitted, under a column prefixed ``custom.`` —
   the same convention the SolarWinds and VMware adapters use — so nothing is
   silently dropped and system fields are never confused with extra ones.
2. Each device row is enriched with the **asset lists (tags)** it belongs to, in
   a ``tags`` column, by building an IP → asset-name map from ``/rest/asset``
   (bounded and best-effort, so it degrades gracefully on large estates).
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# Prefix marking an unmapped (extra / site-specific) field, so it is never
# confused with the standard system columns.
CUSTOM_PREFIX = "custom."


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or default)
    except (TypeError, ValueError):
        return default


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() not in ("false", "0", "no", "off")


# How many asset lists to resolve into member IPs when stamping device tags. Each
# is now a single lightweight ``GET /rest/asset/{id}`` (its resolved viewableIPs),
# not a paginated analysis, so this is cheap — but still capped so a site with
# thousands of asset lists stays bounded. Override with TENABLE_SC_TAG_ASSET_CAP;
# disable device tag stamping entirely with TENABLE_SC_DEVICE_TAGS=false (the
# asset_lists resource still lists every tag). Asset-list metadata itself is never
# capped — only this per-device enrichment.
MAX_ASSET_LISTS_FOR_TAGS = _int_env("TENABLE_SC_TAG_ASSET_CAP", 200)
DEVICE_TAGS_ENABLED = _bool_env("TENABLE_SC_DEVICE_TAGS", True)

# Time-range tokens (from the UI) → number of days back, applied as a
# ``lastSeen`` filter on the vuln analysis resources (devices / findings).
RANGE_DAYS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}

# Plugin IDs whose output enumerates installed software per host, used by the
# host-linked ``software`` view so software correlates to a host/IP.
SOFTWARE_ENUM_PLUGINS = ("20811", "22869")  # Windows installed software, SSH software

# A version-looking token (2+ dotted numbers, optional trailing build/rev), used
# to split a software string into name + version.
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+(?:[-_.][0-9A-Za-z]+)*\b")
_CPE_RE = re.compile(r"cpe:/[aoh]:(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*)")


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

def textish(value: Any) -> str:
    """Render a Tenable.sc field as a compact string.

    Tenable.sc nests several fields as objects (``severity``, ``repository``,
    ``family``, ``role`` …); those are summarized to their human name.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(textish(item) for item in value[:8])
    if isinstance(value, dict):
        for key in ("name", "username", "description", "displayName", "value"):
            if value.get(key):
                return textish(value[key])
        return ", ".join(f"{k}={textish(v)}" for k, v in list(value.items())[:4])
    return str(value)


def _obj_name(value: Any) -> str:
    """Name of a nested object field (``{"id":.., "name":..}``) or its string."""
    if isinstance(value, dict):
        return textish(value.get("name") or value.get("username") or "")
    return textish(value)


def _pick(record: Dict[str, Any], *keys: str) -> Any:
    """First non-empty value among ``keys`` (for fields Tenable renames by release)."""
    for key in keys:
        val = record.get(key)
        if val not in (None, ""):
            return val
    return ""


def _repos(value: Any) -> str:
    """Summarize a repositories field (list of ``{id,name}`` or a single object)."""
    if isinstance(value, list):
        return ", ".join(_obj_name(v) for v in value if _obj_name(v))
    return _obj_name(value)


def _epoch(value: Any) -> str:
    """Convert a Tenable.sc epoch-seconds field to ISO-8601 UTC; '' when unset.

    Tenable.sc returns timestamps as Unix epoch seconds (often as strings), with
    ``-1`` / ``0`` meaning "never". Non-numeric values are returned unchanged so a
    field that is already a date string is not mangled.
    """
    if value in (None, "", "-1", "0", -1, 0):
        return ""
    try:
        secs = int(value)
    except (TypeError, ValueError):
        return textish(value)
    if secs <= 0:
        return ""
    try:
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):  # pragma: no cover - defensive
        return textish(value)


def _result(columns: List[str], rows: List[List[Any]], limit: Optional[int]) -> QueryResult:
    if limit is not None:
        rows = rows[: int(limit)]
    return QueryResult(columns=[{"name": c} for c in columns], rows=rows)


def _split_software(raw: str) -> Tuple[str, str, str]:
    """Split a software string into ``(name, version, cpe)``.

    Tenable software strings come in a few shapes; this normalizes the common ones
    and always preserves the original elsewhere (the caller keeps a raw column):

    * a CPE — ``cpe:/a:openbsd:openssh:8.0`` → name ``openbsd openssh``, version ``8.0``;
    * a Windows enumeration line — ``Google Chrome  [version 100.0.4896.75]`` →
      name ``Google Chrome``, version ``100.0.4896.75``;
    * an rpm/deb-ish token — ``openssh-server-8.0p1-13.el8`` → name ``openssh-server``,
      version ``8.0p1-13.el8``;
    * anything else — the trailing dotted-number token (if any) becomes the version
      and the text before it the name.
    """
    text = (raw or "").strip()
    if not text:
        return "", "", ""

    # 1) CPE form.
    m = _CPE_RE.search(text)
    if m:
        vendor = (m.group("vendor") or "").replace("_", " ").strip()
        product = (m.group("product") or "").replace("_", " ").strip()
        version = (m.group("version") or "").strip()
        name = " ".join(p for p in (vendor, product) if p) or text
        return name, version, m.group(0)

    # 2) Explicit "[version X]" / "(version X)" annotation.
    ver_annot = re.search(r"[\[(]\s*version\s+([^\])]+)[\])]", text, re.IGNORECASE)
    if ver_annot:
        version = ver_annot.group(1).strip()
        name = text[: ver_annot.start()].strip(" -\t")
        return name or text, version, ""

    # 3) Trailing dotted-number version token anywhere in the string.
    matches = list(_VERSION_RE.finditer(text))
    if matches:
        last = matches[-1]
        version = last.group(0)
        name = text[: last.start()].strip(" -_\t")
        # A leading "name-<version>" (rpm/deb) leaves a trailing dash — already stripped.
        return name or text, version, ""

    return text, "", ""


def _listing(response: Any) -> List[Dict[str, Any]]:
    """Normalize a Tenable.sc list endpoint's ``response`` into a flat record list.

    ``GET /rest/user`` returns a plain list; ``/rest/asset``, ``/rest/alert`` and
    ``/rest/ticket`` return ``{"usable": [...], "manageable": [...]}`` — the two
    overlap, so they are merged and de-duplicated by id.
    """
    if isinstance(response, list):
        return [r for r in response if isinstance(r, dict)]
    if not isinstance(response, dict):
        return []
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[Dict[str, Any]] = []
    buckets = []
    for key in ("usable", "manageable"):
        val = response.get(key)
        if isinstance(val, list):
            buckets.append(val)
    if not buckets:
        # Some endpoints return the list directly under ``response``.
        return []
    for bucket in buckets:
        for rec in bucket:
            if not isinstance(rec, dict):
                continue
            rid = str(rec.get("id", ""))
            if rid and rid in merged:
                continue
            if rid:
                merged[rid] = rec
            order.append(rec)
    return order


def _range_filters(time_range: Optional[str]) -> List[dict]:
    """A ``lastSeen`` analysis filter for a UI time-range token (empty for 'all')."""
    days = RANGE_DAYS.get((time_range or "").lower())
    if not days:
        return []
    # Tenable.sc lastSeen filter takes a "start:end" day-range in days-ago.
    return [{"filterName": "lastSeen", "operator": "=", "value": f"0:{days}"}]


# --------------------------------------------------------------------------- #
# Asset-tag enrichment (IP -> asset-list names)
# --------------------------------------------------------------------------- #

def _asset_records(client) -> List[Dict[str, Any]]:
    """All asset lists (``GET /rest/asset``) with the fields we surface."""
    fields = (
        "id,name,description,type,tags,owner,ownerGroup,groups,ipCount,"
        "assetDataFields,status,template,createdTime,modifiedTime"
    )
    try:
        response = client.get(f"asset?fields={fields}")
    except Exception:  # pragma: no cover - network/permission dependent
        try:
            response = client.get("asset")
        except Exception:
            return []
    return _listing(response)


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _ips_for_asset(client, asset_id: str) -> List[str]:
    """Resolved member IPs of one asset list.

    Uses a single lightweight ``GET /rest/asset/{id}`` and reads the resolved
    ``viewableIPs`` (which covers static *and* dynamic/DNS/combination lists —
    Tenable resolves membership for us), falling back to the static
    ``typeFields.definedIPs``. This replaces the previous per-asset ``sumip``
    analysis, which paginated and made the device fetch hang on real estates.
    """
    safe_id = str(asset_id)
    try:
        detail = client.get(f"asset/{safe_id}?fields=id,name,viewableIPs,typeFields")
    except Exception:  # pragma: no cover - network dependent
        return []
    if not isinstance(detail, dict):
        return []
    ips: List[str] = []

    def _harvest(blob: Any) -> None:
        if isinstance(blob, str):
            ips.extend(_IP_RE.findall(blob))
        elif isinstance(blob, list):
            for item in blob:
                _harvest(item)
        elif isinstance(blob, dict):
            for value in blob.values():
                _harvest(value)

    _harvest(detail.get("viewableIPs"))
    type_fields = detail.get("typeFields")
    if isinstance(type_fields, dict):
        _harvest(type_fields.get("definedIPs"))
    # De-duplicate, preserve order.
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _ip_tag_map(client, assets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Build ``ip -> [asset-list names]`` for device tag stamping (bounded, cheap).

    Best-effort: each asset list is resolved to its member IPs via one lightweight
    ``GET /rest/asset/{id}``. Capped at :data:`MAX_ASSET_LISTS_FOR_TAGS`; on any
    failure the affected asset simply contributes no tags. Disabled entirely when
    ``TENABLE_SC_DEVICE_TAGS=false``.
    """
    if not DEVICE_TAGS_ENABLED:
        return {}
    mapping: Dict[str, List[str]] = {}
    for asset in assets[:MAX_ASSET_LISTS_FOR_TAGS]:
        name = textish(asset.get("name"))
        asset_id = textish(asset.get("id"))
        if not (name and asset_id):
            continue
        for ip in _ips_for_asset(client, asset_id):
            names = mapping.setdefault(ip, [])
            if name not in names:
                names.append(name)
    return mapping


# --------------------------------------------------------------------------- #
# Generic analysis flattening (device / finding rows + custom.* extras)
# --------------------------------------------------------------------------- #

# A field spec is (output column, source key, transform). Every source key NOT
# listed in a resource's spec becomes a ``custom.<key>`` column, so extra fields
# Tenable.sc returns are captured rather than dropped.

_DEVICE_SPEC: Tuple[Tuple[str, str, Any], ...] = (
    ("host.ip", "ip", textish),
    ("host.dns", "dnsName", textish),
    ("host.netbios", "netbiosName", textish),
    ("host.mac", "macAddress", textish),
    ("os", "osCPE", textish),
    ("repository", "repository", _obj_name),
    # ACR (Asset Criticality Rating) and AES (Asset Exposure Score) are surfaced by
    # the sumip analysis in Tenable Security Center 6.x; ACR is editable in the
    # "Plus" licensing tier. Named here so they aren't buried in custom.*.
    ("acr", "acrScore", textish),
    ("aes", "assetExposureScore", textish),
    ("vuln.score", "score", textish),
    ("vuln.total", "total", textish),
    ("vuln.critical", "severityCritical", textish),
    ("vuln.high", "severityHigh", textish),
    ("vuln.medium", "severityMedium", textish),
    ("vuln.low", "severityLow", textish),
    ("vuln.info", "severityInfo", textish),
    ("last.auth.scan", "lastAuthRun", _epoch),
    ("last.unauth.scan", "lastUnauthRun", _epoch),
    ("policy.name", "policyName", textish),
    ("plugin.set", "pluginSet", textish),
    ("uuid", "uuid", textish),
)

_FINDING_SPEC: Tuple[Tuple[str, str, Any], ...] = (
    ("host.ip", "ip", textish),
    ("host.dns", "dnsName", textish),
    ("host.netbios", "netbiosName", textish),
    ("host.mac", "macAddress", textish),
    ("plugin.id", "pluginID", textish),
    ("plugin.name", "pluginName", textish),
    ("severity", "severity", _obj_name),
    ("family", "family", _obj_name),
    ("port", "port", textish),
    ("protocol", "protocol", textish),
    ("repository", "repository", _obj_name),
    ("cve", "cve", textish),
    ("cvss.base", "baseScore", textish),
    ("cvss.v3.base", "cvssV3BaseScore", textish),
    ("vpr.score", "vprScore", textish),
    ("risk.factor", "riskFactor", textish),
    ("synopsis", "synopsis", textish),
    ("solution", "solution", textish),
    ("first.seen", "firstSeen", _epoch),
    ("last.seen", "lastSeen", _epoch),
    ("exploit.available", "exploitAvailable", textish),
    ("has.been.mitigated", "hasBeenMitigated", textish),
)

# Source keys that carry the host name candidates (best → worst), used to build
# the leading ``host.name`` column so rows fold into the unified host view.
_HOST_NAME_KEYS = ("dnsName", "netbiosName", "ip", "uuid")

# Keys already surfaced by the specs (plus the host-name keys) — excluded from
# the ``custom.*`` sweep. Some plugin-text / raw fields are also excluded because
# they are huge and better read per-finding, not as a table column.
_FINDING_SKIP = {
    "pluginText", "description", "seeAlso", "pluginModDate", "pluginPubDate",
    "checkType", "vulnPubDate", "patchPubDate", "acceptRisk", "recastRisk",
    "bid", "xref", "stigSeverity", "informationalSeverity", "temporalScore",
}


def _host_name(record: Dict[str, Any]) -> str:
    for key in _HOST_NAME_KEYS:
        val = textish(record.get(key))
        if val:
            return val
    return ""


def _flatten_analysis(
    records: List[Dict[str, Any]],
    spec: Tuple[Tuple[str, str, Any], ...],
    *,
    lead_host_name: bool = True,
    tag_map: Optional[Dict[str, List[str]]] = None,
    skip_custom: Optional[set] = None,
) -> Tuple[List[str], List[List[Any]]]:
    """Flatten analysis records into (columns, rows) with a ``custom.*`` sweep.

    Standard columns come from ``spec``; every other key present on any record is
    appended as ``custom.<key>`` (discovered as the union across records, so
    site-specific extras ride along). When ``tag_map`` is given, a ``tags`` column
    is inserted listing the asset lists each host's IP belongs to.
    """
    mapped_keys = {src for _, src, _ in spec}
    skip = set(skip_custom or set()) | mapped_keys | set(_HOST_NAME_KEYS)

    # Discover extra (custom) keys as the union across records, keeping first-seen
    # order for stable columns.
    custom_keys: List[str] = []
    seen_custom = set()
    for rec in records:
        for key in rec.keys():
            if key in skip or key in seen_custom:
                continue
            # Skip nested list/dict blobs from the custom sweep — they are noise
            # in a flat table; the named specs pull the useful nested names out.
            if isinstance(rec.get(key), (list, dict)):
                continue
            seen_custom.add(key)
            custom_keys.append(key)

    columns: List[str] = []
    if lead_host_name:
        columns.append("host.name")
    columns.extend(out for out, _, _ in spec)
    if tag_map is not None:
        columns.append("tags")
    columns.extend(f"{CUSTOM_PREFIX}{k}" for k in custom_keys)

    rows: List[List[Any]] = []
    for rec in records:
        row: List[Any] = []
        if lead_host_name:
            row.append(_host_name(rec))
        for _, src, transform in spec:
            row.append(transform(rec.get(src)))
        if tag_map is not None:
            ip = textish(rec.get("ip"))
            row.append(", ".join(tag_map.get(ip, [])))
        for key in custom_keys:
            row.append(textish(rec.get(key)))
        rows.append(row)
    return columns, rows


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _collect_devices(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Device inventory via the ``sumip`` analysis tool, tagged with asset lists."""
    records = client.analysis("sumip", filters=_range_filters(time_range))
    # Best-effort asset-tag enrichment (IP -> asset-list names).
    tag_map: Dict[str, List[str]] = {}
    try:
        tag_map = _ip_tag_map(client, _asset_records(client))
    except Exception:  # pragma: no cover - enrichment is best-effort
        tag_map = {}
    columns, rows = _flatten_analysis(records, _DEVICE_SPEC, tag_map=tag_map)
    # Insert a constant asset.type after host.name so devices read as devices in
    # the unified inventory (Tenable.sc has no per-host role field).
    columns.insert(1, "asset.type")
    rows = [[r[0], "Host"] + r[1:] for r in rows]
    return columns, rows


def _collect_findings(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Aggregated security findings via the ``vulndetails`` analysis tool."""
    records = client.analysis("vulndetails", filters=_range_filters(time_range))
    return _flatten_analysis(records, _FINDING_SPEC, skip_custom=_FINDING_SKIP)


def _software_lines(plugin_text: str) -> List[str]:
    """Extract the individual software lines from a software-enumeration plugin's
    output (plugins 20811 / 22869), dropping the header/footer prose."""
    lines: List[str] = []
    for raw in str(plugin_text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        # Skip the plugin's framing sentences and section headers.
        if line.endswith(":") or low.startswith("the following") \
                or "installed on the remote" in low \
                or low.startswith("nessus") or low.startswith("note"):
            continue
        lines.append(line)
    return lines


def _collect_software(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Installed software, **linked to each host**, with name / version split out.

    Uses the software-enumeration plugins (20811 Windows, 22869 SSH) via the
    ``vulndetails`` analysis tool, so each row carries the host it was found on
    (``host.name`` / ``host.ip``) and one installed package — its ``software.name``
    and ``software.version`` parsed out of the long enumeration line (the original
    line is kept in ``software.raw``). This replaces the old estate-wide
    ``listsoftware`` view so software correlates to hosts in the unified inventory.
    """
    filters = list(_range_filters(time_range))
    filters.append({
        "filterName": "pluginID", "operator": "=",
        "value": ",".join(SOFTWARE_ENUM_PLUGINS),
    })
    records = client.analysis("vulndetails", filters=filters)
    columns = [
        "host.name", "host.ip", "host.dns", "software.name", "software.version",
        "software.raw", "plugin.id", "last.seen",
    ]
    rows: List[List[Any]] = []
    for rec in records:
        host = _host_name(rec)
        ip = textish(rec.get("ip"))
        dns = textish(rec.get("dnsName"))
        plugin_id = textish(rec.get("pluginID"))
        last_seen = _epoch(rec.get("lastSeen"))
        for line in _software_lines(rec.get("pluginText")):
            name, version, _cpe = _split_software(line)
            rows.append([host, ip, dns, name, version, line, plugin_id, last_seen])
    return columns, rows


def _plugin_family_id(client, name: str) -> str:
    """Resolve a plugin family name (e.g. "Databases") to its id; '' if not found."""
    try:
        response = client.get("pluginFamily?fields=id,name")
    except Exception:  # pragma: no cover - permission dependent
        return ""
    for rec in _listing(response) or (response if isinstance(response, list) else []):
        if isinstance(rec, dict) and textish(rec.get("name")).lower() == name.lower():
            return textish(rec.get("id"))
    return ""


def _collect_databases(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Running databases and their versions, **linked to each host**.

    Databases are detected by plugins in the "Databases" family; this fetches those
    detections via ``vulndetails`` (filtered to that family) so each row carries the
    host, the database product (from the plugin name), a parsed version, and the
    service port. Version parsing is best-effort and the plugin synopsis is kept.
    Returns no rows if the Databases family can't be resolved on this box.
    """
    fam_id = _plugin_family_id(client, "Databases")
    filters = list(_range_filters(time_range))
    if fam_id:
        filters.append({
            "filterName": "family", "operator": "=", "value": [{"id": fam_id}],
        })
    records = client.analysis("vulndetails", filters=filters)
    columns = [
        "host.name", "host.ip", "host.dns", "database", "version", "port",
        "protocol", "plugin.id", "plugin.name", "last.seen",
    ]
    rows: List[List[Any]] = []
    for rec in records:
        # When the family filter wasn't applied, keep only Databases-family rows.
        if not fam_id and _obj_name(rec.get("family")).lower() != "databases":
            continue
        plugin_name = textish(rec.get("pluginName"))
        # Parse a product name (plugin name up to the first version token) and a
        # version (from the plugin name, else the plugin output).
        product = plugin_name
        version = ""
        m = _VERSION_RE.search(plugin_name)
        if m:
            product = plugin_name[: m.start()].strip(" -")
            version = m.group(0)
        if not version:
            mt = _VERSION_RE.search(str(rec.get("pluginText") or ""))
            version = mt.group(0) if mt else ""
        rows.append([
            _host_name(rec), textish(rec.get("ip")), textish(rec.get("dnsName")),
            product, version, textish(rec.get("port")), textish(rec.get("protocol")),
            textish(rec.get("pluginID")), plugin_name, _epoch(rec.get("lastSeen")),
        ])
    return columns, rows


def _collect_users(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Tenable.sc user accounts (``GET /rest/user``)."""
    fields = (
        "id,username,firstname,lastname,email,title,role,group,orgName,"
        "authType,locked,status,lastLogin,createdTime,modifiedTime,"
        "responsibleAsset,managedUsersGroups"
    )
    try:
        response = client.get(f"user?fields={fields}")
    except Exception:  # pragma: no cover - permission dependent
        response = client.get("user")
    records = _listing(response)
    columns = [
        "host.name", "user.id", "username", "full.name", "email", "title",
        "role", "group", "org", "auth.type", "locked", "status",
        "last.login", "created", "modified",
    ]
    rows: List[List[Any]] = []
    for r in records:
        first = textish(r.get("firstname"))
        last = textish(r.get("lastname"))
        full = (first + " " + last).strip()
        username = textish(r.get("username"))
        rows.append([
            username,  # host.name so the user folds into the unified Users view
            textish(r.get("id")),
            username,
            full,
            textish(r.get("email")),
            textish(r.get("title")),
            _obj_name(r.get("role")),
            _obj_name(r.get("group")),
            textish(r.get("orgName")),
            textish(r.get("authType")),
            textish(r.get("locked")),
            textish(r.get("status")),
            _epoch(r.get("lastLogin")),
            _epoch(r.get("createdTime")),
            _epoch(r.get("modifiedTime")),
        ])
    return columns, rows


def _collect_asset_lists(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Asset lists — the asset tags / groupings defined in Tenable.sc.

    This is where **asset tags** live: each asset list carries a ``tags`` field
    plus its type (static / dynamic / dns / ldap / combination …), owner, group,
    and member-IP count. The devices resource stamps each host with the asset
    lists it belongs to; this resource is the catalog of those tags themselves.
    """
    records = _asset_records(client)
    columns = [
        "asset.name", "asset.id", "asset.type", "tags", "description",
        "ip.count", "owner", "owner.group", "groups", "status",
        "template", "created", "modified",
    ]
    rows: List[List[Any]] = []
    for r in records:
        template = r.get("template")
        rows.append([
            textish(r.get("name")),
            textish(r.get("id")),
            textish(r.get("type")),
            textish(r.get("tags")),
            textish(r.get("description")),
            textish(r.get("ipCount")),
            _obj_name(r.get("owner")),
            _obj_name(r.get("ownerGroup")),
            textish(r.get("groups")),
            textish(r.get("status")),
            _obj_name(template) if isinstance(template, dict) else textish(template),
            _epoch(r.get("createdTime")),
            _epoch(r.get("modifiedTime")),
        ])
    return columns, rows


def _collect_alerts(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Configured Tenable.sc alerts (``GET /rest/alert``)."""
    fields = (
        "id,name,description,didTriggerLastEvaluation,lastTriggered,lastEvaluated,"
        "triggerName,triggerOperator,triggerValue,status,action,owner,ownerGroup,"
        "schedule,createdTime,modifiedTime"
    )
    try:
        response = client.get(f"alert?fields={fields}")
    except Exception:  # pragma: no cover - permission dependent
        response = client.get("alert")
    records = _listing(response)
    columns = [
        "alert.name", "alert.id", "description", "trigger", "status",
        "did.trigger.last", "last.triggered", "last.evaluated", "actions",
        "owner", "owner.group", "created", "modified",
    ]
    rows: List[List[Any]] = []
    for r in records:
        trigger = " ".join(
            x for x in (
                textish(r.get("triggerName")),
                textish(r.get("triggerOperator")),
                textish(r.get("triggerValue")),
            ) if x
        )
        actions = r.get("action")
        action_types = ""
        if isinstance(actions, list):
            action_types = ", ".join(
                textish(a.get("type")) if isinstance(a, dict) else textish(a)
                for a in actions
            )
        else:
            action_types = textish(actions)
        rows.append([
            textish(r.get("name")),
            textish(r.get("id")),
            textish(r.get("description")),
            trigger,
            textish(r.get("status")),
            textish(r.get("didTriggerLastEvaluation")),
            _epoch(r.get("lastTriggered")),
            _epoch(r.get("lastEvaluated")),
            action_types,
            _obj_name(r.get("owner")),
            _obj_name(r.get("ownerGroup")),
            _epoch(r.get("createdTime")),
            _epoch(r.get("modifiedTime")),
        ])
    return columns, rows


def _collect_incidents(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Tickets — Tenable.sc's incident objects (``GET /rest/ticket``)."""
    fields = (
        "id,name,description,status,classification,assignedTime,createdTime,"
        "modifiedTime,assignee,owner,ownerGroup"
    )
    try:
        response = client.get(f"ticket?fields={fields}")
    except Exception:  # pragma: no cover - permission dependent
        response = client.get("ticket")
    records = _listing(response)
    columns = [
        "incident.name", "incident.id", "status", "classification",
        "description", "assignee", "owner", "owner.group",
        "assigned", "created", "modified",
    ]
    rows: List[List[Any]] = []
    for r in records:
        rows.append([
            textish(r.get("name")),
            textish(r.get("id")),
            _obj_name(r.get("status")),
            textish(r.get("classification")),
            textish(r.get("description")),
            _obj_name(r.get("assignee")),
            _obj_name(r.get("owner")),
            _obj_name(r.get("ownerGroup")),
            _epoch(r.get("assignedTime")),
            _epoch(r.get("createdTime")),
            _epoch(r.get("modifiedTime")),
        ])
    return columns, rows


def _collect_saas_applications(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Placeholder — Tenable.sc core does not enumerate SaaS applications.

    SaaS application discovery is a Tenable One / Tenable.io capability, not part
    of the Tenable.sc (SecurityCenter) REST API, so this resource returns no rows.
    It exists so the asset type is visible in the UI with an honest empty result
    rather than silently missing; the registry marks it ``not_validated``.
    """
    columns = ["application.name", "vendor", "note"]
    return columns, []


# -- Explore Assets (/rest/hosts, Tenable Security Center 6.x) --------------- #

# Fields requested from /rest/hosts. Tenable Security Center 6.x renamed a few
# keys across point releases, so the collector reads each with fallbacks and the
# unmapped-field sweep captures whatever else the release returns.
_HOSTS_FIELDS = (
    "id,uuid,name,ipAddress,os,osCPE,dnsName,netbiosName,netBios,macAddress,"
    "firstSeen,lastSeen,repositories,repository,acrScore,assetCriticalityRating,"
    "assetExposureScore,systemType,source,pluginSet,policyName,tenableUUID,hostUUID"
)

# Keys consumed by the named host columns — excluded from the custom.* sweep.
_HOSTS_CONSUMED = {
    "name", "dnsName", "netbiosName", "netBios", "ipAddress", "ip", "systemType",
    "macAddress", "os", "osCPE", "acrScore", "assetCriticalityRating",
    "assetExposureScore", "repositories", "repository", "firstSeen", "lastSeen",
    "uuid", "hostUUID", "tenableUUID",
}


def _fetch_hosts(client) -> List[Dict[str, Any]]:
    """Page ``GET /rest/hosts`` (the 6.x Explore Assets endpoint).

    Handles both response shapes seen across releases — a paged
    ``{"totalRecords", "results": [...]}`` and a plain list — and falls back to an
    unfielded request if the ``fields`` selector is rejected. Bounded by
    :data:`~assetflow.tenable_sc_client.ANALYSIS_MAX_RECORDS` via the page loop.
    """
    from .tenable_sc_client import ANALYSIS_MAX_RECORDS, ANALYSIS_PAGE_SIZE

    def _page(start: int, use_fields: bool):
        end = start + ANALYSIS_PAGE_SIZE
        suffix = f"&fields={_HOSTS_FIELDS}" if use_fields else ""
        return client.get(f"hosts?startOffset={start}&endOffset={end}{suffix}")

    out: List[Dict[str, Any]] = []
    start = 0
    use_fields = True
    while True:
        try:
            resp = _page(start, use_fields)
        except Exception:
            if use_fields:  # retry once without the fields selector
                use_fields = False
                continue
            break
        if isinstance(resp, dict):
            rows = resp.get("results")
            total = resp.get("totalRecords")
        elif isinstance(resp, list):
            rows, total = resp, None
        else:
            rows, total = None, None
        rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        out.extend(rows)
        if len(rows) < ANALYSIS_PAGE_SIZE:
            break
        try:
            total_n = int(total or 0)
        except (TypeError, ValueError):
            total_n = 0
        if total_n and len(out) >= total_n:
            break
        if len(out) >= ANALYSIS_MAX_RECORDS:
            break
        start += ANALYSIS_PAGE_SIZE
    return out[:ANALYSIS_MAX_RECORDS]


def _collect_hosts(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Unified host inventory via the 6.x Explore Assets endpoint (``/rest/hosts``).

    This is the modern companion to ``devices`` (``sumip``): one row per asset in
    the 6.x asset model, carrying ACR / AES, repositories, and system type. Field
    names are read with per-release fallbacks and any extra field the release
    returns rides along under ``custom.*``.
    """
    records = _fetch_hosts(client)
    named = [
        ("host.name", lambda r: textish(_pick(r, "name", "dnsName", "netbiosName", "netBios", "ipAddress", "ip"))),
        ("asset.type", lambda r: textish(_pick(r, "systemType")) or "Host"),
        ("host.ip", lambda r: textish(_pick(r, "ipAddress", "ip"))),
        ("host.dns", lambda r: textish(_pick(r, "dnsName"))),
        ("host.netbios", lambda r: textish(_pick(r, "netbiosName", "netBios"))),
        ("host.mac", lambda r: textish(_pick(r, "macAddress"))),
        ("os", lambda r: textish(_pick(r, "os", "osCPE"))),
        ("acr", lambda r: textish(_pick(r, "acrScore", "assetCriticalityRating"))),
        ("aes", lambda r: textish(_pick(r, "assetExposureScore"))),
        ("repositories", lambda r: _repos(_pick(r, "repositories", "repository"))),
        ("first.seen", lambda r: _epoch(_pick(r, "firstSeen"))),
        ("last.seen", lambda r: _epoch(_pick(r, "lastSeen"))),
        ("uuid", lambda r: textish(_pick(r, "uuid", "hostUUID", "tenableUUID"))),
    ]
    # Discover extra scalar keys (union across records) for the custom.* sweep.
    custom_keys: List[str] = []
    seen = set()
    for rec in records:
        for key in rec.keys():
            if key in _HOSTS_CONSUMED or key in seen:
                continue
            if isinstance(rec.get(key), (list, dict)):
                continue
            seen.add(key)
            custom_keys.append(key)

    columns = [name for name, _ in named] + [f"{CUSTOM_PREFIX}{k}" for k in custom_keys]
    rows: List[List[Any]] = []
    for rec in records:
        row = [fn(rec) for _, fn in named]
        row.extend(textish(rec.get(k)) for k in custom_keys)
        rows.append(row)
    return columns, rows


_COLLECTORS = {
    "devices": _collect_devices,
    "databases": _collect_databases,
    "hosts": _collect_hosts,
    "findings": _collect_findings,
    "software": _collect_software,
    "users": _collect_users,
    "asset_lists": _collect_asset_lists,
    "alerts": _collect_alerts,
    "incidents": _collect_incidents,
    "saas_applications": _collect_saas_applications,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> QueryResult:
    """Fetch a Tenable.sc registry query's resource and normalize the response.

    ``time_range`` bounds the vuln analysis resources (``devices`` / ``findings``)
    by ``lastSeen``; the object-listing resources (users, asset lists, alerts,
    incidents) are point-in-time and ignore it.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no Tenable.sc resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown Tenable.sc resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    columns, rows = collector(client, time_range)
    return _result(columns, rows, limit)
