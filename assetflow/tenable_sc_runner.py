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
* ``software`` — installed software, from the ``listsoftware`` analysis tool.
* ``users`` — the Tenable.sc user accounts (``GET /rest/user``).
* ``asset_lists`` — the asset lists that model **asset tags / groupings** in
  Tenable.sc (``GET /rest/asset``), each with its ``tags`` field, type, owner,
  and member-IP count.
* ``alerts`` — configured alerts (``GET /rest/alert``).
* ``incidents`` — tickets, Tenable.sc's incident objects (``GET /rest/ticket``).
* ``saas_applications`` — a placeholder: Tenable.sc core does not enumerate SaaS
  applications (that is a Tenable One / Tenable.io capability), so this returns no
  rows and is marked accordingly in the registry.

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

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# Prefix marking an unmapped (extra / site-specific) field, so it is never
# confused with the standard system columns.
CUSTOM_PREFIX = "custom."

# How many asset lists to expand into member IPs when stamping device tags, so a
# site with hundreds of asset lists cannot explode into hundreds of analysis
# calls. Asset-list metadata itself (the ``asset_lists`` resource) is never
# capped — only the per-device tag enrichment.
MAX_ASSET_LISTS_FOR_TAGS = 150

# Time-range tokens (from the UI) → number of days back, applied as a
# ``lastSeen`` filter on the vuln analysis resources (devices / findings).
RANGE_DAYS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


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


def _ips_for_asset(client, asset_id: str) -> List[str]:
    """Member IPs of one asset list, via a ``sumip`` analysis filtered to it."""
    filters = [{"filterName": "asset", "operator": "=", "value": {"id": str(asset_id)}}]
    try:
        records = client.analysis("sumip", filters=filters)
    except Exception:  # pragma: no cover - network dependent
        return []
    ips = []
    for r in records:
        ip = textish(r.get("ip"))
        if ip:
            ips.append(ip)
    return ips


def _ip_tag_map(client, assets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Build ``ip -> [asset-list names]`` for device tag stamping (bounded).

    Best-effort: each asset list is expanded into its member IPs via ``sumip``.
    Capped at :data:`MAX_ASSET_LISTS_FOR_TAGS` asset lists so a large estate stays
    bounded; on any failure the affected asset simply contributes no tags.
    """
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


def _collect_software(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Installed-software enumeration via the ``listsoftware`` analysis tool.

    ``listsoftware`` returns one row per distinct software string with a host
    count; some releases also carry a CPE. Extra fields ride along as ``custom.*``.
    """
    records = client.analysis("listsoftware", filters=_range_filters(time_range))
    spec: Tuple[Tuple[str, str, Any], ...] = (
        ("software.name", "name", textish),
        ("host.count", "count", textish),
        ("cpe", "cpe", textish),
    )
    return _flatten_analysis(records, spec, lead_host_name=False)


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


_COLLECTORS = {
    "devices": _collect_devices,
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
