"""Fetch Tufin SecureTrack resources and normalize them to ``QueryResult``.

This is the Tufin analogue of ``runner.py``. Where the Elasticsearch runner
executes an ES|QL string, this runner dispatches on a registry query's
``resource`` name (``devices``, ``revisions``, ``rules`` …) to the matching
SecureTrack REST endpoint(s), then flattens the JSON into the same
column/row shape (:class:`assetflow.runner.QueryResult`) the database, exports,
and unified host view already understand.

Device-scoped resources emit a ``host.name`` column (the device/CI name) so
they fold into the adapter's *All Fetched Results* golden-record view alongside
the Elasticsearch adapter's host-keyed queries.

Endpoint paths follow Tufin's official SecureTrack REST API / pytos SDK
(``/securetrack/api/devices``, ``…/devices/{id}/revisions``,
``…/revisions/{id}/rules``, ``…/devices/{id}/network_objects`` …). Response
shapes vary by TOS version and vendor, so each collector tries a couple of
path/key variants and normalizes defensively.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# ``device_scan_limit`` defaults to ``None`` = scan the WHOLE estate. This
# legacy constant is only a fallback ceiling if a caller explicitly asks for a
# bounded scan; Discover/run-all pass ``None`` to cover every device.
DEFAULT_DEVICE_SCAN = 25

# How many per-device REST calls to run in parallel. The client is stateless
# per request (a fresh HTTP call each time), so a bounded thread pool safely
# turns an N-device sweep into ~N/workers wall-time without flooding the API.
_DEFAULT_CONCURRENCY = 8
_MAX_CONCURRENCY = 32

# The device list is re-read by every collector; within one Discover pass that
# would be ~10 identical calls. Cache it briefly per client so it is fetched
# once. Short TTL bounds staleness across separate passes.
_DEVICE_CACHE_TTL = 60.0

# Time-range tokens (shared with the ES adapter's UI) → day counts, used to
# filter timestamped resources (revisions, audit events) client-side.
_RANGE_DAYS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


def resolve_device_scan() -> Optional[int]:
    """Estate coverage for a fetch: ``TUFIN_DEVICE_SCAN`` (a positive int), else
    ``None`` = all devices. ``0``/blank/invalid also mean all."""
    raw = os.getenv("TUFIN_DEVICE_SCAN")
    if raw:
        try:
            n = int(raw)
            if n > 0:
                return n
        except ValueError:
            pass
    return None


def _concurrency() -> int:
    try:
        n = int(os.getenv("TUFIN_CONCURRENCY", str(_DEFAULT_CONCURRENCY)))
    except ValueError:
        n = _DEFAULT_CONCURRENCY
    return max(1, min(n, _MAX_CONCURRENCY))


def _scan(devices: List[dict], scan: Optional[int]) -> List[dict]:
    """Apply the device-scan ceiling; ``None``/``0`` = the whole estate."""
    return devices if not scan else devices[: int(scan)]


def _map_devices(devices: List[dict], fn: Callable[[dict], Any]) -> List[Any]:
    """Run ``fn`` over each device, in bounded parallel, preserving order."""
    workers = _concurrency()
    if workers <= 1 or len(devices) <= 1:
        return [fn(d) for d in devices]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, devices))


# --------------------------------------------------------------------------- #
# JSON helpers (tolerant of the many shapes SecureTrack returns)
# --------------------------------------------------------------------------- #

def unwrap_items(payload: Any, keys: Tuple[str, ...]) -> List[dict]:
    """Pull a list of records out of a SecureTrack JSON envelope."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = unwrap_items(value, keys)
            if nested:
                return nested
    for value in payload.values():
        nested = unwrap_items(value, keys)
        if nested:
            return nested
    return []


def textish(value: Any) -> str:
    """Render a possibly-nested SecureTrack field as a compact string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(textish(item) for item in value[:6])
    if isinstance(value, dict):
        for key in ("display_name", "name", "ip", "netmask", "id", "uid"):
            if value.get(key):
                return textish(value[key])
        return ", ".join(f"{k}={textish(v)}" for k, v in list(value.items())[:4])
    return str(value)


def _first(record: dict, *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return ""


def _nested(record: dict, outer: str, inner: str) -> Any:
    """Pull ``record[outer][inner]`` when ``outer`` is a nested object."""
    value = record.get(outer)
    if isinstance(value, dict):
        return value.get(inner, "")
    return ""


def _join_datetime(record: dict) -> str:
    """SecureTrack splits a revision into ``date`` + ``time``; join them."""
    date = str(_first(record, "date"))
    time = str(_first(record, "time"))
    joined = f"{date} {time}".strip()
    return joined or str(_first(record, "created_at", "timestamp"))


def _tickets(record: dict) -> str:
    """Flatten a RevisionDTO ``tickets.ticket[]`` wrapper into ticket ids."""
    wrapper = record.get("tickets")
    items: List[dict] = []
    if isinstance(wrapper, dict):
        items = unwrap_items(wrapper, ("ticket",))
    elif isinstance(wrapper, list):
        items = [t for t in wrapper if isinstance(t, dict)]
    ids = [str(t.get("id")) for t in items if t.get("id") not in (None, "")]
    if ids:
        return ", ".join(ids)
    # Older/flat shapes seen in the wild.
    return textish(_first(record, "ticket_cr", "ticket_id", "ticket"))


def _result(columns: List[str], rows: List[List[Any]], limit: Optional[int]) -> QueryResult:
    if limit is not None:
        rows = rows[: int(limit)]
    return QueryResult(columns=[{"name": c} for c in columns], rows=rows)


def _timestamp_index(columns: List[str]) -> Optional[int]:
    for i, name in enumerate(columns):
        if name in ("@timestamp",) or name.endswith("time") or name.endswith("date"):
            return i
    return None


def _apply_time_range(columns: List[str], rows: List[List[Any]], time_range: Optional[str]) -> List[List[Any]]:
    """Keep only rows newer than the range, when a timestamp column exists."""
    days = _RANGE_DAYS.get((time_range or "").lower())
    if not days:
        return rows
    idx = _timestamp_index(columns)
    if idx is None:
        return rows
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    def keep(row: List[Any]) -> bool:
        raw = row[idx] if idx < len(row) else ""
        parsed = _parse_time(raw)
        return parsed is None or parsed >= cutoff

    return [row for row in rows if keep(row)]


def _parse_time(raw: Any):
    if not raw or not isinstance(raw, str):
        return None
    from datetime import datetime, timezone

    text = raw.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


# --------------------------------------------------------------------------- #
# Low-level fetch with endpoint fallbacks
# --------------------------------------------------------------------------- #

def _first_payload(client, paths: Tuple[str, ...]) -> Any:
    """Return the first path that yields a payload, else ``None``."""
    for path in paths:
        try:
            return client.get(path)
        except Exception:  # pragma: no cover - network/endpoint dependent
            continue
    return None


# SecureTrack paginates list endpoints (default page ~200) and reports the full
# size as ``total`` in the envelope. Without paging we only ever saw page one.
_PAGE_SIZE = 2000          # rows requested per page (server may cap lower)
_MAX_ITEMS = 200_000       # hard safety ceiling across all pages of one list


def _page_size() -> int:
    try:
        return max(1, int(os.getenv("TUFIN_PAGE_SIZE", str(_PAGE_SIZE))))
    except ValueError:
        return _PAGE_SIZE


def _page_path(path: str, start: int, count: int) -> str:
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}start={start}&count={count}"


def _read_total(payload: Any) -> Optional[int]:
    """The list's full size from a SecureTrack envelope, if it advertises one."""
    if isinstance(payload, dict):
        value = payload.get("total")
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def _fetch_list(client, paths: Tuple[str, ...], keys: Tuple[str, ...]) -> List[dict]:
    """Fetch EVERY item of a list resource across pages.

    Tries each path variant (a paged request first, then the bare path for
    servers/endpoints that don't accept ``start``/``count``); for the first that
    responds it pages, advancing by the count actually returned (so a server
    that caps the page size below the request is still walked fully) until it
    has everything. It stops using the envelope's ``total`` when present; when
    no ``total`` is advertised it keeps paging only while a page comes back
    *full* (== the requested size, i.e. there may be more) and stops on the
    first short or empty page — so a genuinely single-page or non-paginated
    shape (e.g. the nested cleanup set) makes exactly one call.
    """
    size = _page_size()
    for path in paths:
        payload = None
        for candidate in (_page_path(path, 0, size), path):
            try:
                payload = client.get(candidate)
                break
            except Exception:  # pragma: no cover - network/endpoint dependent
                payload = None
        if payload is None:
            continue
        items = unwrap_items(payload, keys)
        total = _read_total(payload)
        last_len = len(items)
        while len(items) < _MAX_ITEMS:
            if total is not None:
                if len(items) >= total:
                    break
            elif last_len < size:  # no total advertised → a short page ends it
                break
            try:
                payload = client.get(_page_path(path, len(items), size))
            except Exception:  # pragma: no cover
                break
            batch = unwrap_items(payload, keys)
            if not batch:
                break
            items.extend(batch)
            last_len = len(batch)
        return items
    return []


def _fetch_devices(client) -> List[dict]:
    # Serve a recent device list from a per-client cache so one Discover pass
    # (many collectors) hits /devices once, not once per collector.
    cached = getattr(client, "_af_devices_cache", None)
    if cached and (time.monotonic() - cached[0]) < _DEVICE_CACHE_TTL:
        return cached[1]
    devices = _fetch_list(
        client,
        (
            "devices.json?show_os_version=true",
            "devices.json",
            "devices",
        ),
        ("devices", "device"),
    )
    try:
        client._af_devices_cache = (time.monotonic(), devices)
    except Exception:  # pragma: no cover - exotic client without __dict__
        pass
    return devices


def _device_key(device: dict) -> Tuple[str, str]:
    device_id = str(_first(device, "id", "device_id"))
    name = str(_first(device, "name", "display_name", "hostname") or device_id)
    return device_id, name


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

# Model substrings that identify a firewall-management server (not a firewall).
_MGMT_MODEL_HINTS = (
    "panorama", "fmc", "fpmc", "fortimanager", "cma", "mds", "management",
    "smart", "mgmt", "cms", "nsx_manager", "meraki_dashboard",
)
_ROUTER_HINTS = ("router", "switch", "ios", "nexus")
_LB_HINTS = ("load_balancer", "balancer", "bigip", "netscaler", "avi")


def _asset_type(device: dict, parent_ids: set) -> str:
    """Derive an asset type from a SecureTrack device record.

    SecureTrack has no explicit device-type field, so this classifies from the
    model, the virtual_type, and the management hierarchy (a device that is the
    parent of other devices is a management server).
    """
    device_id = str(_first(device, "id", "device_id"))
    model = str(_first(device, "model")).lower()
    virtual_type = str(_first(device, "virtual_type")).lower()
    if device_id in parent_ids or any(h in model for h in _MGMT_MODEL_HINTS):
        return "Firewall Management"
    if virtual_type:
        return f"Virtual Firewall ({virtual_type})"
    if any(h in model for h in _ROUTER_HINTS):
        return "Router/Switch"
    if any(h in model for h in _LB_HINTS):
        return "Load Balancer"
    return "Firewall"


def _collect_devices(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    # Field names confirmed against DetailedDeviceDTO (SecureTrack R25-2) — the
    # full DTO is surfaced: identity, vendor/model, virtual context, IP/OS, the
    # domain (name + id, for multi-domain estates), status, the latest revision
    # id, the managed-module type/uid, and whether it is in the topology map.
    columns = [
        "host.name", "device.id", "asset.type", "device.vendor", "device.model",
        "virtual_type", "context_name", "host.ip", "os.version",
        "device.domain", "domain.id", "device.status", "latest_revision",
        "module_type", "module_uid", "topology", "installed_policy",
    ]
    devices = _fetch_devices(client)
    # A device that manages others (its id is some device's parent_id) is mgmt.
    parent_ids = {
        str(d.get("parent_id")) for d in devices if d.get("parent_id") not in (None, "")
    }
    rows = []
    for device in devices:
        device_id, name = _device_key(device)
        status = textish(_first(device, "status"))
        if not status and "offline" in device:
            status = "offline" if device.get("offline") else "online"
        rows.append([
            name,
            device_id,
            _asset_type(device, parent_ids),
            textish(_first(device, "vendor", "vendor_name")),
            textish(_first(device, "model", "type", "device_type")),
            textish(_first(device, "virtual_type")),
            textish(_first(device, "context_name")),
            textish(_first(device, "ip", "management_ip", "host")),
            textish(_first(device, "OS_Version", "os_version", "version")),
            textish(_first(device, "domain_name", "domain")),
            textish(_first(device, "domain_id")),
            status,
            textish(_first(device, "latest_revision", "revision_id", "revision")),
            textish(_first(device, "module_type")),
            textish(_first(device, "module_uid")),
            textish(_first(device, "topology")),
            textish(_first(device, "installed_policy")),
        ])
    return columns, rows


def _collect_per_device(
    client,
    scan: Optional[int],
    paths_for: Callable[[str, str, dict], Tuple[str, ...]],
    keys: Tuple[str, ...],
    columns: List[str],
    row_for: Callable[[dict, str, str], List[Any]],
) -> Tuple[List[str], List[List[Any]]]:
    def rows_for(device: dict) -> List[List[Any]]:
        device_id, name = _device_key(device)
        items = _fetch_list(client, paths_for(device_id, name, device), keys)
        return [row_for(item, device_id, name) for item in items]

    rows: List[List[Any]] = []
    for chunk in _map_devices(_scan(_fetch_devices(client), scan), rows_for):
        rows.extend(chunk)
    return columns, rows


def _collect_revisions(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    # Field names confirmed against RevisionDTO (SecureTrack R25-2). The API
    # splits time into date+time, nests the comment and tickets, and exposes the
    # acting admin as `admin` and the client/tool as `guiClient`.
    columns = [
        "host.name", "revision.id", "revision.number", "@timestamp", "changed_by",
        "gui_client", "action", "ticket", "policy_package", "authorization_status", "comment",
    ]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/revisions.json",
            f"devices/{device_id}/revisions",
        )

    def row_for(rev: dict, device_id: str, name: str) -> List[Any]:
        comment = _nested(rev, "comment", "comment") or _first(rev, "description", "message")
        return [
            name,
            str(_first(rev, "id", "revisionId")),
            str(_first(rev, "revisionId")),
            _join_datetime(rev),
            textish(_first(rev, "admin", "admin_name", "changed_by", "user", "actor")),
            textish(_first(rev, "guiClient", "gui_client")),
            textish(_first(rev, "action")),
            _tickets(rev),
            textish(_first(rev, "policyPackage", "policy_package", "policy")),
            textish(_first(rev, "authorizationStatus", "automaticAuthorizationStatus", "authorization_status")),
            textish(comment),
        ]

    return _collect_per_device(client, scan, paths_for, ("revisions", "revision"), columns, row_for)


# R25-2 rule source/destination/service live under src_network/dst_network/
# dst_service (arrays of objects), with zones under src_zone/dst_zone — NOT the
# generic "source"/"destination" keys.
def _rule_src(rule: dict) -> Any:
    return _first(rule, "src_network", "src_networks", "source", "src", "sources")


def _rule_dst(rule: dict) -> Any:
    return _first(rule, "dst_network", "dst_networks", "destination", "dst", "destinations")


def _rule_svc(rule: dict) -> Any:
    return _first(rule, "dst_service", "dst_services", "service", "services", "src_service", "protocol")


def _rule_src_zone(rule: dict) -> Any:
    return _first(rule, "src_zone", "from_zone")


def _rule_dst_zone(rule: dict) -> Any:
    return _first(rule, "dst_zone", "to_zone")


def _rule_any(value: Any) -> str:
    """Render a rule field, showing 'Any' when the object list is empty (as a
    firewall rule with no explicit source/destination means any)."""
    text = textish(value)
    return text if text else "Any"


def _collect_rules(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "rule.uid", "rule.name", "src_zone", "source",
        "dst_zone", "destination", "service", "action", "track", "disabled", "comment",
    ]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        revision_id = str(_first(device, "latest_revision", "revision_id", "revision"))
        variants = [
            f"devices/{device_id}/rules.json",
            f"devices/{device_id}/rules",
        ]
        if revision_id:
            variants[:0] = [
                f"revisions/{revision_id}/rules.json",
                f"revisions/{revision_id}/rules",
            ]
        return tuple(variants)

    def row_for(rule: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            str(_first(rule, "uid", "id", "rule_id", "order", "number")),
            textish(_first(rule, "name", "comment")),
            textish(_rule_src_zone(rule)),
            _rule_any(_rule_src(rule)),
            textish(_rule_dst_zone(rule)),
            _rule_any(_rule_dst(rule)),
            _rule_any(_rule_svc(rule)),
            textish(_first(rule, "action")),
            textish(_first(rule, "track")),
            textish(_first(rule, "disabled")),
            textish(_first(rule, "comment", "documentation")),
        ]

    return _collect_per_device(client, scan, paths_for, ("rules", "rule"), columns, row_for)


def _collect_network_objects(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "object.id", "object.name", "object.type", "object.ip", "comment"]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/network_objects.json",
            f"devices/{device_id}/network_objects",
        )

    def row_for(obj: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            str(_first(obj, "id", "uid")),
            textish(_first(obj, "display_name", "name")),
            textish(_first(obj, "@xsi.type", "type", "class_name")),
            textish(_first(obj, "ip", "ip_address", "value")),
            textish(_first(obj, "comment")),
        ]

    return _collect_per_device(
        client, scan, paths_for, ("network_objects", "network_object"), columns, row_for
    )


def _collect_services(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "service.id", "service.name", "protocol", "port", "type"]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/services.json",
            f"devices/{device_id}/services",
        )

    def row_for(svc: dict, device_id: str, name: str) -> List[Any]:
        # SecureTrack singleServiceDTO exposes a numeric protocol and a min/max
        # port range; collapse an equal range to a single port.
        lo = textish(_first(svc, "min", "port", "min_port", "dst_port"))
        hi = textish(_first(svc, "max", "max_port"))
        port = lo if (not hi or hi == lo) else f"{lo}-{hi}"
        return [
            name,
            str(_first(svc, "id", "uid")),
            textish(_first(svc, "display_name", "name")),
            textish(_first(svc, "protocol", "ip_protocol")),
            port,
            textish(_first(svc, "@xsi.type", "type", "class_name")),
        ]

    return _collect_per_device(client, scan, paths_for, ("services", "service"), columns, row_for)


def _collect_cleanups(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    # R25-2: /devices/{id}/cleanups requires a cleanup category ``code`` and only
    # supports C01 (fully shadowed rules); results nest under shadowed_rule.
    columns = ["host.name", "cleanup.type", "rule.uid", "rule.name", "comment"]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/cleanups.json?code=C01",
            f"devices/{device_id}/cleanups?code=C01",
        )

    def row_for(item: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            "fully_shadowed",
            textish(_first(item, "uid", "id", "rule_id", "order", "number")),
            textish(_first(item, "name", "comment")),
            textish(_first(item, "comment", "description")),
        ]

    return _collect_per_device(
        client, scan, paths_for,
        ("shadowed_rule", "shadowed_rules", "cleanup", "cleanups", "rule"),
        columns, row_for,
    )


def _collect_zones(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    # R25-2 has no global /zones; zones are per device (PolicyZoneListDTO).
    columns = ["host.name", "zone.id", "zone.name", "global"]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/zones.json",
            f"devices/{device_id}/zones",
        )

    def row_for(zone: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            str(_first(zone, "id", "uid")),
            textish(_first(zone, "name", "display_name")),
            textish(_first(zone, "global")),
        ]

    return _collect_per_device(client, scan, paths_for, ("zones", "zone"), columns, row_for)


# With no time range, how many of the most recent revisions to diff per device
# (2 revisions = the single latest change). A time range overrides this.
DEFAULT_CHANGE_REVISIONS = 2
# Safety cap on how many consecutive revision pairs to diff per device in one
# fetch, so a wide range on a busy device can't fan out into unbounded calls.
MAX_CHANGE_PAIRS = 25
# Time-range tokens that select the "since last seen" incremental mode.
INCREMENTAL_TOKENS = {"incremental", "since", "new"}


def _rev_id(rev: dict) -> str:
    return str(_first(rev, "id", "revisionId"))


def _rule_key(rule: dict) -> str:
    return str(_first(rule, "uid", "id", "rule_id", "order", "number"))


def _rule_fingerprint(rule: dict) -> str:
    """Identity of a rule's *effect* — used to tell a modification from a no-op.

    The rule name/comment is deliberately excluded so a pure rename does not
    read as a traffic change (mirrors the original Tufin change detector).
    """
    parts = [
        textish(_rule_src(rule)),
        textish(_rule_dst(rule)),
        textish(_rule_svc(rule)),
        textish(_first(rule, "action")),
        textish(_first(rule, "disabled")),
    ]
    return " | ".join(parts)


def _rule_compact(rule: dict) -> str:
    """A short human-readable rule summary for before/after cells."""
    src = textish(_rule_src(rule)) or "any"
    dst = textish(_rule_dst(rule)) or "any"
    svc = textish(_rule_svc(rule)) or "any"
    act = textish(_first(rule, "action")) or "?"
    return f"{src} → {dst} : {svc} ({act})"


def _revisions_sorted(client, device_id: str) -> List[dict]:
    revs = _fetch_list(
        client,
        (f"devices/{device_id}/revisions.json", f"devices/{device_id}/revisions"),
        ("revisions", "revision"),
    )

    def order(rev: dict):
        raw = _first(rev, "id", "revisionId", "number")
        try:
            return (0, int(raw))
        except (TypeError, ValueError):
            return (1, str(raw))

    return sorted(revs, key=order)


def _revision_time(rev: dict):
    return _parse_time(_join_datetime(rev))


def _select_change_pairs(
    revisions: List[dict], time_range: Optional[str], max_pairs: int
) -> List[Tuple[dict, dict]]:
    """Pick which consecutive revision pairs to diff.

    With a time range (24h/7d/30d/90d), select every revision whose date falls
    in the window **plus the one immediately before it** (the baseline, so the
    first in-window change has a "before" state), then diff each consecutive
    pair. With no range, fall back to the latest ``DEFAULT_CHANGE_REVISIONS``.
    Either way the number of pairs is capped at ``max_pairs`` (keeping the most
    recent) to bound the REST calls.
    """
    if len(revisions) < 2:
        return []

    days = _RANGE_DAYS.get((time_range or "").lower())
    if not days:
        window = revisions[-max(2, DEFAULT_CHANGE_REVISIONS):]
    else:
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        first_in = None
        for i, rev in enumerate(revisions):
            ts = _revision_time(rev)
            if ts is None or ts >= cutoff:  # unparseable dates are kept, not dropped
                first_in = i
                break
        if first_in is None:
            return []
        window = revisions[max(0, first_in - 1):]  # include the baseline revision

    if len(window) > max_pairs + 1:
        window = window[-(max_pairs + 1):]
    return list(zip(window, window[1:]))


def _incremental_pairs(
    revisions: List[dict], watermark: Optional[str], max_pairs: int
) -> Tuple[List[Tuple[dict, dict]], str]:
    """Pick pairs newer than the watermark; also return the new watermark.

    - First run (``watermark`` is None): establish a baseline silently — no
      pairs, and the returned watermark is the latest revision id.
    - Known watermark: diff every consecutive pair from it up to the latest.
    - Stale/unknown watermark (revision was pruned): fall back to the latest
      pair so a change is still reported rather than nothing.
    """
    if len(revisions) < 2:
        latest = _rev_id(revisions[-1]) if revisions else (watermark or "")
        return [], latest

    latest = _rev_id(revisions[-1])
    if watermark is None:
        return [], latest  # baseline only

    idx = next((i for i, r in enumerate(revisions) if _rev_id(r) == watermark), None)
    window = revisions[idx:] if idx is not None else revisions[-2:]
    pairs = list(zip(window, window[1:]))
    if len(pairs) > max_pairs:
        pairs = pairs[-max_pairs:]
    return pairs, latest


def _revision_rules(client, revision_id: str) -> Dict[str, dict]:
    rules = _fetch_list(
        client,
        (f"revisions/{revision_id}/rules.json", f"revisions/{revision_id}/rules"),
        ("rules", "rule"),
    )
    return {_rule_key(r): r for r in rules}


def _authorization(client, old_id: str, new_id: str) -> Tuple[str, str]:
    """Best-effort ``/change_authorization`` verdict for a revision pair.

    Returns ``(status, requester)``; empty strings when the endpoint is
    unavailable (it requires 'Authorize Revisions with Tickets' enabled).
    """
    payload = _first_payload(
        client,
        (
            f"change_authorization?old_version={old_id}&new_version={new_id}",
            f"change_authorization/?old_version={old_id}&new_version={new_id}",
        ),
    )
    if not isinstance(payload, dict):
        return "", ""
    root = payload.get("change_authorization", payload)
    status = textish(_first(root, "status"))
    tickets = root.get("tickets")
    requester = ""
    items = unwrap_items(tickets, ("ticket",)) if isinstance(tickets, (dict, list)) else []
    for t in items:
        requester = textish(_first(t, "requester_display_name", "requester_email"))
        if requester:
            break
    return status, requester


def _rule_field_delta(before: dict, after: dict) -> List[Tuple[str, str, str]]:
    """Per-field (label, before, after) for every rule field that changed."""
    bf = _rule_fields(before) if before else {}
    af = _rule_fields(after) if after else {}
    return [(label, bf.get(label, ""), af.get(label, ""))
            for label, _ in _RULE_FIELD_ORDER if bf.get(label) != af.get(label)]


def _is_on(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _change_summary(change_type: str, before: dict, after: dict) -> str:
    """A plain-language "what happened" line for one unit change."""
    if change_type == "added":
        return f"Added rule — {_rule_compact(after)}"
    if change_type == "removed":
        return f"Removed rule — {_rule_compact(before)}"
    if change_type == "moved":
        return "Moved — reordered within the rulebase (content unchanged)"
    deltas = _rule_field_delta(before, after)
    if len(deltas) == 1 and deltas[0][0] == "disabled":
        return "Disabled rule" if _is_on(deltas[0][2]) else "Re-enabled rule"
    parts = [f"{f}: {(b or '∅')} → {(a or '∅')}" for f, b, a in deltas]
    return "Modified — " + "; ".join(parts) if parts else "Modified rule"


# --- network-object change detection (folded into the same change stream) --- #

def _revision_objects_map(client, revision_id: str) -> Dict[str, dict]:
    objs = _fetch_list(
        client,
        (f"revisions/{revision_id}/network_objects.json", f"revisions/{revision_id}/network_objects"),
        ("network_objects", "network_object"),
    )
    out: Dict[str, dict] = {}
    for obj in objs:
        key = str(_first(obj, "uid", "id", "display_name", "name"))
        if key:
            out[key] = obj
    return out


def _object_type(obj: dict) -> str:
    return textish(_first(obj, "@xsi.type", "type", "class_name"))


def _object_name(obj: dict) -> str:
    return textish(_first(obj, "display_name", "name"))


def _object_disp(obj: dict) -> str:
    typ = _object_type(obj) or "object"
    val = _object_value(obj)
    return f"{typ}: {val}" if val else typ


def _object_fp(obj: dict) -> str:
    return f"{_object_type(obj)} | {_object_value(obj)}"


def _object_field_delta(before: dict, after: dict) -> List[Tuple[str, str, str]]:
    fields = [("type", _object_type), ("value", _object_value),
              ("comment", lambda o: textish(_first(o, "comment")))]
    out = []
    for label, fn in fields:
        b = fn(before) if before else ""
        a = fn(after) if after else ""
        if b != a:
            out.append((label, b, a))
    return out


def _object_summary(change_type: str, name: str, before: dict, after: dict) -> str:
    label = name or "(object)"
    if change_type == "added":
        return f"Added object '{label}' — {_object_disp(after)}"
    if change_type == "removed":
        return f"Removed object '{label}' — {_object_disp(before)}"
    parts = [f"{f}: {(b or '∅')} → {(a or '∅')}" for f, b, a in _object_field_delta(before, after)]
    return f"Modified object '{label}' — " + "; ".join(parts) if parts else f"Modified object '{label}'"


# --- security lens: did an object change *widen* access, and how many rules
# does it affect (blast radius)? ------------------------------------------- #

def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return [] if value in (None, "") else [value]


def _object_member_keys(obj: dict) -> set:
    keys = set()
    for item in _as_list(_first(obj, "members", "member")):
        if isinstance(item, dict):
            keys.add(str(_first(item, "uid", "id", "display_name", "name", "ip")))
        elif item not in (None, ""):
            keys.add(str(item))
    return {k for k in keys if k}


def _prefix_len(obj: dict) -> Optional[int]:
    """CIDR prefix length of a host/subnet object (smaller = broader)."""
    ip = textish(_first(obj, "ip", "ip_address", "value"))
    if "/" in ip:
        try:
            return int(ip.split("/", 1)[1])
        except ValueError:
            pass
    netmask = textish(_first(obj, "netmask"))
    if netmask.isdigit():
        return int(netmask)
    if netmask.count(".") == 3:
        try:
            return sum(bin(int(o)).count("1") for o in netmask.split("."))
        except ValueError:
            pass
    return None


def _object_risk(before: dict, after: dict) -> str:
    """Classify a modified object as widened / narrowed / changed access.

    A *widening* (members added, or a broader subnet) increases what every rule
    using the object permits — the security-relevant direction.
    """
    bm, am = _object_member_keys(before), _object_member_keys(after)
    if bm or am:
        if am - bm and not (bm - am):
            return "widened (members added)"
        if bm - am and not (am - bm):
            return "narrowed (members removed)"
        if am != bm:
            return "members changed"
    bp, ap = _prefix_len(before), _prefix_len(after)
    if bp is not None and ap is not None and bp != ap:
        return "widened (broader subnet)" if ap < bp else "narrowed (tighter subnet)"
    return "changed"


def _rule_object_refs(rules: Dict[str, dict]) -> Dict[str, set]:
    """Map each referenced object (by uid and by name) → the rule uids using it."""
    idx: Dict[str, set] = {}
    for ruid, rule in rules.items():
        for netval in (_rule_src(rule), _rule_dst(rule)):
            for item in _as_list(netval):
                if isinstance(item, dict):
                    for k in (_first(item, "uid", "id"), _first(item, "display_name", "name")):
                        if k:
                            idx.setdefault(str(k), set()).add(ruid)
    return idx


def _collect_change_detail(
    client, scan: int, time_range: Optional[str] = None, watermark_store=None
) -> Tuple[List[str], List[List[Any]]]:
    """Diff each device's revisions into per-change rows.

    Answers *what changed, who changed it, when* — and, when SecureChange
    ticket authorization is enabled, whether the change was authorized (with the
    requester). The API exposes revision *snapshots*, so the change list is
    computed by comparing consecutive revisions' rulebases.

    Which revisions get compared depends on ``time_range``:
    - a window token (24h/7d/…) → every revision in the window plus a baseline;
    - an incremental token (``since``/``new``/``incremental``) with a
      ``watermark_store`` → only revisions newer than each device's last-seen
      watermark, which is then advanced (the change-monitoring mode);
    - otherwise → the latest two revisions.

    Rules for a given revision are fetched once and reused across adjacent pairs.
    """
    columns = [
        "host.name", "revision.id", "@timestamp", "changed_by", "action", "policy_package",
        "change_type", "entity", "rule.uid", "summary", "changed_fields", "risk", "blast_radius",
        "src_zone", "source", "dst_zone", "destination", "service",
        "before", "after", "authorized", "requester",
    ]
    incremental = (time_range or "").lower() in INCREMENTAL_TOKENS and watermark_store is not None
    devices = _scan(_fetch_devices(client), scan)

    # Read every device's watermark up front on the main thread; the store is a
    # DB handle, so its reads/writes stay off the worker threads.
    watermarks: Dict[str, Any] = {}
    if incremental:
        for device in devices:
            device_id, _name = _device_key(device)
            watermarks[device_id] = watermark_store.get(device_id)

    def work(device: dict) -> Tuple[List[List[Any]], Optional[Tuple[str, str]]]:
        device_id, name = _device_key(device)
        revisions = _revisions_sorted(client, device_id)
        wm_update: Optional[Tuple[str, str]] = None
        if incremental:
            watermark = watermarks.get(device_id)
            pairs, new_watermark = _incremental_pairs(revisions, watermark, MAX_CHANGE_PAIRS)
            if new_watermark and new_watermark != watermark:
                wm_update = (device_id, new_watermark)
        else:
            pairs = _select_change_pairs(revisions, time_range, MAX_CHANGE_PAIRS)

        dev_rows: List[List[Any]] = []
        rules_cache: Dict[str, Dict[str, dict]] = {}
        objects_cache: Dict[str, Dict[str, dict]] = {}

        def rules_for(rev_id: str) -> Dict[str, dict]:
            if rev_id not in rules_cache:
                rules_cache[rev_id] = _revision_rules(client, rev_id)
            return rules_cache[rev_id]

        def objects_for(rev_id: str) -> Dict[str, dict]:
            if rev_id not in objects_cache:
                objects_cache[rev_id] = _revision_objects_map(client, rev_id)
            return objects_cache[rev_id]

        for older, newer in pairs:
            old_id = str(_first(older, "id", "revisionId"))
            new_id = str(_first(newer, "id", "revisionId"))
            before_rules = rules_for(old_id)
            after_rules = rules_for(new_id)
            before_objs = objects_for(old_id)
            after_objs = objects_for(new_id)
            if not (before_rules or after_rules or before_objs or after_objs):
                continue
            when = _join_datetime(newer)
            action = textish(_first(newer, "action"))
            policy_package = textish(_first(newer, "policyPackage", "policy_package", "policy"))
            admin = textish(_first(newer, "admin", "admin_name", "changed_by", "user"))
            if not admin:  # SecureTrack leaves the actor blank for system/automatic installs
                admin = "(automatic)" if "automat" in action.lower() else "(unattributed)"
            status, requester = _authorization(client, old_id, new_id)

            def emit(change_type: str, uid: str, before: dict, after: dict) -> None:
                # Describe the rule with its actual fields (the state that exists
                # after the change, or the pre-change state for a removed rule) so
                # a reader has full context without decoding the compact summary.
                ctx = after or before
                if change_type == "modified":
                    changed_fields = ", ".join(f for f, _, _ in _rule_field_delta(before, after))
                elif change_type == "moved":
                    changed_fields = "position"
                else:
                    changed_fields = ""
                dev_rows.append([
                    name, new_id, when, admin, action, policy_package, change_type, "rule", uid,
                    _change_summary(change_type, before, after), changed_fields, "", "",
                    textish(_rule_src_zone(ctx)), _rule_any(_rule_src(ctx)),
                    textish(_rule_dst_zone(ctx)), _rule_any(_rule_dst(ctx)),
                    _rule_any(_rule_svc(ctx)),
                    _rule_compact(before) if before else "",
                    _rule_compact(after) if after else "",
                    status, requester,
                ])

            # Which rules reference each object (blast radius). A removed object's
            # references live in the pre-change rulebase; otherwise the after one.
            after_refs = _rule_object_refs(after_rules)
            before_refs = _rule_object_refs(before_rules)

            def emit_obj(change_type: str, uid: str, before: dict, after: dict) -> None:
                # A rule can reference a named object; editing the object changes
                # what every rule using it permits while the rule text is unchanged.
                # Folding object edits into the same stream surfaces those, tagged
                # with whether access *widened* and how many rules it affects.
                ctx = after or before
                nm = _object_name(ctx)
                changed_fields = (", ".join(f for f, _, _ in _object_field_delta(before, after))
                                  if change_type == "modified" else "")
                risk = _object_risk(before, after) if change_type == "modified" else ""
                refs = before_refs if change_type == "removed" else after_refs
                blast = len(refs.get(str(uid), set()) | refs.get(str(nm), set()))
                dev_rows.append([
                    name, new_id, when, admin, action, policy_package, change_type, "object", uid,
                    _object_summary(change_type, nm, before, after), changed_fields,
                    risk, (str(blast) if blast else ""),
                    "", "", "", "", "",  # zone/source/dest/service are rule-only
                    _object_disp(before) if before else "",
                    _object_disp(after) if after else "",
                    status, requester,
                ])

            # Rules — position tracking so a pure reorder reads as "moved".
            on_lcs = _lcs_keep(
                [u for u in before_rules if u in after_rules],
                [u for u in after_rules if u in before_rules],
            )
            for uid, after in after_rules.items():
                before = before_rules.get(uid)
                if before is None:
                    emit("added", uid, {}, after)
                elif _rule_fingerprint(before) != _rule_fingerprint(after):
                    emit("modified", uid, before, after)
                elif uid not in on_lcs:
                    emit("moved", uid, before, after)
            for uid, before in before_rules.items():
                if uid not in after_rules:
                    emit("removed", uid, before, {})

            # Network objects — added / removed / modified.
            for uid, after in after_objs.items():
                before = before_objs.get(uid)
                if before is None:
                    emit_obj("added", uid, {}, after)
                elif _object_fp(before) != _object_fp(after):
                    emit_obj("modified", uid, before, after)
            for uid, before in before_objs.items():
                if uid not in after_objs:
                    emit_obj("removed", uid, before, {})
        return dev_rows, wm_update

    rows: List[List[Any]] = []
    for dev_rows, wm_update in _map_devices(devices, work):
        rows.extend(dev_rows)
        if wm_update is not None:
            watermark_store.set(*wm_update)  # main thread — serialized DB write
    return columns, rows


# --------------------------------------------------------------------------- #
# Revision comparison (SecureTrack "Compare revisions" report)
# --------------------------------------------------------------------------- #

# Ordered rule fields shown in the per-rule before/after detail (label ->
# extractor). Mirrors the columns of a SecureTrack revision-comparison report.
_RULE_FIELD_ORDER: List[Tuple[str, Callable[[dict], str]]] = [
    ("name", lambda r: textish(_first(r, "name", "comment"))),
    ("src_zone", lambda r: textish(_rule_src_zone(r))),
    ("source", lambda r: _rule_any(_rule_src(r))),
    ("dst_zone", lambda r: textish(_rule_dst_zone(r))),
    ("destination", lambda r: _rule_any(_rule_dst(r))),
    ("service", lambda r: _rule_any(_rule_svc(r))),
    ("action", lambda r: textish(_first(r, "action"))),
    ("track", lambda r: textish(_first(r, "track"))),
    ("disabled", lambda r: textish(_first(r, "disabled"))),
    ("comment", lambda r: textish(_first(r, "comment", "documentation"))),
]


def _rule_fields(rule: dict) -> Dict[str, str]:
    return {label: fn(rule) for label, fn in _RULE_FIELD_ORDER}


def _lcs_keep(a: List[str], b: List[str]) -> set:
    """Return the set of items on a longest common subsequence of ``a``/``b``.

    Used to tell a *moved* rule (present in both revisions, same content, but
    reordered) from one that merely shifted because rules around it were added
    or removed: only items off the common subsequence count as moved.
    """
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for k in range(m - 1, -1, -1):
            dp[i][k] = dp[i + 1][k + 1] + 1 if a[i] == b[k] else max(dp[i + 1][k], dp[i][k + 1])
    keep: set = set()
    i = k = 0
    while i < n and k < m:
        if a[i] == b[k]:
            keep.add(a[i]); i += 1; k += 1
        elif dp[i + 1][k] >= dp[i][k + 1]:
            i += 1
        else:
            k += 1
    return keep


def _rev_meta(rev: dict) -> Dict[str, str]:
    return {
        "id": _rev_id(rev),
        "number": str(_first(rev, "revisionId")),
        "date": _join_datetime(rev),
        "admin": textish(_first(rev, "admin", "admin_name", "changed_by", "user")),
        "action": textish(_first(rev, "action")),
        "policy_package": textish(_first(rev, "policyPackage", "policy_package", "policy")),
        "authorization_status": textish(
            _first(rev, "authorizationStatus", "automaticAuthorizationStatus", "authorization_status")
        ),
        "comment": textish(_nested(rev, "comment", "comment") or _first(rev, "description")),
    }


def _order_key(rev_id: str):
    try:
        return (0, int(rev_id))
    except (TypeError, ValueError):
        return (1, str(rev_id))


# Per-revision rulebase snapshot (persisted by TUF009). One row = one rule in
# one revision of one device. The Compare / Policy views read these rows back
# and diff them, so no live SecureTrack call is made at view time — you fetch
# once (explicitly, or via Fetch-all / the scheduler) and compare the fetched
# data, exactly like every other resource in the tool.
REVISION_RULE_COLUMNS = [
    "host.name", "device.id", "revision.id", "revision.number", "@timestamp", "changed_by",
    "rule.uid", "rule.name", "src_zone", "source", "dst_zone", "destination",
    "service", "action", "track", "disabled", "comment",
]
# (label shown in the compare detail  ->  column in REVISION_RULE_COLUMNS)
_COMPARE_FIELDS: List[Tuple[str, str]] = [
    ("name", "rule.name"), ("src_zone", "src_zone"), ("source", "source"),
    ("dst_zone", "dst_zone"), ("destination", "destination"), ("service", "service"),
    ("action", "action"), ("track", "track"), ("disabled", "disabled"), ("comment", "comment"),
]
# With no time range, how many of the most recent revisions to snapshot per
# device; a time range (24h/7d/…) overrides this. Capped for safety.
DEFAULT_REVISION_HISTORY = 5
MAX_REVISION_HISTORY = 30


def _select_recent_revisions(
    revisions: List[dict], time_range: Optional[str], default_count: int, cap: int
) -> List[dict]:
    """Pick which revisions to snapshot: a time window, else the latest N."""
    if not revisions:
        return []
    days = _RANGE_DAYS.get((time_range or "").lower())
    if not days:
        return revisions[-default_count:]
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    picked = [r for r in revisions if (_revision_time(r) is None or _revision_time(r) >= cutoff)]
    if len(picked) < 2:  # always keep a baseline so at least one pair can be compared
        picked = revisions[-2:]
    return picked[-cap:]


def _collect_revision_rules(
    client, scan: Optional[int], time_range: Optional[str] = None
) -> Tuple[List[str], List[List[Any]]]:
    """Snapshot the rulebases of each device's recent revisions into flat rows."""
    def rows_for(device: dict) -> List[List[Any]]:
        device_id, name = _device_key(device)
        out: List[List[Any]] = []
        for rev in _select_recent_revisions(
            _revisions_sorted(client, device_id), time_range,
            DEFAULT_REVISION_HISTORY, MAX_REVISION_HISTORY
        ):
            rid = _rev_id(rev)
            number = str(_first(rev, "revisionId"))
            when = _join_datetime(rev)
            admin = textish(_first(rev, "admin", "admin_name", "changed_by", "user"))
            for uid, rule in _revision_rules(client, rid).items():
                f = _rule_fields(rule)
                out.append([
                    name, device_id, rid, number, when, admin, uid,
                    f["name"], f["src_zone"], f["source"], f["dst_zone"], f["destination"],
                    f["service"], f["action"], f["track"], f["disabled"], f["comment"],
                ])
        return out

    rows: List[List[Any]] = []
    for chunk in _map_devices(_scan(_fetch_devices(client), scan), rows_for):
        rows.extend(chunk)
    return REVISION_RULE_COLUMNS, rows


# Per-revision network-object snapshot (persisted by TUF010). A rule can point
# at a named object (a host, subnet, or group); editing that object changes what
# every rule referencing it permits, while the rule text stays identical — so
# object-level diffing catches "hidden" scope changes rule diffing cannot see.
REVISION_OBJECT_COLUMNS = [
    "host.name", "device.id", "revision.id", "revision.number", "@timestamp", "changed_by",
    "object.uid", "object.name", "object.type", "object.value", "comment",
]
# (label shown in the compare detail  ->  column in REVISION_OBJECT_COLUMNS)
_OBJECT_FIELDS: List[Tuple[str, str]] = [
    ("name", "object.name"), ("type", "object.type"),
    ("value", "object.value"), ("comment", "comment"),
]


def _object_value(obj: dict) -> str:
    """Render an object's addresses/members — the part that defines its effect."""
    ip = textish(_first(obj, "ip", "ip_address", "value"))
    if ip:
        netmask = textish(_first(obj, "netmask"))
        return f"{ip}/{netmask}" if netmask and "/" not in ip else ip
    members = _first(obj, "members", "member")
    return textish(members) if members else ""


def _collect_revision_objects(
    client, scan: Optional[int], time_range: Optional[str] = None
) -> Tuple[List[str], List[List[Any]]]:
    """Snapshot each device's recent revisions' network objects into flat rows."""
    def rows_for(device: dict) -> List[List[Any]]:
        device_id, name = _device_key(device)
        out: List[List[Any]] = []
        for rev in _select_recent_revisions(
            _revisions_sorted(client, device_id), time_range,
            DEFAULT_REVISION_HISTORY, MAX_REVISION_HISTORY
        ):
            rid = _rev_id(rev)
            number = str(_first(rev, "revisionId"))
            when = _join_datetime(rev)
            admin = textish(_first(rev, "admin", "admin_name", "changed_by", "user"))
            objects = _fetch_list(
                client,
                (f"revisions/{rid}/network_objects.json", f"revisions/{rid}/network_objects"),
                ("network_objects", "network_object"),
            )
            for obj in objects:
                uid = str(_first(obj, "uid", "id", "display_name", "name"))
                out.append([
                    name, device_id, rid, number, when, admin, uid,
                    textish(_first(obj, "display_name", "name")),
                    textish(_first(obj, "@xsi.type", "type", "class_name")),
                    _object_value(obj),
                    textish(_first(obj, "comment")),
                ])
        return out

    rows: List[List[Any]] = []
    for chunk in _map_devices(_scan(_fetch_devices(client), scan), rows_for):
        rows.extend(chunk)
    return REVISION_OBJECT_COLUMNS, rows


# --------------------------------------------------------------------------- #
# Revision comparison / policy view — computed from the SAVED snapshot rows
# (no live client), so they read whatever the last TUF009/TUF010 fetch persisted.
# --------------------------------------------------------------------------- #

def _colmap(columns: List[Any]) -> Tuple[List[str], Dict[str, int]]:
    names = [c["name"] if isinstance(c, dict) else c for c in columns]
    return names, {n: i for i, n in enumerate(names)}


def _device_revision_rules(
    columns: List[Any], rows: List[List[Any]], device_id: str
) -> Tuple[str, Dict[str, dict]]:
    """Group saved rows for one device into rev_id -> {meta, rules{uid->fields}}.

    Rules keep their saved row order (i.e. rulebase order), which the moved
    detection relies on. Returns the device name alongside.
    """
    _names, idx = _colmap(columns)

    def cell(row: List[Any], key: str) -> str:
        i = idx.get(key)
        return str(row[i]) if i is not None and i < len(row) and row[i] is not None else ""

    name = ""
    revs: Dict[str, dict] = {}
    for row in rows:
        did = cell(row, "device.id")
        hname = cell(row, "host.name")
        if str(device_id) not in (did, hname):
            continue
        name = name or hname
        rid = cell(row, "revision.id")
        if not rid:
            continue
        rev = revs.get(rid)
        if rev is None:
            rev = revs[rid] = {
                "meta": {"id": rid, "number": cell(row, "revision.number"),
                         "date": cell(row, "@timestamp"), "admin": cell(row, "changed_by")},
                "rules": {},
            }
        rev["rules"][cell(row, "rule.uid")] = {label: cell(row, col) for label, col in _COMPARE_FIELDS}
    return name, revs


def _saved_fingerprint(fields: Dict[str, str]) -> str:
    return " | ".join(fields.get(k, "") for k in ("source", "destination", "service", "action", "disabled"))


def _device_revision_objects(
    columns: List[Any], rows: List[List[Any]], device_id: str
) -> Dict[str, dict]:
    """Group saved TUF010 rows for one device into rev_id -> {objects{uid->fields}}."""
    _names, idx = _colmap(columns)

    def cell(row: List[Any], key: str) -> str:
        i = idx.get(key)
        return str(row[i]) if i is not None and i < len(row) and row[i] is not None else ""

    revs: Dict[str, dict] = {}
    for row in rows:
        if str(device_id) not in (cell(row, "device.id"), cell(row, "host.name")):
            continue
        rid = cell(row, "revision.id")
        if not rid:
            continue
        rev = revs.setdefault(rid, {"objects": {}})
        rev["objects"][cell(row, "object.uid")] = {label: cell(row, col) for label, col in _OBJECT_FIELDS}
    return revs


def _saved_obj_fingerprint(fields: Dict[str, str]) -> str:
    return " | ".join(fields.get(k, "") for k in ("type", "value"))


def _diff_saved_objects(revs: Dict[str, dict], old_id: str, new_id: str) -> Tuple[dict, List[dict]]:
    """Added/removed/modified network objects between two revisions (no 'moved')."""
    before = revs.get(old_id, {}).get("objects", {})
    after = revs.get(new_id, {}).get("objects", {})
    counts = {"added": 0, "removed": 0, "modified": 0}
    obj_rows: List[dict] = []
    for uid, af in after.items():
        bf = before.get(uid)
        if bf is None:
            ctype = "added"
        elif _saved_obj_fingerprint(bf) != _saved_obj_fingerprint(af):
            ctype = "modified"
        else:
            continue
        counts[ctype] += 1
        changed = [label for label, _ in _OBJECT_FIELDS if bf and bf.get(label) != af.get(label)]
        obj_rows.append({"change_type": ctype, "object_uid": uid, "name": af.get("name", ""),
                         "before": bf or {}, "after": af, "changed_fields": changed})
    for uid, bf in before.items():
        if uid not in after:
            counts["removed"] += 1
            obj_rows.append({"change_type": "removed", "object_uid": uid, "name": bf.get("name", ""),
                             "before": bf, "after": {}, "changed_fields": []})
    rank = {"added": 0, "removed": 1, "modified": 2}
    obj_rows.sort(key=lambda r: (rank.get(r["change_type"], 9), r["object_uid"]))
    return counts, obj_rows


def index_revision_rules(columns: List[Any], rows: List[List[Any]]) -> List[dict]:
    """Devices (with their revisions, newest first) present in the saved snapshot."""
    _names, idx = _colmap(columns)

    def cell(row: List[Any], key: str) -> str:
        i = idx.get(key)
        return str(row[i]) if i is not None and i < len(row) and row[i] is not None else ""

    devices: Dict[str, dict] = {}
    for row in rows:
        did = cell(row, "device.id") or cell(row, "host.name")
        if not did:
            continue
        dev = devices.get(did)
        if dev is None:
            dev = devices[did] = {"id": did, "name": cell(row, "host.name"), "_revs": {}}
        rid = cell(row, "revision.id")
        if rid and rid not in dev["_revs"]:
            dev["_revs"][rid] = {"id": rid, "number": cell(row, "revision.number"),
                                 "date": cell(row, "@timestamp"), "admin": cell(row, "changed_by")}
    out = []
    for dev in devices.values():
        revs = sorted(dev["_revs"].values(), key=lambda r: _order_key(r["id"]), reverse=True)
        out.append({"id": dev["id"], "name": dev["name"], "revisions": revs})
    out.sort(key=lambda d: (d["name"] or "").lower())
    return out


def compare_from_saved(
    columns: List[Any], rows: List[List[Any]], device_id: str,
    old_rev: Optional[str] = None, new_rev: Optional[str] = None,
    object_columns: Optional[List[Any]] = None, object_rows: Optional[List[List[Any]]] = None,
) -> dict:
    """Compare two saved revisions of one device (SecureTrack-style report).

    Reads the persisted TUF009 snapshot rows — no SecureTrack call. Summary of
    New/Deleted/Modified/Moved security rules plus per-rule before→after detail.
    Omitting the revisions compares the device's latest two *saved* revisions;
    given both, they are ordered oldest→newest so the report reads forward.

    When a TUF010 network-object snapshot is supplied (``object_columns`` /
    ``object_rows``), a Network Objects summary and per-object before→after
    detail for the same two revisions are appended — catching object edits that
    change what a rule permits without the rule text changing.
    """
    name, revs = _device_revision_rules(columns, rows, device_id)
    base = {"device": {"id": str(device_id), "name": name}, "summary": [], "rules": []}
    if not revs:
        base["error"] = "no saved rulebase for this device — run TUF009 (Revision Rulebases) first"
        return base

    ordered = sorted(revs.keys(), key=_order_key)
    if old_rev or new_rev:
        ids = sorted({str(x) for x in (old_rev, new_rev) if x not in (None, "")}, key=_order_key)
        old_id, new_id = ids[0], (ids[-1] if len(ids) > 1 else ids[0])
    elif len(ordered) >= 2:
        old_id, new_id = ordered[-2], ordered[-1]
    else:
        old_id, new_id = "", ordered[-1]

    missing = [r for r in (old_id, new_id) if r and r not in revs]
    if missing:
        base["error"] = ("revision(s) " + ", ".join(missing) +
                         " are not in the saved snapshot — re-run TUF009 with a wider range")
        return base

    before = revs.get(old_id, {}).get("rules", {}) if old_id else {}
    after = revs.get(new_id, {}).get("rules", {}) if new_id else {}

    on_lcs = _lcs_keep([u for u in before if u in after], [u for u in after if u in before])
    rule_rows: List[dict] = []
    counts = {"added": 0, "removed": 0, "modified": 0, "moved": 0}
    for uid, af in after.items():
        bf = before.get(uid)
        if bf is None:
            ctype = "added"
        elif _saved_fingerprint(bf) != _saved_fingerprint(af):
            ctype = "modified"
        elif uid not in on_lcs:
            ctype = "moved"
        else:
            continue
        counts[ctype] += 1
        changed = [label for label, _ in _COMPARE_FIELDS if bf and bf.get(label) != af.get(label)]
        rule_rows.append({"change_type": ctype, "rule_uid": uid, "name": af.get("name", ""),
                          "before": bf or {}, "after": af, "changed_fields": changed})
    for uid, bf in before.items():
        if uid not in after:
            counts["removed"] += 1
            rule_rows.append({"change_type": "removed", "rule_uid": uid, "name": bf.get("name", ""),
                              "before": bf, "after": {}, "changed_fields": []})

    rank = {"added": 0, "removed": 1, "modified": 2, "moved": 3}
    rule_rows.sort(key=lambda r: (rank.get(r["change_type"], 9), _order_key(r["rule_uid"])))

    out = {
        "device": {"id": str(device_id), "name": name},
        "from": revs.get(old_id, {}).get("meta", {"id": old_id}),
        "to": revs.get(new_id, {}).get("meta", {"id": new_id}),
        "summary": [
            {"category": "Security Rules", "added": counts["added"], "deleted": counts["removed"],
             "modified": counts["modified"], "moved": counts["moved"]},
        ],
        "rule_fields": [label for label, _ in _COMPARE_FIELDS],
        "rules": rule_rows,
        "has_objects": object_columns is not None,
    }

    if object_columns is not None:
        orevs = _device_revision_objects(object_columns, object_rows or [], device_id)
        if old_id in orevs or new_id in orevs:
            ocounts, obj_rows = _diff_saved_objects(orevs, old_id, new_id)
            out["summary"].append(
                {"category": "Network Objects", "added": ocounts["added"], "deleted": ocounts["removed"],
                 "modified": ocounts["modified"], "moved": 0}
            )
            out["object_fields"] = [label for label, _ in _OBJECT_FIELDS]
            out["objects"] = obj_rows
    return out


def policy_from_saved(
    columns: List[Any], rows: List[List[Any]], device_id: str, revision_id: Optional[str] = None
) -> dict:
    """Return one saved revision's full rulebase as a column/row table."""
    name, revs = _device_revision_rules(columns, rows, device_id)
    if not revs:
        return {"device": {"id": str(device_id), "name": name},
                "error": "no saved rulebase for this device — run TUF009 (Revision Rulebases) first",
                "columns": [], "rows": []}
    ordered = sorted(revs.keys(), key=_order_key)
    rid = str(revision_id) if revision_id not in (None, "") else ordered[-1]
    if rid not in revs:
        return {"device": {"id": str(device_id), "name": name},
                "error": f"revision {rid} is not in the saved snapshot — re-run TUF009",
                "columns": [], "rows": []}
    labels = [label for label, _ in _COMPARE_FIELDS]
    out_cols = ["rule.uid"] + labels
    out_rows = [[uid] + [fields[label] for label in labels]
                for uid, fields in revs[rid]["rules"].items()]
    return {
        "device": {"id": str(device_id), "name": name},
        "revision": revs[rid]["meta"],
        "columns": [{"name": c} for c in out_cols],
        "rows": out_rows,
    }


_COLLECTORS: Dict[str, Callable[..., Tuple[List[str], List[List[Any]]]]] = {
    "devices": _collect_devices,
    "revisions": _collect_revisions,
    "rules": _collect_rules,
    "network_objects": _collect_network_objects,
    "services": _collect_services,
    "cleanups": _collect_cleanups,
    "zones": _collect_zones,
    "change_detail": _collect_change_detail,
    "revision_rules": _collect_revision_rules,
    "revision_objects": _collect_revision_objects,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
    device_scan_limit: Optional[int] = None,
    watermark_store=None,
) -> QueryResult:
    """Fetch a Tufin registry query's resource and normalize the response.

    ``device_scan_limit`` bounds how many devices per-device resources scan;
    ``None`` (the default) covers the whole estate.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no Tufin resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown Tufin resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    if resource == "change_detail":
        # This resource selects its own revision window from the time range
        # (it decides which revisions to fetch and diff), so it is not also
        # row-filtered afterwards.
        columns, rows = _collect_change_detail(
            client, device_scan_limit, time_range, watermark_store
        )
    elif resource == "revision_rules":
        # Selects its own revision set from the time range; the @timestamp is a
        # revision date and must not be used to drop baseline revisions.
        columns, rows = _collect_revision_rules(client, device_scan_limit, time_range)
    elif resource == "revision_objects":
        columns, rows = _collect_revision_objects(client, device_scan_limit, time_range)
    else:
        columns, rows = collector(client, device_scan_limit)
        rows = _apply_time_range(columns, rows, time_range)
    return _result(columns, rows, limit)
