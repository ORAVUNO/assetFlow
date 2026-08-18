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

from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# How many devices a per-device resource will scan before stopping, to bound
# the number of REST calls on large estates. Rows are still capped by ``limit``.
DEFAULT_DEVICE_SCAN = 25

# Time-range tokens (shared with the ES adapter's UI) → day counts, used to
# filter timestamped resources (revisions, audit events) client-side.
_RANGE_DAYS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


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


def _fetch_devices(client) -> List[dict]:
    payload = _first_payload(
        client,
        (
            "devices.json?show_os_version=true",
            "devices.json",
            "devices",
        ),
    )
    return unwrap_items(payload, ("devices", "device"))


def _device_key(device: dict) -> Tuple[str, str]:
    device_id = str(_first(device, "id", "device_id"))
    name = str(_first(device, "name", "display_name", "hostname") or device_id)
    return device_id, name


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _collect_devices(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "device.id", "device.vendor", "device.model", "host.ip", "os.version", "device.domain"]
    rows = []
    for device in _fetch_devices(client):
        device_id, name = _device_key(device)
        rows.append([
            name,
            device_id,
            textish(_first(device, "vendor", "vendor_name")),
            textish(_first(device, "model", "type", "device_type")),
            textish(_first(device, "management_ip", "ip", "host")),
            textish(_first(device, "os_version", "version")),
            textish(_first(device, "domain", "domain_name")),
        ])
    return columns, rows


def _collect_per_device(
    client,
    scan: int,
    paths_for: Callable[[str, str, dict], Tuple[str, ...]],
    keys: Tuple[str, ...],
    columns: List[str],
    row_for: Callable[[dict, str, str], List[Any]],
) -> Tuple[List[str], List[List[Any]]]:
    rows: List[List[Any]] = []
    for device in _fetch_devices(client)[:scan]:
        device_id, name = _device_key(device)
        payload = _first_payload(client, paths_for(device_id, name, device))
        if payload is None:
            continue
        for item in unwrap_items(payload, keys):
            rows.append(row_for(item, device_id, name))
    return columns, rows


def _collect_revisions(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "revision.id", "@timestamp", "changed_by", "action",
        "ticket", "policy_package", "authorization_status", "comment",
    ]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/revisions.json",
            f"devices/{device_id}/revisions",
            f"revisions.json?device_id={device_id}",
        )

    def row_for(rev: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            str(_first(rev, "revision_id", "id", "number")),
            textish(_first(rev, "date", "time", "created_at", "timestamp")),
            textish(_first(rev, "admin_name", "changed_by", "user", "admin", "actor")),
            textish(_first(rev, "action")),
            textish(_first(rev, "ticket_cr", "ticket_id", "ticket")),
            textish(_first(rev, "policy_package", "policy", "policy_name")),
            textish(_first(rev, "authorization_status", "guidelines_status", "status")),
            textish(_first(rev, "comment", "description", "message")),
        ]

    return _collect_per_device(client, scan, paths_for, ("revisions", "revision"), columns, row_for)


def _collect_rules(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "rule.uid", "rule.name", "source", "destination",
        "service", "action", "track", "disabled", "comment",
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
            textish(_first(rule, "source", "src", "sources")),
            textish(_first(rule, "destination", "dst", "destinations")),
            textish(_first(rule, "service", "services", "protocol")),
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
            textish(_first(obj, "type", "class_name")),
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
        return [
            name,
            str(_first(svc, "id", "uid")),
            textish(_first(svc, "display_name", "name")),
            textish(_first(svc, "protocol", "ip_protocol")),
            textish(_first(svc, "port", "min", "min_port", "dst_port")),
            textish(_first(svc, "type", "class_name")),
        ]

    return _collect_per_device(client, scan, paths_for, ("services", "service"), columns, row_for)


def _collect_cleanups(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "cleanup.type", "rule.uid", "count", "comment"]

    def paths_for(device_id: str, name: str, device: dict) -> Tuple[str, ...]:
        return (
            f"devices/{device_id}/cleanups.json",
            f"devices/{device_id}/cleanups",
        )

    def row_for(item: dict, device_id: str, name: str) -> List[Any]:
        return [
            name,
            textish(_first(item, "cleanup_type", "type", "name")),
            textish(_first(item, "rule_uid", "uid", "rule_id")),
            textish(_first(item, "count", "instances_number")),
            textish(_first(item, "comment", "description")),
        ]

    return _collect_per_device(
        client, scan, paths_for, ("cleanups", "cleanup", "rule_cleanups"), columns, row_for
    )


def _collect_zones(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["zone.id", "zone.name", "domain", "comment"]
    payload = _first_payload(client, ("zones.json", "zones"))
    rows = []
    for zone in unwrap_items(payload, ("zones", "zone")):
        rows.append([
            str(_first(zone, "id", "uid")),
            textish(_first(zone, "name", "display_name")),
            textish(_first(zone, "domain", "domain_name")),
            textish(_first(zone, "comment", "description")),
        ])
    return columns, rows


def _collect_audit_logs(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "event.id", "@timestamp", "changed_by", "source.ip", "event.type", "message"]
    payload = _first_payload(
        client,
        (
            "audit_logs.json?count=100",
            "audit_logs?count=100",
            "change_logs.json?count=100",
            "changes.json?count=100",
        ),
    )
    rows = []
    for log in unwrap_items(payload, ("audit_logs", "audit_log", "changes", "change", "events", "event", "logs", "log")):
        rows.append([
            textish(_first(log, "device_name", "ci_name")),
            str(_first(log, "event_id", "id", "uid")),
            textish(_first(log, "event_time", "time", "timestamp", "date")),
            textish(_first(log, "actor", "user", "changed_by", "admin")),
            textish(_first(log, "source_ip", "client_ip")),
            textish(_first(log, "event_type", "type", "action")),
            textish(_first(log, "message", "description", "comment")),
        ])
    return columns, rows


_COLLECTORS: Dict[str, Callable[[Any, int], Tuple[List[str], List[List[Any]]]]] = {
    "devices": _collect_devices,
    "revisions": _collect_revisions,
    "rules": _collect_rules,
    "network_objects": _collect_network_objects,
    "services": _collect_services,
    "cleanups": _collect_cleanups,
    "zones": _collect_zones,
    "audit_logs": _collect_audit_logs,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
    device_scan_limit: int = DEFAULT_DEVICE_SCAN,
) -> QueryResult:
    """Fetch a Tufin registry query's resource and normalize the response."""
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
    columns, rows = collector(client, device_scan_limit)
    rows = _apply_time_range(columns, rows, time_range)
    return _result(columns, rows, limit)
