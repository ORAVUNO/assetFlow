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
    # Field names confirmed against DetailedDeviceDTO (SecureTrack R25-2).
    columns = [
        "host.name", "device.id", "device.vendor", "device.model", "host.ip",
        "os.version", "device.domain", "device.status", "installed_policy",
    ]
    rows = []
    for device in _fetch_devices(client):
        device_id, name = _device_key(device)
        status = textish(_first(device, "status"))
        if not status and "offline" in device:
            status = "offline" if device.get("offline") else "online"
        rows.append([
            name,
            device_id,
            textish(_first(device, "vendor", "vendor_name")),
            textish(_first(device, "model", "type", "device_type")),
            textish(_first(device, "ip", "management_ip", "host")),
            textish(_first(device, "OS_Version", "os_version", "version")),
            textish(_first(device, "domain_name", "domain")),
            status,
            textish(_first(device, "installed_policy")),
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
        textish(_first(rule, "source", "src", "sources")),
        textish(_first(rule, "destination", "dst", "destinations")),
        textish(_first(rule, "service", "services", "protocol")),
        textish(_first(rule, "action")),
        textish(_first(rule, "disabled")),
    ]
    return " | ".join(parts)


def _rule_compact(rule: dict) -> str:
    """A short human-readable rule summary for before/after cells."""
    src = textish(_first(rule, "source", "src", "sources")) or "any"
    dst = textish(_first(rule, "destination", "dst", "destinations")) or "any"
    svc = textish(_first(rule, "service", "services", "protocol")) or "any"
    act = textish(_first(rule, "action")) or "?"
    return f"{src} → {dst} : {svc} ({act})"


def _revisions_sorted(client, device_id: str) -> List[dict]:
    payload = _first_payload(
        client,
        (f"devices/{device_id}/revisions.json", f"devices/{device_id}/revisions"),
    )
    revs = unwrap_items(payload, ("revisions", "revision"))

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
    payload = _first_payload(
        client,
        (f"revisions/{revision_id}/rules.json", f"revisions/{revision_id}/rules"),
    )
    return {_rule_key(r): r for r in unwrap_items(payload, ("rules", "rule"))}


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
        "host.name", "revision.id", "@timestamp", "changed_by", "change_type",
        "rule.uid", "before", "after", "authorized", "requester",
    ]
    incremental = (time_range or "").lower() in INCREMENTAL_TOKENS and watermark_store is not None
    rows: List[List[Any]] = []
    for device in _fetch_devices(client)[:scan]:
        device_id, name = _device_key(device)
        revisions = _revisions_sorted(client, device_id)
        if incremental:
            watermark = watermark_store.get(device_id)
            pairs, new_watermark = _incremental_pairs(revisions, watermark, MAX_CHANGE_PAIRS)
            if new_watermark and new_watermark != watermark:
                watermark_store.set(device_id, new_watermark)
        else:
            pairs = _select_change_pairs(revisions, time_range, MAX_CHANGE_PAIRS)
        rules_cache: Dict[str, Dict[str, dict]] = {}

        def rules_for(rev_id: str) -> Dict[str, dict]:
            if rev_id not in rules_cache:
                rules_cache[rev_id] = _revision_rules(client, rev_id)
            return rules_cache[rev_id]

        for older, newer in pairs:
            old_id = str(_first(older, "id", "revisionId"))
            new_id = str(_first(newer, "id", "revisionId"))
            before_rules = rules_for(old_id)
            after_rules = rules_for(new_id)
            if not before_rules and not after_rules:
                continue
            when = _join_datetime(newer)
            admin = textish(_first(newer, "admin", "admin_name", "changed_by", "user"))
            status, requester = _authorization(client, old_id, new_id)

            def emit(change_type: str, uid: str, before: dict, after: dict) -> None:
                rows.append([
                    name, new_id, when, admin, change_type, uid,
                    _rule_compact(before) if before else "",
                    _rule_compact(after) if after else "",
                    status, requester,
                ])

            for uid, after in after_rules.items():
                before = before_rules.get(uid)
                if before is None:
                    emit("added", uid, {}, after)
                elif _rule_fingerprint(before) != _rule_fingerprint(after):
                    emit("modified", uid, before, after)
            for uid, before in before_rules.items():
                if uid not in after_rules:
                    emit("removed", uid, before, {})
    return columns, rows


_COLLECTORS: Dict[str, Callable[..., Tuple[List[str], List[List[Any]]]]] = {
    "devices": _collect_devices,
    "revisions": _collect_revisions,
    "rules": _collect_rules,
    "network_objects": _collect_network_objects,
    "services": _collect_services,
    "cleanups": _collect_cleanups,
    "zones": _collect_zones,
    "change_detail": _collect_change_detail,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
    device_scan_limit: int = DEFAULT_DEVICE_SCAN,
    watermark_store=None,
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
    if resource == "change_detail":
        # This resource selects its own revision window from the time range
        # (it decides which revisions to fetch and diff), so it is not also
        # row-filtered afterwards.
        columns, rows = _collect_change_detail(
            client, device_scan_limit, time_range, watermark_store
        )
    else:
        columns, rows = collector(client, device_scan_limit)
        rows = _apply_time_range(columns, rows, time_range)
    return _result(columns, rows, limit)
