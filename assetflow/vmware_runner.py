"""Fetch VMware vCenter inventory and normalize it to ``QueryResult``.

This is the VMware analogue of ``runner.py`` / ``tufin_runner.py``. Each
registry query names a ``resource`` (``virtual_machines``, ``hosts``,
``clusters`` …) that this runner maps to the matching vCenter REST endpoint(s),
then flattens the JSON into the same column/row shape
(:class:`assetflow.runner.QueryResult`) that the database, exports, and unified
host view already understand.

Two things distinguish the VMware inventory from the other adapters:

* **Asset kind.** Every object carries an ``asset.type`` column so the estate is
  legible at a glance — VMs are *Virtual Machine* (the virtual servers), ESXi
  hosts are *Physical Host (ESXi)* (the physical servers), plus clusters,
  datastores, and datacenters.

* **Custom fields.** vCenter Custom Attributes are read via pyVmomi (see
  ``vmware_client``) and merged onto each VM / host row under columns prefixed
  ``custom.`` — e.g. ``custom.System Owner`` — so system-provided fields and
  site-defined custom fields are never confused. The custom columns are
  discovered dynamically (the union of attributes present on the objects in
  scope) and appended after the standard columns. When pyVmomi is not installed
  the standard inventory is returned without any ``custom.`` columns.

Every VM / host row emits a ``host.name`` column (the object name) so the rows
fold into the adapter's *All Fetched Results* golden-record view alongside the
other adapters' host-keyed queries.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# Prefix that marks a vCenter Custom Attribute column, distinguishing it from
# the standard (system) fields. Requested by the integration: "put a prefix like
# custom, so I know the system fields and custom fields".
CUSTOM_PREFIX = "custom."

# How many VMs to enrich with per-VM detail / guest-identity REST calls before
# stopping, to bound the number of REST calls on large estates. Every VM is
# still listed with its summary fields and custom attributes; only the extra
# per-VM detail columns stop being filled past this cap.
DEFAULT_VM_DETAIL_SCAN = 200


# --------------------------------------------------------------------------- #
# JSON helpers (tolerant of both /api raw and legacy /rest {"value": …} shapes)
# --------------------------------------------------------------------------- #

def unwrap_items(payload: Any) -> List[dict]:
    """Pull a list of records out of a vCenter REST response.

    The modern ``/api`` endpoints return a bare JSON array; the legacy
    ``/rest`` endpoints wrap it as ``{"value": [...]}``.
    """
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        value = payload.get("value")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def unwrap_obj(payload: Any) -> dict:
    """Pull a single record out of a vCenter REST response (``value`` or raw)."""
    if isinstance(payload, dict):
        value = payload.get("value")
        if isinstance(value, dict):
            return value
        return payload
    return {}


def textish(value: Any) -> str:
    """Render a possibly-nested vCenter field as a compact string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(textish(item) for item in value[:6])
    if isinstance(value, dict):
        # Localizable messages come back as {"default_message": "...", ...}.
        for key in ("default_message", "display_name", "name", "full_name", "value"):
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


def _first_payload(client, paths: Tuple[str, ...]) -> Any:
    """Return the first path that yields a payload, else ``None``."""
    for path in paths:
        try:
            return client.get(path)
        except Exception:  # pragma: no cover - network/endpoint dependent
            continue
    return None


def _optional(client, method: str) -> Dict[str, Dict[str, str]]:
    """Call an optional client method (custom_values / host_hardware) defensively.

    These read through pyVmomi (custom fields, host hardware) which is optional;
    any failure (not installed, no SOAP access) degrades to no enrichment
    rather than failing the whole fetch.
    """
    fn = getattr(client, method, None)
    if not callable(fn):
        return {}
    try:
        data = fn()
    except Exception:  # pragma: no cover - pyVmomi/live dependent
        return {}
    return data if isinstance(data, dict) else {}


def _merge_custom(
    columns: List[str],
    rows: List[List[Any]],
    moids: List[str],
    custom_by_moid: Dict[str, Dict[str, str]],
) -> Tuple[List[str], List[List[Any]]]:
    """Append ``custom.<name>`` columns for every custom attribute in scope.

    ``moids`` is row-aligned with ``rows`` (the object id per row). The set of
    custom columns is the sorted union of attribute names found on those
    objects; each row is padded with its own values (blank where absent).
    """
    names: set = set()
    for moid in moids:
        names.update(custom_by_moid.get(moid, {}).keys())
    if not names:
        return columns, rows
    ordered = sorted(names)
    custom_cols = [f"{CUSTOM_PREFIX}{name}" for name in ordered]
    out_rows: List[List[Any]] = []
    for moid, row in zip(moids, rows):
        values = custom_by_moid.get(moid, {})
        out_rows.append(list(row) + [values.get(name, "") for name in ordered])
    return columns + custom_cols, out_rows


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _collect_virtual_machines(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Inventory every VM (a *virtual server*) with summary, guest, and custom
    fields.

    ``/api/vcenter/vm`` lists all VMs with their summary fields in one call; the
    first ``scan`` VMs are further enriched with ``/vm/{id}`` detail and
    ``/vm/{id}/guest/identity`` (OS, hostname, IP from VMware Tools). Custom
    attributes are merged by moid under ``custom.*`` columns.
    """
    columns = [
        "host.name", "vm.id", "asset.type", "power_state", "cpu.count",
        "memory.mib", "guest.os", "guest.hostname", "host.ip", "guest.family",
    ]
    payload = _first_payload(client, ("vcenter/vm",))
    vms = unwrap_items(payload)
    custom = _optional(client, "custom_values")

    rows: List[List[Any]] = []
    moids: List[str] = []
    for index, vm in enumerate(vms):
        vm_id = str(_first(vm, "vm", "id"))
        name = str(_first(vm, "name") or vm_id)
        guest_os = ""
        guest_host = ""
        guest_ip = ""
        guest_family = ""
        if index < scan and vm_id:
            detail = unwrap_obj(
                _first_payload(client, (f"vcenter/vm/{vm_id}",)) or {}
            )
            guest_os = textish(_first(detail, "guest_OS", "guest_os"))
            identity = unwrap_obj(
                _first_payload(client, (f"vcenter/vm/{vm_id}/guest/identity",)) or {}
            )
            guest_host = textish(_first(identity, "host_name", "hostname"))
            guest_ip = textish(_first(identity, "ip_address", "ip"))
            guest_family = textish(_first(identity, "family"))
            if not guest_os:
                guest_os = textish(_first(identity, "full_name", "name"))
        rows.append([
            name,
            vm_id,
            "Virtual Machine",
            textish(_first(vm, "power_state")),
            textish(_first(vm, "cpu_count")),
            textish(_first(vm, "memory_size_MiB", "memory_size_mib")),
            guest_os,
            guest_host,
            guest_ip,
            guest_family,
        ])
        moids.append(vm_id)
    return _merge_custom(columns, rows, moids, custom)


def _collect_hosts(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Inventory every ESXi host (a *physical server*) with hardware and custom
    fields.

    ``/api/vcenter/host`` lists hosts with their connection/power state; the
    physical hardware detail (vendor, model, CPU, memory, ESXi build, cluster)
    comes from pyVmomi's ``HostSystem.summary`` when available. Custom
    attributes are merged by moid under ``custom.*`` columns.
    """
    columns = [
        "host.name", "host.id", "asset.type", "connection_state", "power_state",
        "hardware.vendor", "hardware.model", "cpu.model", "cpu.cores",
        "memory.gib", "esxi.version", "esxi.build", "cluster",
    ]
    payload = _first_payload(client, ("vcenter/host",))
    hosts = unwrap_items(payload)
    hardware = _optional(client, "host_hardware")
    custom = _optional(client, "custom_values")

    rows: List[List[Any]] = []
    moids: List[str] = []
    for host in hosts:
        host_id = str(_first(host, "host", "id"))
        name = str(_first(host, "name") or host_id)
        hw = hardware.get(host_id, {})
        rows.append([
            name,
            host_id,
            "Physical Host (ESXi)",
            textish(_first(host, "connection_state")),
            textish(_first(host, "power_state")),
            hw.get("vendor", ""),
            hw.get("model", ""),
            hw.get("cpu_model", ""),
            hw.get("cpu_cores", ""),
            hw.get("memory_gib", ""),
            hw.get("version", ""),
            hw.get("build", ""),
            hw.get("cluster", ""),
        ])
        moids.append(host_id)
    return _merge_custom(columns, rows, moids, custom)


def _collect_clusters(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "cluster.id", "asset.type", "ha_enabled", "drs_enabled"]
    clusters = unwrap_items(_first_payload(client, ("vcenter/cluster",)))
    rows = []
    for cluster in clusters:
        cluster_id = str(_first(cluster, "cluster", "id"))
        name = str(_first(cluster, "name") or cluster_id)
        rows.append([
            name,
            cluster_id,
            "Compute Cluster",
            textish(_first(cluster, "ha_enabled")),
            textish(_first(cluster, "drs_enabled")),
        ])
    return columns, rows


def _collect_datastores(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "datastore.id", "asset.type", "datastore.type",
        "capacity.gib", "free.gib",
    ]
    datastores = unwrap_items(_first_payload(client, ("vcenter/datastore",)))
    rows = []
    for ds in datastores:
        ds_id = str(_first(ds, "datastore", "id"))
        name = str(_first(ds, "name") or ds_id)
        rows.append([
            name,
            ds_id,
            "Datastore",
            textish(_first(ds, "type")),
            _to_gib(_first(ds, "capacity")),
            _to_gib(_first(ds, "free_space", "free")),
        ])
    return columns, rows


def _collect_datacenters(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    columns = ["host.name", "datacenter.id", "asset.type"]
    datacenters = unwrap_items(_first_payload(client, ("vcenter/datacenter",)))
    rows = []
    for dc in datacenters:
        dc_id = str(_first(dc, "datacenter", "id"))
        name = str(_first(dc, "name") or dc_id)
        rows.append([name, dc_id, "Datacenter"])
    return columns, rows


def _collect_custom_attributes(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """List the vCenter Custom Attribute *definitions* (what custom fields exist).

    Needs pyVmomi; returns an empty set of rows when it is unavailable.
    """
    columns = ["custom_field.key", "custom_field.name", "applies_to"]
    getter = getattr(client, "custom_field_defs", None)
    defs: List[dict] = []
    if callable(getter):
        try:
            defs = getter() or []
        except Exception:  # pragma: no cover - pyVmomi/live dependent
            defs = []
    rows = [
        [
            textish(_first(d, "key")),
            textish(_first(d, "name")),
            textish(_first(d, "object_type")) or "Global",
        ]
        for d in defs
        if isinstance(d, dict)
    ]
    return columns, rows


def _to_gib(value: Any) -> str:
    """Render a byte count as GiB (vCenter returns capacity/free_space in bytes)."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return ""
    if num <= 0:
        return ""
    return str(round(num / (1024 ** 3), 1))


_COLLECTORS = {
    "virtual_machines": _collect_virtual_machines,
    "hosts": _collect_hosts,
    "clusters": _collect_clusters,
    "datastores": _collect_datastores,
    "datacenters": _collect_datacenters,
    "custom_attributes": _collect_custom_attributes,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
    vm_detail_scan: int = DEFAULT_VM_DETAIL_SCAN,
) -> QueryResult:
    """Fetch a VMware registry query's resource and normalize the response.

    ``time_range`` is accepted for interface parity with the other adapters but
    vCenter inventory is a point-in-time snapshot, so it does not filter rows.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no VMware resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown VMware resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    columns, rows = collector(client, vm_detail_scan)
    return _result(columns, rows, limit)
