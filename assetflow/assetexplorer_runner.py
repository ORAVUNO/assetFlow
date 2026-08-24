"""Fetch ManageEngine AssetExplorer asset intelligence, normalized to ``QueryResult``.

This is the AssetExplorer analogue of ``tenable_sc_runner.py`` / ``vmware_runner.py``.
Each registry query names a ``resource`` that this runner maps to one or more
AssetExplorer v3 REST calls (through :class:`AssetExplorerClient`) and flattens
into the same column/row shape (:class:`assetflow.runner.QueryResult`) the
database, exports, and unified host view already understand.

The resources cover exactly what the integration asked for:

* ``assets`` — the **full asset inventory** from ``GET /api/v3/assets``: one row
  per asset with its default fields (name, IP, state, product, vendor, site,
  department, user, serial, costs, dates …) **and** every site-specific custom
  (UDF) field, each emitted under a ``custom.`` prefix so nothing is dropped. The
  leading ``host.name`` and ``asset.type`` columns fold each asset into the
  unified inventory, and ``asset.type`` carries the asset's **product type**
  (Servers, Routers, Switches, Access Points, Workstations, …).
* the **per-asset-type** resources — ``servers``, ``workstations``,
  ``virtual_machines``, ``routers``, ``switches``, ``firewalls``,
  ``access_points``, ``printers``, ``storage_devices``, ``ups``,
  ``network_devices``, ``clusters``, ``mobile_devices`` — the same asset rows,
  bucketed by product type, so each asset lands in its respective asset type as
  the report does.
* ``cmdb`` — the CMDB configuration items (``GET /api/v3/cmdb/{ci_type}``) across
  the configured CI types, each row stamped with its CI type.
* ``contracts`` — maintenance / lease / warranty contracts (``GET /api/v3/contracts``).
* ``purchases`` — purchase orders (``GET /api/v3/purchase_orders``).
* ``asset_types`` / ``products`` — the product-type / product catalog that
  categorizes assets (``GET /api/v3/asset_types`` / ``/products``).

**Custom fields.** Any field AssetExplorer returns for an asset that this runner
does not map to a named column — every ``udf_fields`` entry and any extra scalar
top-level key — is still emitted, under a column prefixed ``custom.`` (the same
convention the SolarWinds, VMware, and Tenable.sc adapters use), so the site's UDF
fields ride along and are never confused with the standard system columns.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# Prefix marking an unmapped (extra / site-specific) field — a UDF or any other
# key the runner doesn't name — so it is never confused with the system columns.
CUSTOM_PREFIX = "custom."


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

def textish(value: Any) -> str:
    """Render an AssetExplorer field as a compact string.

    AssetExplorer nests many fields as objects (``state``, ``vendor``,
    ``department`` …) and dates as ``{"value", "display_value"}``; those are
    summarized to their human-readable form.
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
        # A date field: prefer the human display value, else convert the epoch.
        if "display_value" in value or ("value" in value and len(value) <= 2):
            disp = value.get("display_value")
            if disp:
                return textish(disp)
            return _epoch_millis(value.get("value"))
        for key in ("name", "display_name", "display_value", "value", "label",
                    "email_id", "first_name"):
            if value.get(key):
                return textish(value[key])
        return ", ".join(f"{k}={textish(v)}" for k, v in list(value.items())[:4])
    return str(value)


def _name(value: Any) -> str:
    """Name of a nested object field (``{"id":.., "name":..}``) or its string."""
    if isinstance(value, dict):
        return textish(value.get("name") or value.get("display_name")
                       or value.get("display_value") or "")
    return textish(value)


def _epoch_millis(value: Any) -> str:
    """Convert an AssetExplorer epoch-milliseconds field to ISO-8601 UTC.

    AssetExplorer returns timestamps as Unix epoch **milliseconds** (often as
    strings), with ``0`` / ``-1`` meaning "unset". Non-numeric values are returned
    unchanged so a value that is already a date string is not mangled.
    """
    if value in (None, "", "-1", "0", -1, 0):
        return ""
    try:
        millis = int(value)
    except (TypeError, ValueError):
        return textish(value)
    if millis <= 0:
        return ""
    try:
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, OSError, ValueError):  # pragma: no cover - defensive
        return textish(value)


def _date(value: Any) -> str:
    """Render an AssetExplorer date field (object or epoch-millis) as a string."""
    if isinstance(value, dict):
        return textish(value)  # textish handles the {value, display_value} shape
    return _epoch_millis(value)


def _pick(record: Dict[str, Any], *keys: str) -> Any:
    """First present, non-empty value among ``keys`` (fields AssetExplorer renames
    across releases / product types)."""
    for key in keys:
        if key in record:
            val = record.get(key)
            if val not in (None, ""):
                return val
    return ""


def _result(columns: List[str], rows: List[List[Any]], limit: Optional[int]) -> QueryResult:
    if limit is not None:
        rows = rows[: int(limit)]
    return QueryResult(columns=[{"name": c} for c in columns], rows=rows)


def _product_type(asset: Dict[str, Any]) -> str:
    """The asset's product type — the fine category that buckets it into an asset
    type (Servers / Routers / Switches / Access Points / …).

    AssetExplorer exposes it either directly as ``product_type`` or nested under
    ``product.product_type``; both are checked.
    """
    pt = asset.get("product_type")
    name = _name(pt)
    if name:
        return name
    product = asset.get("product")
    if isinstance(product, dict):
        return _name(product.get("product_type"))
    return ""


# --------------------------------------------------------------------------- #
# Asset flattening (named default columns + custom.* sweep over UDFs & extras)
# --------------------------------------------------------------------------- #

# The named default columns, as (output column, extractor). Each extractor reads
# the asset dict with per-release / per-product-type key fallbacks, so the same
# mapping works across AssetExplorer versions. Everything NOT consumed here (every
# udf_fields entry and any other scalar key) is swept into custom.* below.
_ASSET_SPEC: Tuple[Tuple[str, Any], ...] = (
    ("asset.tag", lambda a: textish(_pick(a, "asset_tag", "assettag"))),
    ("resource.type", lambda a: _name(_pick(a, "type", "asset_category"))),
    ("asset.category", lambda a: _name(_pick(a, "category", "asset_category"))),
    ("asset.state", lambda a: _name(_pick(a, "state", "asset_state"))),
    ("host.ip", lambda a: textish(_pick(a, "ip_address", "ip_addresses", "ipaddress"))),
    ("mac", lambda a: textish(_pick(a, "mac_address", "macaddress"))),
    ("os", lambda a: _name(_pick(a, "operating_system", "os"))),
    ("product", lambda a: _name(_pick(a, "product"))),
    ("vendor", lambda a: _name(_pick(a, "vendor", "manufacturer"))),
    ("serial.number", lambda a: textish(_pick(a, "serial_number", "serialnumber", "serial_no"))),
    ("barcode", lambda a: textish(_pick(a, "barcode"))),
    ("department", lambda a: _name(_pick(a, "department", "dept"))),
    ("site", lambda a: _name(_pick(a, "site"))),
    ("location", lambda a: _name(_pick(a, "location"))),
    ("region", lambda a: _name(_pick(a, "region"))),
    ("assigned.user", lambda a: _name(_pick(a, "user", "assigned_to", "assigned_user"))),
    ("technical.owner", lambda a: _name(_pick(a, "managed_by", "asset_owner", "owner"))),
    ("acquisition.date", lambda a: _date(_pick(a, "acquisition_date", "acquisitiondate"))),
    ("expiry.date", lambda a: _date(_pick(a, "warranty_expiry", "expiry_date", "expirydate"))),
    ("purchase.cost", lambda a: textish(_pick(a, "purchase_cost", "cost"))),
    ("total.cost", lambda a: textish(_pick(a, "total_cost"))),
    ("operational.cost", lambda a: textish(_pick(a, "operational_cost"))),
    ("current.cost", lambda a: textish(_pick(a, "current_cost", "current_book_value"))),
    ("last.audit", lambda a: _date(_pick(a, "last_audit_on", "last_scan", "last_audit"))),
    ("created.date", lambda a: _date(_pick(a, "created_time", "created_date"))),
    ("updated.date", lambda a: _date(_pick(a, "last_updated_time", "updated_at", "last_modified"))),
)

# Top-level keys already consumed by the named columns (or read via _pick
# fallbacks / the type/name columns) — excluded from the custom.* sweep so extra
# fields are captured without duplicating the named ones.
_ASSET_CONSUMED = {
    "id", "name", "udf_fields",
    "asset_tag", "assettag", "type", "asset_category", "category",
    "state", "asset_state", "ip_address", "ip_addresses", "ipaddress",
    "mac_address", "macaddress", "operating_system", "os",
    "product", "product_type", "vendor", "manufacturer",
    "serial_number", "serialnumber", "serial_no", "barcode",
    "department", "dept", "site", "location", "region",
    "user", "assigned_to", "assigned_user", "managed_by", "asset_owner", "owner",
    "acquisition_date", "acquisitiondate", "warranty_expiry", "expiry_date",
    "expirydate", "purchase_cost", "cost", "total_cost", "operational_cost",
    "current_cost", "current_book_value", "last_audit_on", "last_scan",
    "last_audit", "created_time", "created_date", "last_updated_time",
    "updated_at", "last_modified",
}


def _flatten_assets(
    assets: List[Dict[str, Any]],
) -> Tuple[List[str], List[List[Any]]]:
    """Flatten asset records into (columns, rows) with a ``custom.*`` sweep.

    Leading ``host.name`` + ``asset.type`` fold the asset into the unified
    inventory (``asset.type`` = product type). Standard columns come from
    ``_ASSET_SPEC``; every ``udf_fields`` entry and any other scalar top-level key
    is appended as ``custom.<key>`` (discovered as the union across assets, so
    site-specific UDFs ride along), keeping first-seen order for stable columns.
    """
    # Discover custom keys: all udf_fields keys, then any extra scalar top-level
    # keys, as the union across records (stable, first-seen order).
    custom_keys: List[str] = []
    seen_custom = set()

    def _note(key: str) -> None:
        if key not in seen_custom:
            seen_custom.add(key)
            custom_keys.append(key)

    for asset in assets:
        udf = asset.get("udf_fields")
        if isinstance(udf, dict):
            for key in udf.keys():
                _note(key)
        for key, val in asset.items():
            if key in _ASSET_CONSUMED or isinstance(val, (list, dict)):
                continue
            _note(key)

    columns = ["host.name", "asset.type"]
    columns.extend(out for out, _ in _ASSET_SPEC)
    columns.extend(f"{CUSTOM_PREFIX}{k}" for k in custom_keys)

    rows: List[List[Any]] = []
    for asset in assets:
        name = textish(_pick(asset, "name", "asset_name"))
        row: List[Any] = [name, _product_type(asset) or "Asset"]
        for _, extract in _ASSET_SPEC:
            row.append(extract(asset))
        udf = asset.get("udf_fields")
        udf = udf if isinstance(udf, dict) else {}
        for key in custom_keys:
            if key in udf:
                row.append(textish(udf.get(key)))
            else:
                row.append(textish(asset.get(key)))
        rows.append(row)
    return columns, rows


# --------------------------------------------------------------------------- #
# Asset-type buckets — categorize assets by product type
# --------------------------------------------------------------------------- #

# resource name -> product-type keywords (lower-case, substring match). Mirrors the
# CI types the sample report separates assets into. An asset is in a bucket when
# its product type contains any of the bucket's keywords.
ASSET_TYPE_BUCKETS: Dict[str, Tuple[str, ...]] = {
    "servers": ("server", "mainframe", "esx", "blade", "vcenter"),
    "workstations": ("workstation", "desktop", "laptop", "notebook", "pc"),
    "virtual_machines": ("virtual machine", "virtual server", "vm", "guest"),
    "clusters": ("cluster",),
    "routers": ("router",),
    "switches": ("switch",),
    "firewalls": ("firewall",),
    "access_points": ("access point", "wireless", "wlan", "wap"),
    "printers": ("printer", "mfp", "scanner", "copier"),
    "storage_devices": ("storage", "san", "nas", "tape", "disk array"),
    "ups": ("ups", "power supply", "pdu"),
    "network_devices": ("router", "switch", "firewall", "access point", "wireless",
                        "load balancer", "gateway", "modem", "ntp", "network",
                        "sensor", "encoder"),
    "mobile_devices": ("mobile", "phone", "tablet", "ipad", "iphone", "android",
                       "smartphone"),
}


def _matches_bucket(product_type: str, keywords: Tuple[str, ...]) -> bool:
    low = (product_type or "").lower()
    return any(k in low for k in keywords)


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _fetch_assets(client) -> List[Dict[str, Any]]:
    """The full asset inventory (``GET /api/v3/assets``, paged)."""
    return client.list("assets", "assets")


def _collect_assets(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Every asset, flattened with default + custom (UDF) columns."""
    return _flatten_assets(_fetch_assets(client))


def _bucket_collector(keywords: Tuple[str, ...]):
    """Build a collector that returns only the assets whose product type matches."""
    def _collect(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
        assets = [a for a in _fetch_assets(client)
                  if _matches_bucket(_product_type(a), keywords)]
        return _flatten_assets(assets)
    return _collect


# CI types fetched by the CMDB resource (``GET /api/v3/cmdb/{ci_type}``). AssetExplorer
# keys each CI type by an api name; the common IT CI types are tried best-effort and
# the ones a deployment doesn't have simply contribute no rows. Override the set with
# AE_CMDB_CI_TYPES (comma-separated api names).
_DEFAULT_CI_TYPES = (
    "business_service", "server", "workstation", "virtual_machine", "cluster",
    "router", "switch", "firewall", "access_point", "printer", "storage",
    "ups", "network_device", "database", "application", "rack",
)


def _ci_types() -> Tuple[str, ...]:
    override = (os.getenv("AE_CMDB_CI_TYPES") or "").strip()
    if override:
        return tuple(t.strip() for t in override.split(",") if t.strip())
    return _DEFAULT_CI_TYPES


def _flatten_generic(
    records: List[Dict[str, Any]],
    lead: List[Tuple[str, Any]],
    consumed: set,
) -> Tuple[List[str], List[List[Any]]]:
    """Flatten arbitrary v3 records: named ``lead`` columns + a custom.* sweep of
    every other scalar key (and udf_fields), union across records."""
    custom_keys: List[str] = []
    seen = set()
    for rec in records:
        udf = rec.get("udf_fields")
        if isinstance(udf, dict):
            for key in udf.keys():
                if key not in seen:
                    seen.add(key)
                    custom_keys.append(key)
        for key, val in rec.items():
            if key in consumed or key == "udf_fields" or isinstance(val, (list, dict)):
                continue
            if key not in seen:
                seen.add(key)
                custom_keys.append(key)

    columns = [name for name, _ in lead] + [f"{CUSTOM_PREFIX}{k}" for k in custom_keys]
    rows: List[List[Any]] = []
    for rec in records:
        row = [fn(rec) for _, fn in lead]
        udf = rec.get("udf_fields")
        udf = udf if isinstance(udf, dict) else {}
        for key in custom_keys:
            row.append(textish(udf.get(key)) if key in udf else textish(rec.get(key)))
        rows.append(row)
    return columns, rows


def _collect_cmdb(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """CMDB configuration items across the configured CI types.

    Each CI type is fetched via ``GET /api/v3/cmdb/{ci_type}`` (best-effort: a CI
    type the deployment doesn't have simply contributes no rows), and every row is
    stamped with its CI type in ``ci.type`` / ``asset.type`` so the CIs land in
    their respective type in the unified inventory.
    """
    records: List[Dict[str, Any]] = []
    for ci_type in _ci_types():
        try:
            rows = client.list(f"cmdb/{ci_type}", ci_type)
        except Exception:  # pragma: no cover - per-type availability varies
            continue
        for rec in rows:
            if isinstance(rec, dict):
                rec = dict(rec)
                rec.setdefault("_ci_type", ci_type)
                records.append(rec)

    lead: List[Tuple[str, Any]] = [
        ("host.name", lambda r: textish(_pick(r, "name", "ci_name"))),
        ("asset.type", lambda r: _name(_pick(r, "ci_type", "type")) or textish(r.get("_ci_type"))),
        ("ci.type", lambda r: _name(_pick(r, "ci_type", "type")) or textish(r.get("_ci_type"))),
        ("host.ip", lambda r: textish(_pick(r, "ip_address", "ipaddress"))),
        ("asset.state", lambda r: _name(_pick(r, "state", "status", "impact"))),
        ("site", lambda r: _name(_pick(r, "site"))),
        ("department", lambda r: _name(_pick(r, "department"))),
        ("product", lambda r: _name(_pick(r, "product"))),
        ("serial.number", lambda r: textish(_pick(r, "serial_number", "serial_no"))),
        ("updated.date", lambda r: _date(_pick(r, "last_updated_time", "updated_at"))),
    ]
    consumed = {
        "id", "name", "ci_name", "ci_type", "type", "_ci_type", "ip_address",
        "ipaddress", "state", "status", "impact", "site", "department", "product",
        "serial_number", "serial_no", "last_updated_time", "updated_at",
    }
    return _flatten_generic(records, lead, consumed)


def _collect_contracts(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Maintenance / lease / warranty contracts (``GET /api/v3/contracts``)."""
    records = client.list("contracts", "contracts")
    lead: List[Tuple[str, Any]] = [
        ("host.name", lambda r: textish(_pick(r, "name", "contract_name"))),
        ("asset.type", lambda r: "Contract"),
        ("contract.id", lambda r: textish(_pick(r, "id", "contract_id"))),
        ("contract.type", lambda r: _name(_pick(r, "type", "contract_type"))),
        ("status", lambda r: _name(_pick(r, "status", "active"))),
        ("vendor", lambda r: _name(_pick(r, "vendor", "supplier"))),
        ("maintenance.vendor", lambda r: _name(_pick(r, "maintenance_vendor"))),
        ("owner", lambda r: _name(_pick(r, "owner", "user"))),
        ("cost", lambda r: textish(_pick(r, "cost", "contract_cost"))),
        ("start.date", lambda r: _date(_pick(r, "active_from", "start_date", "from_date"))),
        ("end.date", lambda r: _date(_pick(r, "expiry_date", "active_to", "end_date", "to_date"))),
        ("notify.date", lambda r: _date(_pick(r, "notify_date", "notification_date"))),
    ]
    consumed = {
        "id", "contract_id", "name", "contract_name", "type", "contract_type",
        "status", "active", "vendor", "supplier", "maintenance_vendor", "owner",
        "user", "cost", "contract_cost", "active_from", "start_date", "from_date",
        "expiry_date", "active_to", "end_date", "to_date", "notify_date",
        "notification_date",
    }
    return _flatten_generic(records, lead, consumed)


def _collect_purchases(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """Purchase orders (``GET /api/v3/purchase_orders``)."""
    records = client.list("purchase_orders", "purchase_orders")
    lead: List[Tuple[str, Any]] = [
        ("host.name", lambda r: textish(_pick(r, "name", "po_name", "po_number"))),
        ("asset.type", lambda r: "Purchase Order"),
        ("po.id", lambda r: textish(_pick(r, "id", "po_id"))),
        ("po.number", lambda r: textish(_pick(r, "po_number", "order_number"))),
        ("status", lambda r: _name(_pick(r, "status", "po_status"))),
        ("vendor", lambda r: _name(_pick(r, "vendor", "supplier"))),
        ("owner", lambda r: _name(_pick(r, "owner", "requester", "created_by"))),
        ("total.cost", lambda r: textish(_pick(r, "total_cost", "grand_total", "total_price"))),
        ("ordered.date", lambda r: _date(_pick(r, "order_date", "created_time", "po_date"))),
        ("expected.date", lambda r: _date(_pick(r, "expected_delivery_date", "delivery_date"))),
    ]
    consumed = {
        "id", "po_id", "name", "po_name", "po_number", "order_number", "status",
        "po_status", "vendor", "supplier", "owner", "requester", "created_by",
        "total_cost", "grand_total", "total_price", "order_date", "created_time",
        "po_date", "expected_delivery_date", "delivery_date",
    }
    return _flatten_generic(records, lead, consumed)


def _collect_asset_types(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """The product-type / asset-type catalog (``GET /api/v3/asset_types``)."""
    records = client.list("asset_types", "asset_types")
    lead: List[Tuple[str, Any]] = [
        ("asset.type", lambda r: textish(_pick(r, "name", "display_name"))),
        ("type.id", lambda r: textish(_pick(r, "id"))),
        ("category", lambda r: _name(_pick(r, "type", "category", "asset_category"))),
        ("parent", lambda r: _name(_pick(r, "parent_asset_type", "parent"))),
        ("accessibility", lambda r: textish(_pick(r, "accessibility"))),
    ]
    consumed = {"id", "name", "display_name", "type", "category", "asset_category",
                "parent_asset_type", "parent", "accessibility"}
    return _flatten_generic(records, lead, consumed)


def _collect_products(client, time_range: Optional[str]) -> Tuple[List[str], List[List[Any]]]:
    """The product catalog (``GET /api/v3/products``)."""
    records = client.list("products", "products")
    lead: List[Tuple[str, Any]] = [
        ("product", lambda r: textish(_pick(r, "name"))),
        ("product.id", lambda r: textish(_pick(r, "id"))),
        ("product.type", lambda r: _name(_pick(r, "product_type", "asset_type"))),
        ("category", lambda r: _name(_pick(r, "type", "category"))),
        ("manufacturer", lambda r: _name(_pick(r, "manufacturer", "vendor"))),
        ("part.number", lambda r: textish(_pick(r, "part_no", "part_number"))),
    ]
    consumed = {"id", "name", "product_type", "asset_type", "type", "category",
                "manufacturer", "vendor", "part_no", "part_number"}
    return _flatten_generic(records, lead, consumed)


# Build the collector table: the fixed resources plus one per asset-type bucket.
_COLLECTORS = {
    "assets": _collect_assets,
    "cmdb": _collect_cmdb,
    "contracts": _collect_contracts,
    "purchases": _collect_purchases,
    "asset_types": _collect_asset_types,
    "products": _collect_products,
}
for _name_, _keywords_ in ASSET_TYPE_BUCKETS.items():
    _COLLECTORS[_name_] = _bucket_collector(_keywords_)


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> QueryResult:
    """Fetch an AssetExplorer registry query's resource and normalize the response.

    AssetExplorer's inventory is point-in-time, so ``time_range`` is accepted (for
    interface parity with the other adapters) but not applied.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no AssetExplorer resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown AssetExplorer resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    columns, rows = collector(client, time_range)
    return _result(columns, rows, limit)
