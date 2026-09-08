"""Fetch BMC Remedy AR System / Atrium CMDB records and normalize them.

This is the BMC Remedy analogue of ``runner.py`` / ``vmware_runner.py``. Each
registry query names a ``resource`` (``computer_systems``, ``software``,
``business_services``, ``people``, ``incidents``, ``changes``) that this runner
maps to a BMC Remedy AR *form* (see ``config/remedy_registry.yaml``), then
flattens the entry ``values`` into the same column/row shape
(:class:`assetflow.runner.QueryResult`) that the database, exports, and unified
host view already understand.

Two things distinguish the Remedy inventory:

* **Asset kind.** Every row carries an ``asset.type`` column so the estate is
  legible at a glance — CMDB computer systems are classified *Server* /
  *Workstation* / *Computer System* from their ``SystemRole``, software is
  *Software*, and so on.

* **Custom fields.** AR forms routinely carry site-added fields. The entry
  ``values`` come back keyed by field label; any label this runner does not map
  to a standard column (and that is not internal AR plumbing) is emitted as its
  own column prefixed ``custom.`` — e.g. ``custom.Cost Center`` — so
  system-provided fields and site-defined custom fields are never confused. The
  custom columns are discovered dynamically (the union of extra fields present
  on the rows in scope) and appended after the standard columns.

Asset-bearing rows (computer systems, software, business services, people) emit
a ``host.name`` column so they fold into the adapter's *All Fetched Results*
golden-record view alongside the other adapters' host-keyed queries.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .models import Query
from .runner import QueryResult

# Prefix marking a site-added (custom) AR field, distinguishing it from the
# standard fields — the same convention the VMware / AssetExplorer adapters use.
CUSTOM_PREFIX = "custom."

# Common AR System plumbing / display-only fields that should never surface as
# "custom" columns. The ``z``-prefix heuristic below additionally drops Remedy's
# temporary / workflow display fields (zTmp*, z1D*, z2AF* …).
_IGNORE_FIELDS: Set[str] = {
    "Request ID",
    "Submitter",
    "Submit Date",
    "Assignee Login ID",
    "Last Modified By",
    "Modified Date",
    "Status History",
    "Short Description",
    "InstanceId",
    "Reconciliation Identity",
    "GUID",
    "Object ID",
    "ClassId",
    "DatasetId",
    "AttributeDataSourceList",
    "MarkAsDeleted",
}


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

def textish(value: Any) -> str:
    """Render an AR field value as a compact string."""
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
        for key in ("value", "name", "display", "label"):
            if value.get(key):
                return textish(value[key])
        return ", ".join(f"{k}={textish(v)}" for k, v in list(value.items())[:4])
    return str(value)


def values_of(entry: dict) -> dict:
    """Pull the field ``values`` mapping out of an AR entry record."""
    if not isinstance(entry, dict):
        return {}
    values = entry.get("values")
    return values if isinstance(values, dict) else {}


def g(values: dict, *labels: str) -> str:
    """First non-empty field value among ``labels`` (rendered as text)."""
    for label in labels:
        if label in values:
            text = textish(values[label])
            if text != "":
                return text
    return ""


def _custom_fields(values: dict, consumed: Set[str]) -> Dict[str, str]:
    """Every non-empty field not already mapped and not AR plumbing."""
    out: Dict[str, str] = {}
    for label, raw in values.items():
        if not label or label in consumed or label in _IGNORE_FIELDS:
            continue
        # Remedy names transient / workflow / display-only fields with a leading
        # 'z' (zTmp, z1D, z2AF …); these are UI plumbing, not real attributes.
        if label[0] in ("z", "Z"):
            continue
        text = textish(raw)
        if text == "":
            continue
        out[label] = text
    return out


def _result(columns: List[str], rows: List[List[Any]], limit: Optional[int]) -> QueryResult:
    if limit is not None:
        rows = rows[: int(limit)]
    return QueryResult(columns=[{"name": c} for c in columns], rows=rows)


# A row builder returns the standard cell values plus the set of AR field labels
# it consumed (so those are not re-emitted as custom columns).
RowFn = Callable[[dict], Tuple[List[Any], Set[str]]]


def _build(
    entries: List[dict], columns: List[str], row_fn: RowFn
) -> Tuple[List[str], List[List[Any]]]:
    """Assemble standard columns + a sorted union of ``custom.*`` columns."""
    std_rows: List[List[Any]] = []
    custom_maps: List[Dict[str, str]] = []
    custom_names: Set[str] = set()
    for entry in entries:
        values = values_of(entry)
        std, consumed = row_fn(values)
        custom = _custom_fields(values, consumed)
        std_rows.append(std)
        custom_maps.append(custom)
        custom_names.update(custom.keys())
    ordered = sorted(custom_names)
    cols = list(columns) + [f"{CUSTOM_PREFIX}{name}" for name in ordered]
    rows: List[List[Any]] = []
    for std, custom in zip(std_rows, custom_maps):
        rows.append(list(std) + [custom.get(name, "") for name in ordered])
    return cols, rows


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

def _computer_asset_type(values: dict) -> str:
    """Classify a CMDB computer system from its SystemRole / CTI."""
    role = g(values, "SystemRole").lower()
    if role:
        if "server" in role:
            return "Server"
        if any(k in role for k in ("client", "workstation", "desktop", "laptop")):
            return "Workstation"
    item = g(values, "Item")
    typ = g(values, "Type")
    return item or typ or "Computer System"


# Standard field labels each computer-system row consumes (kept out of custom.*).
_CS_CONSUMED = {
    "Name", "SystemRole", "Item", "Type", "Category", "HostName", "Domain",
    "Manufacturer", "Model", "SerialNumber", "AssetLifecycleStatus", "Company",
    "Region", "Site", "OwnerName", "SupportGroupName", "IPAddress",
}


def _collect_computer_systems(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "asset.type", "host.hostname", "host.ip", "domain",
        "manufacturer", "model", "serial_number", "category", "type", "item",
        "lifecycle_status", "company", "region", "site", "owner",
    ]
    entries = client.get_entries(form)

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        return [
            g(values, "Name"),
            _computer_asset_type(values),
            g(values, "HostName"),
            g(values, "IPAddress"),
            g(values, "Domain"),
            g(values, "Manufacturer"),
            g(values, "Model"),
            g(values, "SerialNumber"),
            g(values, "Category"),
            g(values, "Type"),
            g(values, "Item"),
            g(values, "AssetLifecycleStatus"),
            g(values, "Company"),
            g(values, "Region"),
            g(values, "Site"),
            g(values, "OwnerName", "SupportGroupName"),
        ], _CS_CONSUMED

    return _build(entries, columns, row)


def _collect_software(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "asset.type", "version", "manufacturer", "category",
        "type", "item", "lifecycle_status", "company",
    ]
    entries = client.get_entries(form)
    consumed = {
        "Name", "MarketVersion", "VersionNumber", "Manufacturer", "Category",
        "Type", "Item", "AssetLifecycleStatus", "Company",
    }

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        return [
            g(values, "Name"),
            "Software",
            g(values, "MarketVersion", "VersionNumber"),
            g(values, "Manufacturer"),
            g(values, "Category"),
            g(values, "Type"),
            g(values, "Item"),
            g(values, "AssetLifecycleStatus"),
            g(values, "Company"),
        ], consumed

    return _build(entries, columns, row)


def _collect_business_services(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "asset.type", "description", "status", "company", "owner",
    ]
    entries = client.get_entries(form)
    consumed = {
        "Name", "Description", "AssetLifecycleStatus", "Status", "Company",
        "OwnerName", "SupportGroupName",
    }

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        return [
            g(values, "Name"),
            "Business Service",
            g(values, "Description"),
            g(values, "AssetLifecycleStatus", "Status"),
            g(values, "Company"),
            g(values, "OwnerName", "SupportGroupName"),
        ], consumed

    return _build(entries, columns, row)


def _collect_people(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "host.name", "asset.type", "corporate_id", "email", "phone",
        "organization", "department", "site", "company", "support_staff",
    ]
    entries = client.get_entries(form)
    consumed = {
        "Full Name", "First Name", "Last Name", "Corporate ID", "Internet E-mail",
        "Phone Number Business", "Organization", "Department", "Site", "Company",
        "Support Staff",
    }

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        full = g(values, "Full Name")
        if not full:
            first = g(values, "First Name")
            last = g(values, "Last Name")
            full = " ".join(p for p in (first, last) if p)
        return [
            full,
            "Person",
            g(values, "Corporate ID"),
            g(values, "Internet E-mail"),
            g(values, "Phone Number Business"),
            g(values, "Organization"),
            g(values, "Department"),
            g(values, "Site"),
            g(values, "Company"),
            g(values, "Support Staff"),
        ], consumed

    return _build(entries, columns, row)


def _collect_incidents(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "incident.id", "asset.type", "summary", "status", "priority", "impact",
        "urgency", "service", "ci.name", "assignee", "submit_date",
    ]
    entries = client.get_entries(form)
    consumed = {
        "Incident Number", "Description", "Status", "Priority", "Impact",
        "Urgency", "Service Type", "HPD_CI", "Assignee", "Submit Date",
    }

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        return [
            g(values, "Incident Number"),
            "Incident",
            g(values, "Description"),
            g(values, "Status"),
            g(values, "Priority"),
            g(values, "Impact"),
            g(values, "Urgency"),
            g(values, "Service Type"),
            g(values, "HPD_CI"),
            g(values, "Assignee"),
            g(values, "Submit Date"),
        ], consumed

    return _build(entries, columns, row)


def _collect_changes(client, form: str) -> Tuple[List[str], List[List[Any]]]:
    columns = [
        "change.id", "asset.type", "summary", "status", "risk_level", "priority",
        "coordinator_group", "scheduled_start", "scheduled_end",
    ]
    entries = client.get_entries(form)
    consumed = {
        "Infrastructure Change ID", "Change Request ID", "Description",
        "Change Request Status", "Risk Level", "Priority",
        "Change Coordinator Group", "Scheduled Start Date", "Scheduled End Date",
    }

    def row(values: dict) -> Tuple[List[Any], Set[str]]:
        return [
            g(values, "Infrastructure Change ID", "Change Request ID"),
            "Change Request",
            g(values, "Description"),
            g(values, "Change Request Status"),
            g(values, "Risk Level"),
            g(values, "Priority"),
            g(values, "Change Coordinator Group"),
            g(values, "Scheduled Start Date"),
            g(values, "Scheduled End Date"),
        ], consumed

    return _build(entries, columns, row)


_COLLECTORS: Dict[str, Callable[[Any, str], Tuple[List[str], List[List[Any]]]]] = {
    "computer_systems": _collect_computer_systems,
    "software": _collect_software,
    "business_services": _collect_business_services,
    "people": _collect_people,
    "incidents": _collect_incidents,
    "changes": _collect_changes,
}

# Resource name -> the AR form it reads. The form is fixed per resource here so
# the registry stays declarative (a query only names its resource).
_RESOURCE_FORMS: Dict[str, str] = {
    "computer_systems": "BMC.CORE:BMC_ComputerSystem",
    "software": "BMC.CORE:BMC_Product",
    "business_services": "BMC.CORE:BMC_BusinessService",
    "people": "CTM:People",
    "incidents": "HPD:Help Desk",
    "changes": "CHG:Infrastructure Change",
}


def form_for_resource(resource: str) -> str:
    """Return the AR form name a resource reads (raises for unknown resources)."""
    try:
        return _RESOURCE_FORMS[resource]
    except KeyError:
        raise ValueError(
            f"unknown BMC Remedy resource {resource!r}; known resources: "
            f"{', '.join(sorted(_RESOURCE_FORMS))}"
        )


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
) -> QueryResult:
    """Fetch a Remedy registry query's resource and normalize the response.

    ``time_range`` is accepted for interface parity with the other adapters but
    Remedy inventory is a point-in-time read, so it does not filter rows.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no Remedy resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown Remedy resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    form = form_for_resource(resource)
    columns, rows = collector(client, form)
    return _result(columns, rows, limit)
