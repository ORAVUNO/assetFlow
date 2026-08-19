"""Fetch SolarWinds Orion / NCM inventory and posture, normalized to ``QueryResult``.

This is the SolarWinds analogue of ``tufin_runner.py`` / ``vmware_runner.py``.
Each registry query names a ``resource`` that this runner maps to one or more
**SWQL** statements (run through :meth:`SolarWindsClient.query`), then flattens
the results into the same column/row shape
(:class:`assetflow.runner.QueryResult`) the database, exports, and unified host
view already understand.

The adapter answers two questions the integration note asked for:

* **Full inventory, typed.** ``nodes`` inventories every device Orion monitors —
  routers, switches, firewalls, load balancers, wireless controllers, servers,
  … — tagging each with a derived ``asset.type`` (from vendor / machine type /
  poll method) so the estate is legible at a glance, and merging every
  SolarWinds **custom property** onto the row under columns prefixed ``custom.``
  so system fields and site-defined custom fields are never confused.

* **Configuration posture and change, beyond inventory.** Through SolarWinds
  **NCM** (Network Configuration Manager):
    - ``config_inventory`` — the current config posture: the latest running /
      startup config version per device, when it was captured, and whether it is
      the approved baseline (``NCM.ConfigArchive``).
    - ``change_detail`` — *what changed* in a device's configuration, computed by
      diffing consecutive archived configs line by line (added / removed lines),
      with the change time. This resource feeds the deduplicated change log and
      supports the "since last check" incremental mode via a per-node watermark,
      exactly like the Tufin change detector.
    - ``policy_violations`` — the compliance posture: which devices violate which
      NCM policy rules (``NCM.PolicyReportResults`` and friends).

Node-scoped resources emit a ``host.name`` column so their rows fold into the
adapter's *All Fetched Results* golden-record view alongside the other adapters.

Entity names differ across SolarWinds Platform releases (the modern ``NCM.*``
namespace vs. the legacy ``Cirrus.*`` one), and custom-property columns are
site-specific, so — as in the Tufin/VMware runners — each collector tries a
couple of entity/field variants and discovers columns defensively rather than
assuming one fixed schema.
"""

from __future__ import annotations

import difflib
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from .models import Query
from .runner import QueryResult

# Prefix that marks a SolarWinds custom property column, distinguishing it from
# the standard (system) fields. Requested by the integration: "for custom fields
# i would like you to put a prefix like custom, so i know the system fields and
# custom fields".
CUSTOM_PREFIX = "custom."

# SWIS pagination page size for the big node listing.
SWIS_PAGE_SIZE = 1000

# How many NCM nodes a config resource scans before stopping, to bound the number
# of (potentially large) config-text fetches on big estates.
DEFAULT_NODE_SCAN = 100

# Cap on config-diff rows emitted per node in one fetch, so a device whose whole
# config was replaced cannot fan out into thousands of change rows.
MAX_CONFIG_CHANGE_LINES = 500

# Time-range tokens that select the change-detail "since last check" mode.
INCREMENTAL_TOKENS = {"incremental", "since", "new"}

# Base (non-custom) columns of Orion.NodesCustomProperties — everything else the
# entity exposes is a site-defined custom property.
_CP_BASE_COLUMNS = {
    "nodeid", "instancetype", "uri", "instancesiteid", "displayname", "description",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def textish(value: Any) -> str:
    """Render a SWIS field as a compact string."""
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
        for key in ("DisplayName", "Caption", "Name", "value"):
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


def _first_query(client, swqls: Tuple[str, ...]) -> List[Dict[str, Any]]:
    """Return rows from the first SWQL variant that runs without error.

    A bad entity/field raises (HTTP 400 surfaced by the client); the next variant
    is tried. Returns ``[]`` when every variant fails (e.g. NCM not licensed).
    """
    for swql in swqls:
        try:
            return client.query_rows(swql)
        except Exception:  # pragma: no cover - network/schema dependent
            continue
    return []


def _paged_rows(
    client, swql: str, page_size: int = SWIS_PAGE_SIZE, max_rows: int = 100000
) -> List[Dict[str, Any]]:
    """Page a SWQL statement with ``WITH ROWS … WITH TOTALROWS``.

    ``swql`` must already carry its ``ORDER BY`` (the paging clause follows it).
    If the server rejects the paging clause for this entity, falls back to a
    single unpaged fetch.
    """
    all_rows: List[Dict[str, Any]] = []
    start = 1
    while True:
        end = start + page_size - 1
        paged = f"{swql} WITH ROWS {start} TO {end} WITH TOTALROWS"
        try:
            data = client.query(paged)
        except Exception:  # pragma: no cover - schema/version dependent
            if start == 1:
                # Paging unsupported here — take one plain page instead.
                try:
                    return client.query_rows(swql)
                except Exception:
                    return all_rows
            break
        rows = [r for r in (data.get("results") or []) if isinstance(r, dict)]
        if not rows:
            break
        all_rows.extend(rows)
        total = data.get("totalRows") or 0
        if len(all_rows) >= max_rows:
            break
        if total and len(all_rows) >= total:
            break
        if len(rows) < page_size:
            break
        start += page_size
    return all_rows


# --------------------------------------------------------------------------- #
# Node classification (router / switch / firewall / server / …)
# --------------------------------------------------------------------------- #

# (asset type, matching tokens) — checked in order, first hit wins. Tokens are
# matched against the lowercased vendor + machine type + node description.
_TYPE_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Firewall", ("firewall", "palo alto", "pan-os", "fortigate", "fortinet",
                  "fortios", "check point", "checkpoint", "asa", "firepower",
                  "sonicwall", "srx", "sophos", "barracuda")),
    ("Load Balancer", ("load balancer", "load-balancer", "big-ip", "big ip", "f5 ",
                       "netscaler", "citrix adc", "a10 ", "avi ")),
    ("Wireless", ("wireless", "wlan", "access point", "aironet", "wlc",
                  "meraki mr", "mobility controller")),
    ("Switch", ("switch", "catalyst", "nexus", "nx-os", "arista", "procurve",
                "aruba", "meraki ms", "ex series", "qfx")),
    ("Router", ("router", "isr", "asr", "ios-xe", "ios xe", "mx series",
                "juniper mx", "vedge", "sd-wan", "routing")),
    ("Storage", ("netapp", "storage", "isilon", "nimble", "pure storage",
                 "san ", "unity")),
    ("Hypervisor", ("esxi", "vmware", "hyper-v", "hypervisor", "vsphere")),
    ("Printer", ("printer", "jetdirect", "laserjet")),
    ("UPS / Power", ("ups", "pdu", "apc ", "power")),
    ("Server", ("windows server", "windows", "linux", "ubuntu", "centos",
                "red hat", "rhel", "debian", "suse", "net-snmp", "server")),
)

# Poll-method (ObjectSubType) values that strongly imply a general-purpose host.
_SERVER_SUBTYPES = {"wmi", "agent"}


def _classify_node(vendor: str, machine_type: str, description: str, subtype: str) -> str:
    """Derive an ``asset.type`` for a node from its vendor / machine type / poll
    method. SolarWinds has no single device-role field, so this classifies from
    the strings it does carry — the same keyword approach the Tufin adapter uses."""
    hay = " ".join((vendor or "", machine_type or "", description or "")).lower()
    for asset_type, tokens in _TYPE_RULES:
        if any(token in hay for token in tokens):
            return asset_type
    # WMI/Agent-polled nodes with no network-gear hint are almost always servers.
    if (subtype or "").strip().lower() in _SERVER_SUBTYPES:
        return "Server"
    return "Network Device"


# --------------------------------------------------------------------------- #
# Custom properties & MAC enrichment
# --------------------------------------------------------------------------- #

def _custom_property_names(client) -> List[str]:
    """Discover the site-defined node custom-property column names.

    Probes ``SELECT TOP 1 * FROM Orion.NodesCustomProperties`` and returns every
    column that is not a base/system column — exactly the dynamic probe the
    integration note describes. Returns ``[]`` when the entity is unavailable or
    ``SELECT *`` is unsupported.
    """
    try:
        rows = client.query_rows("SELECT TOP 1 * FROM Orion.NodesCustomProperties")
    except Exception:  # pragma: no cover - schema/version dependent
        return []
    if not rows:
        return []
    names = [k for k in rows[0].keys() if k.lower() not in _CP_BASE_COLUMNS]
    return sorted(names)


def _mac_by_node(client) -> Dict[str, str]:
    """Map NodeID -> first real MAC address (Orion.NodeMACAddresses)."""
    try:
        rows = client.query_rows("SELECT NodeID, MAC FROM Orion.NodeMACAddresses")
    except Exception:  # pragma: no cover - schema/version dependent
        return {}
    out: Dict[str, str] = {}
    for r in rows:
        node_id = r.get("NodeID")
        mac = (r.get("MAC") or "").strip()
        if node_id is not None and mac and mac != "000000000000":
            out.setdefault(str(node_id), mac)
    return out


# --------------------------------------------------------------------------- #
# Per-resource collectors → (columns, rows)
# --------------------------------------------------------------------------- #

# Standard Orion.Nodes columns fetched for every node. IP_Address / IOSVersion /
# NodeDescription match the names in the integration note's working queries.
_NODE_STD = [
    "NodeID", "Caption", "IP_Address", "DNS", "SysName", "Vendor", "MachineType",
    "IOSVersion", "NodeDescription", "Location", "Contact", "StatusDescription",
    "ObjectSubType",
]


def _collect_nodes(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Full node inventory, typed, with custom properties merged as ``custom.*``.

    Selects the standard Orion.Nodes fields, LEFT JOINs
    Orion.NodesCustomProperties so every site-defined custom property rides along
    (prefixed ``custom.``), and merges each node's MAC. Each node is tagged with a
    derived ``asset.type`` (Router / Switch / Firewall / Server / …).
    """
    custom_names = _custom_property_names(client)
    select_std = ", ".join(f"n.{c}" for c in _NODE_STD)
    if custom_names:
        select_cp = ", ".join(f"cp.{c}" for c in custom_names)
        swql = (
            f"SELECT {select_std}, {select_cp} "
            "FROM Orion.Nodes n "
            "LEFT JOIN Orion.NodesCustomProperties cp ON n.NodeID = cp.NodeID "
            "ORDER BY n.NodeID"
        )
    else:
        swql = f"SELECT {select_std} FROM Orion.Nodes n ORDER BY n.NodeID"

    raw = _paged_rows(client, swql)
    macs = _mac_by_node(client)

    columns = [
        "host.name", "node.id", "asset.type", "host.ip", "device.vendor",
        "device.model", "os.version", "host.dns", "sys.name", "location",
        "status", "host.mac",
    ] + [f"{CUSTOM_PREFIX}{name}" for name in custom_names]

    rows: List[List[Any]] = []
    for r in raw:
        node_id = textish(_first(r, "NodeID"))
        vendor = textish(_first(r, "Vendor"))
        machine_type = textish(_first(r, "MachineType"))
        description = textish(_first(r, "NodeDescription"))
        subtype = textish(_first(r, "ObjectSubType"))
        name = textish(_first(r, "Caption", "SysName", "DNS")) or node_id
        row = [
            name,
            node_id,
            _classify_node(vendor, machine_type, description, subtype),
            textish(_first(r, "IP_Address")),
            vendor,
            machine_type,
            textish(_first(r, "IOSVersion")),
            textish(_first(r, "DNS")),
            textish(_first(r, "SysName")),
            textish(_first(r, "Location")),
            textish(_first(r, "StatusDescription")),
            macs.get(node_id, ""),
        ]
        row.extend(textish(r.get(name_)) for name_ in custom_names)
        rows.append(row)
    return columns, rows


def _collect_interfaces(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Node interfaces (Orion.NPM.Interfaces), keyed to their host."""
    columns = [
        "host.name", "interface.id", "interface.name", "interface.type",
        "speed.bps", "mac", "admin.status", "oper.status",
    ]
    swql = (
        "SELECT n.Caption AS NodeName, i.InterfaceID, i.InterfaceName, "
        "i.InterfaceTypeDescription, i.InterfaceSpeed, i.PhysicalAddress, "
        "i.AdminStatus, i.OperStatus "
        "FROM Orion.NPM.Interfaces i "
        "INNER JOIN Orion.Nodes n ON i.NodeID = n.NodeID "
        "ORDER BY n.Caption"
    )
    rows = []
    for r in _paged_rows(client, swql):
        rows.append([
            textish(_first(r, "NodeName")),
            textish(_first(r, "InterfaceID")),
            textish(_first(r, "InterfaceName")),
            textish(_first(r, "InterfaceTypeDescription")),
            textish(_first(r, "InterfaceSpeed")),
            textish(_first(r, "PhysicalAddress")),
            textish(_first(r, "AdminStatus")),
            textish(_first(r, "OperStatus")),
        ])
    return columns, rows


def _collect_volumes(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Node volumes / disks (Orion.Volumes), keyed to their host."""
    columns = [
        "host.name", "volume.id", "volume.name", "volume.type",
        "size.bytes", "percent.used",
    ]
    swql = (
        "SELECT n.Caption AS NodeName, v.VolumeID, v.Caption AS VolumeName, "
        "v.VolumeType, v.VolumeSize, v.VolumePercentUsed "
        "FROM Orion.Volumes v "
        "INNER JOIN Orion.Nodes n ON v.NodeID = n.NodeID "
        "ORDER BY n.Caption"
    )
    rows = []
    for r in _paged_rows(client, swql):
        rows.append([
            textish(_first(r, "NodeName")),
            textish(_first(r, "VolumeID")),
            textish(_first(r, "VolumeName")),
            textish(_first(r, "VolumeType")),
            textish(_first(r, "VolumeSize")),
            textish(_first(r, "VolumePercentUsed")),
        ])
    return columns, rows


def _collect_custom_properties(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """List the node custom-property *definitions* — the catalog of custom fields.

    Prefers the rich ``Orion.CustomProperty`` metadata (description, data type);
    falls back to the names discovered by probing the values entity.
    """
    columns = ["custom_field.name", "custom_field.description", "data_type", "target"]
    rows_raw = _first_query(
        client,
        (
            "SELECT Field, Description, DataType, TargetEntity "
            "FROM Orion.CustomProperty WHERE TargetEntity = 'Orion.NodesCustomProperties' "
            "ORDER BY Field",
            "SELECT Field, Description, DataType, TargetEntity "
            "FROM Orion.CustomProperty ORDER BY Field",
        ),
    )
    if rows_raw:
        rows = [
            [
                textish(_first(r, "Field")),
                textish(_first(r, "Description")),
                textish(_first(r, "DataType")),
                textish(_first(r, "TargetEntity")) or "Orion.NodesCustomProperties",
            ]
            for r in rows_raw
        ]
        return columns, rows
    # Fallback: names only, discovered from the values entity.
    rows = [[name, "", "", "Orion.NodesCustomProperties"] for name in _custom_property_names(client)]
    return columns, rows


# -- NCM config posture ----------------------------------------------------- #

def _collect_config_inventory(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Current config posture: the latest running / startup config per device.

    Reads ``NCM.ConfigArchive`` joined to the NCM node caption, keeping the newest
    archived version per (device, config type) — so each row says which config a
    device is running, when it was captured, and whether it is the approved
    baseline. The (large) config text itself is not selected here.
    """
    columns = [
        "host.name", "asset.type", "config.type", "config.title",
        "config.id", "captured_at", "baseline",
    ]
    # Read the archive directly (no INNER JOIN). Try a rich column set first —
    # the node caption comes inline from the NCM.ConfigArchive -> Node navigation
    # property (c.Node.NodeCaption), plus title/baseline — then fall back to a
    # minimal, always-present column set so a version lacking Baseline/ConfigTitle
    # still returns rows rather than silently erroring to empty.
    raw = _first_query(
        client,
        (
            "SELECT c.NodeID, c.Node.NodeCaption AS NodeCaption, c.ConfigID, "
            "c.ConfigType, c.ConfigTitle, c.DownloadTime, c.Baseline "
            "FROM NCM.ConfigArchive c ORDER BY c.DownloadTime DESC",
            "SELECT c.NodeID, c.Node.NodeCaption AS NodeCaption, c.ConfigID, "
            "c.ConfigType, c.ConfigTitle, c.DownloadTime, c.Baseline "
            "FROM Cirrus.ConfigArchive c ORDER BY c.DownloadTime DESC",
            "SELECT NodeID, ConfigID, ConfigType, DownloadTime "
            "FROM NCM.ConfigArchive ORDER BY DownloadTime DESC",
            "SELECT NodeID, ConfigID, ConfigType, DownloadTime "
            "FROM Cirrus.ConfigArchive ORDER BY DownloadTime DESC",
        ),
    )
    # Only pay for the caption lookup when the rich (inline-caption) query didn't win.
    captions = _ncm_caption_map(client) if (raw and "NodeCaption" not in raw[0]) else {}
    seen: set = set()
    rows: List[List[Any]] = []
    for r in raw:
        node_id = textish(_first(r, "NodeID"))
        caption = (
            textish(_first(r, "NodeCaption"))
            or captions.get(node_id)
            or node_id
            or textish(_first(r, "ConfigID"))
        )
        config_type = textish(_first(r, "ConfigType"))
        key = (caption, config_type)
        if key in seen:  # rows are newest-first, so the first per key wins
            continue
        seen.add(key)
        rows.append([
            caption,
            "Config Snapshot",
            config_type,
            textish(_first(r, "ConfigTitle")),
            textish(_first(r, "ConfigID")),
            textish(_first(r, "DownloadTime")),
            textish(_first(r, "Baseline")),
        ])
    return columns, rows


def _ncm_nodes(client) -> List[Tuple[str, str]]:
    """Return ``(ncm_node_id, caption)`` for every NCM-managed node."""
    raw = _first_query(
        client,
        (
            "SELECT NodeID, NodeCaption FROM NCM.Nodes ORDER BY NodeCaption",
            "SELECT NodeID, NodeCaption FROM Cirrus.Nodes ORDER BY NodeCaption",
        ),
    )
    out: List[Tuple[str, str]] = []
    for r in raw:
        node_id = textish(_first(r, "NodeID"))
        caption = textish(_first(r, "NodeCaption")) or node_id
        if node_id:
            out.append((node_id, caption))
    return out


def _ncm_caption_map(client) -> Dict[str, str]:
    """Map NCM node id -> caption (for merging onto config-archive rows)."""
    return {node_id: caption for node_id, caption in _ncm_nodes(client)}


def _recent_running_configs(client, node_id: str, limit: int = 2) -> List[Dict[str, Any]]:
    """The most recent configs (with text) for one NCM node, newest first.

    Prefers the ``Running`` config type; if a device archives its configs under a
    different type label (some NCM setups do), falls back to the most recent
    configs of any type so a diff is still produced.
    """
    safe_id = str(node_id).replace("'", "''")
    running = _first_query(
        client,
        (
            f"SELECT TOP {limit} ConfigID, ConfigType, DownloadTime, Config "
            f"FROM NCM.ConfigArchive WHERE NodeID = '{safe_id}' "
            "AND ConfigType = 'Running' ORDER BY DownloadTime DESC",
            f"SELECT TOP {limit} ConfigID, ConfigType, DownloadTime, Config "
            f"FROM Cirrus.ConfigArchive WHERE NodeID = '{safe_id}' "
            "AND ConfigType = 'Running' ORDER BY DownloadTime DESC",
        ),
    )
    if len(running) >= 2:
        return running
    any_type = _first_query(
        client,
        (
            f"SELECT TOP {limit} ConfigID, ConfigType, DownloadTime, Config "
            f"FROM NCM.ConfigArchive WHERE NodeID = '{safe_id}' "
            "ORDER BY DownloadTime DESC",
            f"SELECT TOP {limit} ConfigID, ConfigType, DownloadTime, Config "
            f"FROM Cirrus.ConfigArchive WHERE NodeID = '{safe_id}' "
            "ORDER BY DownloadTime DESC",
        ),
    )
    return any_type if len(any_type) >= len(running) else running


# Volatile config lines that change on every capture without being a real edit;
# excluded from the diff so they do not read as configuration changes.
_VOLATILE_HINTS = (
    "last configuration change",
    "ntp clock-period",
    "! time:",
    "uptime is",
    "current configuration",
)


def _config_lines(text: str) -> List[str]:
    """Normalize config text into comparable lines (trimmed, volatile dropped)."""
    lines: List[str] = []
    for raw in str(text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        low = line.lower()
        if any(hint in low for hint in _VOLATILE_HINTS):
            continue
        lines.append(line)
    return lines


def _line_uid(change_type: str, line: str) -> str:
    """Stable per-line key for change-log dedup (content-hash, so re-fetching the
    same change never duplicates it)."""
    digest = hashlib.sha1(line.encode("utf-8", "ignore")).hexdigest()[:12]
    return f"{change_type[:3]}:{digest}"


def _diff_config(
    older: Dict[str, Any], newer: Dict[str, Any], caption: str
) -> List[List[Any]]:
    """Diff two config versions into added/removed change rows (change-log shape)."""
    old_lines = _config_lines(older.get("Config"))
    new_lines = _config_lines(newer.get("Config"))
    new_id = textish(_first(newer, "ConfigID"))
    when = textish(_first(newer, "DownloadTime"))

    rows: List[List[Any]] = []
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        for line in old_lines[i1:i2] if tag in ("replace", "delete") else []:
            rows.append([
                caption, new_id, when, "", "removed",
                _line_uid("removed", line), line, "", "", "",
            ])
        for line in new_lines[j1:j2] if tag in ("replace", "insert") else []:
            rows.append([
                caption, new_id, when, "", "added",
                _line_uid("added", line), "", line, "", "",
            ])
        if len(rows) >= MAX_CONFIG_CHANGE_LINES:
            break
    return rows[:MAX_CONFIG_CHANGE_LINES]


def _collect_config_changes(
    client, scan: int, time_range: Optional[str] = None, watermark_store=None
) -> Tuple[List[str], List[List[Any]]]:
    """Diff each device's archived configs into per-line change rows.

    Answers *what changed in the configuration, and when*, by comparing the two
    most recent running configs per device. NCM's config archive does not record
    the acting user, so ``changed_by`` is left blank (config attribution needs
    NCM real-time change detection with AAA/syslog, out of SWQL's reach).

    Modes:
    - default → the latest two archived configs per device are diffed;
    - incremental (``since``/``new``/``incremental``) with a ``watermark_store``
      → a device is diffed only when its newest ConfigID differs from the last
      one seen, and the watermark is then advanced (first run establishes a
      baseline silently), so each change is reported exactly once.

    The column shape matches the change log so rows dedupe into it by the globally
    unique ConfigID plus the per-line key and change type.
    """
    columns = [
        "host.name", "revision.id", "@timestamp", "changed_by", "change_type",
        "rule.uid", "before", "after", "authorized", "requester",
    ]
    incremental = (time_range or "").lower() in INCREMENTAL_TOKENS and watermark_store is not None
    rows: List[List[Any]] = []
    for node_id, caption in _ncm_nodes(client)[:scan]:
        configs = _recent_running_configs(client, node_id, limit=2)
        if not configs:
            continue
        newest_id = textish(_first(configs[0], "ConfigID"))
        if incremental:
            watermark = watermark_store.get(node_id)
            if watermark is None:
                watermark_store.set(node_id, newest_id)  # baseline only
                continue
            if watermark == newest_id:
                continue  # nothing new since last check
            watermark_store.set(node_id, newest_id)
        if len(configs) < 2:
            continue
        rows.extend(_diff_config(configs[1], configs[0], caption))
    return columns, rows


def _collect_policy_violations(client, scan: int) -> Tuple[List[str], List[List[Any]]]:
    """Compliance posture: NCM policy-rule violations per device.

    NCM's compliance results live under a handful of entity names across
    releases; this tries them in turn (``SELECT TOP N *``) and reads whichever
    columns each exposes, so it degrades gracefully rather than assuming one
    fixed schema.
    """
    columns = [
        "host.name", "policy.report", "policy.name", "policy.rule",
        "severity", "remediation", "violation.detail",
    ]
    raw = _first_query(
        client,
        (
            "SELECT TOP 5000 * FROM NCM.PolicyReportResults",
            "SELECT TOP 5000 * FROM NCM.PolicyViolations",
            "SELECT TOP 5000 * FROM Cirrus.PolicyReportViolations",
            "SELECT TOP 5000 * FROM NCM.PolicyCacheResults",
            "SELECT TOP 5000 * FROM Cirrus.PolicyCacheResults",
        ),
    )
    rows: List[List[Any]] = []
    for r in raw:
        rows.append([
            textish(_first(r, "NodeCaption", "NodeName", "Caption", "DeviceName", "Name")),
            textish(_first(r, "PolicyReportName", "ReportName", "PolicyReportTitle", "PolicyReport")),
            textish(_first(r, "PolicyName", "Policy")),
            textish(_first(r, "RuleName", "PolicyRuleName", "Rule")),
            textish(_first(r, "Severity", "SeverityName", "PolicyRuleLevel", "Level")),
            textish(_first(r, "RemediationScript", "Remediation")),
            textish(_first(r, "ViolationString", "ViolationDetail", "Violation", "ConfigBlock", "Description")),
        ])
    return columns, rows


_COLLECTORS = {
    "nodes": _collect_nodes,
    "interfaces": _collect_interfaces,
    "volumes": _collect_volumes,
    "custom_properties": _collect_custom_properties,
    "config_inventory": _collect_config_inventory,
    "change_detail": _collect_config_changes,
    "policy_violations": _collect_policy_violations,
}


def run_query(
    client,
    query: Query,
    limit: Optional[int] = None,
    time_range: Optional[str] = None,
    node_scan_limit: int = DEFAULT_NODE_SCAN,
    watermark_store=None,
) -> QueryResult:
    """Fetch a SolarWinds registry query's resource and normalize the response.

    ``time_range`` is only meaningful for ``change_detail`` (it selects the
    incremental "since last check" mode); the inventory/posture resources are
    point-in-time snapshots and ignore it.
    """
    resource = (query.resource or "").strip()
    if not resource:
        raise ValueError(
            f"query {query.id} ({query.name}) names no SolarWinds resource; nothing to run"
        )
    collector = _COLLECTORS.get(resource)
    if collector is None:
        raise ValueError(
            f"query {query.id} names unknown SolarWinds resource {resource!r}; "
            f"known resources: {', '.join(sorted(_COLLECTORS))}"
        )
    if resource == "change_detail":
        columns, rows = _collect_config_changes(
            client, node_scan_limit, time_range, watermark_store
        )
    else:
        columns, rows = collector(client, node_scan_limit)
    return _result(columns, rows, limit)
