"""Assemble every saved Tufin fetch into one device-centric profile.

The Tufin adapter fetches each resource (devices, revisions, rules, network
objects, services, zones, cleanups) into its own saved table. This module folds
the *latest* saved fetch of each, plus the deduplicated change log, into a
single nested structure keyed by device (``host.name`` — the anchor every Tufin
resource shares).

That one object drives the unified "Discover" view end to end: estate-wide
totals for the dashboard, one expandable row per device with its rules /
objects / services / zones / revisions / cleanups / changes as nested tables,
and a downloadable JSON of the whole estate. It is a pure function of the saved
records, so it can be rebuilt instantly without touching SecureTrack.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# resource name -> the per-device sub-list it populates
_SECTION_KEYS = {
    "revisions": "revisions",
    "rules": "rules",
    "network_objects": "objects",
    "services": "services",
    "zones": "zones",
    "cleanups": "cleanups",
}
_SECTIONS = ("rules", "objects", "services", "zones", "revisions", "cleanups")

# device-inventory column -> top-level device attribute
_DEVICE_ATTRS = [
    ("device.id", "id"), ("asset.type", "asset_type"), ("device.vendor", "vendor"),
    ("device.model", "model"), ("virtual_type", "virtual_type"),
    ("context_name", "context_name"), ("host.ip", "ip"),
    ("os.version", "os_version"), ("device.domain", "domain"), ("domain.id", "domain_id"),
    ("device.status", "status"), ("latest_revision", "latest_revision"),
    ("module_type", "module_type"), ("topology", "topology"),
    ("installed_policy", "installed_policy"),
]

# change-log columns copied into each device's recent-changes list
_CHANGE_KEYS = ("revision.id", "@timestamp", "changed_by", "action", "policy_package",
                "change_type", "rule.uid", "src_zone", "source", "dst_zone", "destination",
                "service", "before", "after", "authorized", "requester")
_MAX_RECENT = 25


def _colnames(rec: dict) -> List[str]:
    return [c["name"] if isinstance(c, dict) else c for c in (rec.get("columns") or [])]


def _rowdicts(rec: Optional[dict]) -> List[dict]:
    if not rec:
        return []
    names = _colnames(rec)
    return [dict(zip(names, row)) for row in (rec.get("rows") or [])]


def _host(row: dict) -> str:
    return str(row.get("host.name") or "")


def build_profile(
    sections: Dict[str, Optional[dict]],
    changes: Optional[dict] = None,
    generated_at: Optional[str] = None,
) -> dict:
    """Fold saved Tufin fetches into one device-keyed profile.

    ``sections`` maps a Tufin resource name (``devices``, ``rules``, …) to its
    latest saved fetch record (``{columns, rows}``) or ``None``. ``changes`` is
    the deduplicated change log (``{columns, rows}``). Returns
    ``{generated_at, totals, devices[]}``, devices ordered most-changed first.
    """
    devices: Dict[str, dict] = {}

    def device(name: str) -> dict:
        d = devices.get(name)
        if d is None:
            d = devices[name] = {
                "name": name, "id": "", "asset_type": "", "vendor": "", "model": "",
                "virtual_type": "", "context_name": "", "ip": "", "os_version": "",
                "domain": "", "domain_id": "", "status": "", "latest_revision": "",
                "module_type": "", "topology": "", "installed_policy": "",
                "revisions": [], "rules": [], "objects": [], "services": [],
                "zones": [], "cleanups": [],
                "changes": {"total": 0, "added": 0, "removed": 0, "modified": 0,
                            "unauthorized": 0, "recent": []},
            }
        return d

    # 1) device inventory -> top-level attributes
    for row in _rowdicts(sections.get("devices")):
        name = _host(row)
        if not name:
            continue
        d = device(name)
        for col, key in _DEVICE_ATTRS:
            if row.get(col) not in (None, ""):
                d[key] = row.get(col)

    # 2) every other resource -> the device's nested sub-list
    for resource, key in _SECTION_KEYS.items():
        for row in _rowdicts(sections.get(resource)):
            name = _host(row)
            if not name:
                continue
            device(name)[key].append({k: v for k, v in row.items() if k != "host.name"})

    # 3) change log -> per-device rollup + estate totals
    estate = {"total": 0, "added": 0, "removed": 0, "modified": 0, "unauthorized": 0}
    for row in _rowdicts(changes):
        name = _host(row)
        if not name:
            continue
        ch = device(name)["changes"]
        ctype = str(row.get("change_type") or "").lower()
        ch["total"] += 1
        estate["total"] += 1
        if ctype in ("added", "removed", "modified"):
            ch[ctype] += 1
            estate[ctype] += 1
        if str(row.get("authorized") or "").lower() == "unauthorized":
            ch["unauthorized"] += 1
            estate["unauthorized"] += 1
        if len(ch["recent"]) < _MAX_RECENT:
            ch["recent"].append({k: row.get(k, "") for k in _CHANGE_KEYS})

    # 4) per-device counts + estate totals
    by_asset_type: Dict[str, int] = {}
    totals = {sec: 0 for sec in _SECTIONS}
    device_list: List[dict] = []
    for d in devices.values():
        counts = {sec: len(d[sec]) for sec in _SECTIONS}
        counts["changes"] = d["changes"]["total"]
        d["counts"] = counts
        for sec in _SECTIONS:
            totals[sec] += counts[sec]
        at = d.get("asset_type") or "Unknown"
        by_asset_type[at] = by_asset_type.get(at, 0) + 1
        device_list.append(d)

    device_list.sort(key=lambda d: (-d["changes"]["total"], (d["name"] or "").lower()))

    totals["devices"] = len(device_list)
    totals["by_asset_type"] = by_asset_type
    totals["changes"] = estate

    return {"generated_at": generated_at, "totals": totals, "devices": device_list}
