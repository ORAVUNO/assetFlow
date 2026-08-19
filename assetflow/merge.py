"""Correlate saved query results into a unified, host-keyed view.

This is the intra-adapter merge (layer 2): take every saved result that carries
a ``host.name`` column and fold it into one **golden record per host** — the
"main table" of the *All Fetched Results* view. Results without ``host.name``
(e.g. service-aggregated queries) can't be a host row and are reported as
``excluded`` so the UI shows them as standalone sheets instead.

Each merged cell summarizes what a query captured for that host: the distinct
values of the query's most identifying column (a ``*.name``/``*Name`` field, or
the sole value column), or a plain record count when there's no obvious one.

Layer 3 — cross-adapter reconciliation — lives here too: ``correlate`` resolves
rows from *every* adapter into one asset per correlated entity by matching shared
identifiers. Assets come in **types** (devices, users, applications); each type
is correlated in its own namespace (a device never merges into a user), keying on
that type's identifiers. ``build_unified_inventory`` / ``build_asset_detail`` /
``inventory_types`` present the correlated view per type.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

HOST_KEY = "host.name"
HOST_IP = "host.ip"
_SAMPLE_CAP = 6

# --- cross-adapter identity correlation ------------------------------------
#
# Assets come in several **types** — devices, users, applications — and each type
# is correlated in its own namespace, the way Axonius-style CAASM tools separate
# Devices from Users. Two rows merge only when they share a non-junk identifier
# *of the same type*: a device never merges into a user, even if a value happens
# to match. Each AssetType lists the columns (matched case-insensitively) that
# carry its identifiers, mapped to the *kind* of identifier, plus the ordered
# ``primary`` columns used for the asset's display name. A single result row can
# feed more than one type (a "user on host" row is both a device and a user).


@dataclass(frozen=True)
class AssetType:
    type: str
    label: str
    primary: Tuple[str, ...]   # display-name columns, in preference order
    identity: Dict[str, str]   # column (lowercased) -> identifier kind


ASSET_TYPES: Dict[str, AssetType] = {
    "device": AssetType(
        type="device", label="Devices",
        primary=("host.name",),
        identity={
            "host.name": "name", "host.ip": "ip", "ips": "ip",
            "host.mac": "mac", "macs": "mac", "host.serial": "serial",
            "serial.number": "serial", "host.id": "uid", "cloud.instance.id": "uid",
        },
    ),
    "user": AssetType(
        type="user", label="Users",
        primary=("user.name", "user.email"),
        identity={
            "user.name": "name", "user.email": "email", "email": "email",
            "user.id": "uid", "user.sid": "sid", "sid": "sid",
            "user.principal_name": "upn", "upn": "upn",
        },
    ),
    "application": AssetType(
        type="application", label="Applications",
        primary=("application.name", "package.name", "service.name",
                 "software.name", "process.name"),
        identity={
            "application.name": "name", "package.name": "name",
            "service.name": "name", "software.name": "name", "process.name": "name",
        },
    ),
}
DEFAULT_TYPE = "device"


def _type_spec(asset_type: str) -> AssetType:
    if asset_type not in ASSET_TYPES:
        raise KeyError(f"unknown asset type {asset_type!r}")
    return ASSET_TYPES[asset_type]


# --- device categorization -------------------------------------------------
#
# Router / firewall / switch / server are not separate asset types — they are all
# Devices, distinguished by a derived ``category`` attribute. We classify a
# device from any vendor / model / OS / type columns its sources carry, falling
# back to the contributing adapter's data category as a prior.

_CLASSIFY_COLS: Dict[str, str] = {
    "device.vendor": "vendor", "vendor": "vendor",
    "device.model": "model", "model": "model",
    "device.platform": "model", "platform": "model",
    "device.type": "type", "device.category": "type", "device.role": "type",
    "os.name": "os", "os.version": "os", "host.os.name": "os", "operating_system": "os",
}

# (category, matching tokens) — checked in order; first hit wins.
_CATEGORY_RULES = [
    ("firewall", ("firewall", "palo alto", "pan-os", "fortigate", "fortinet",
                  "fortios", "check point", "checkpoint", "gaia", "asa",
                  "firepower", "sonicwall", "srx", "sophos", "barracuda")),
    ("switch", ("switch", "catalyst", "nexus", "nx-os", "arista", "procurve",
                "aruba", "meraki ms")),
    ("router", ("router", "isr", "asr", "ios-xe", "juniper mx", "mx series", "routing")),
    ("load balancer", ("load balancer", "big-ip", "netscaler", "citrix adc", "haproxy")),
    ("server", ("windows server", "linux", "ubuntu", "centos", "red hat", "rhel",
                "debian", "suse", "esxi", "vmware", "server")),
    ("workstation", ("windows 10", "windows 11", "windows 7", "macos", "mac os",
                     "workstation", "laptop", "desktop")),
]


def _classify_device(values: Dict[str, set], adapter_cats: set) -> str:
    """Derive a device category from its vendor/model/OS/type values, falling back
    to the contributing adapters' data categories."""
    text = " ".join(
        sorted(str(v) for vals in values.values() for v in vals)
    ).lower()
    for category, tokens in _CATEGORY_RULES:
        if any(t in text for t in tokens):
            return category
    ac = " ".join(str(c) for c in adapter_cats).lower()
    if "network" in ac:
        return "network device"
    if any(k in ac for k in ("siem", "log", "endpoint", "edr", "cloud")):
        return "server"
    return "unknown"


# Human labels for the "correlated by" / identifiers text, per identifier kind.
_IDENT_LABELS = {
    "name": "name", "ip": "host.ip", "mac": "host.mac", "serial": "serial",
    "uid": "id", "email": "email", "sid": "SID", "upn": "UPN",
}
# Order identifiers are listed in for display.
_IDENT_ORDER = ["ip", "mac", "email", "upn", "sid", "serial", "uid"]

# Back-compat alias: the device identity map (some callers/tests reference it).
IDENTITY_FIELDS: Dict[str, str] = ASSET_TYPES["device"].identity

# Values that are never a real, unique identifier — ignored for correlation so
# placeholders (empty, loopback, all-zero MAC, "unknown") don't merge everything.
_JUNK_IDENTS = {
    "", "-", "n/a", "na", "none", "null", "unknown",
    "0.0.0.0", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1",
    "000000000000", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
    "ffffffffffff",
}


def _norm_ident(kind: str, value) -> Optional[str]:
    """Normalize an identifier value for matching, or None if it's junk.

    MACs are reduced to bare lowercase hex (so ``AA:BB:CC`` == ``aa-bb-cc``),
    hostnames are lowercased with any trailing dot stripped, everything else is
    lowercased and trimmed.
    """
    s = str(value).strip()
    if kind == "mac":
        s = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    elif kind == "name":
        s = s.rstrip(".").lower()
    else:
        s = s.lower()
    if not s or s in _JUNK_IDENTS:
        return None
    return s


def _row_identities(columns: List[dict], row: list, identity: Dict[str, str]) -> set:
    """Return the ``(kind, normalized_value)`` identity tokens in a row, for the
    given type's identity map."""
    out = set()
    for i, c in enumerate(columns):
        kind = identity.get(str(c.get("name", "")).lower())
        if not kind or i >= len(row):
            continue
        cell = row[i]
        for v in (cell if isinstance(cell, list) else [cell]):
            nv = _norm_ident(kind, v)
            if nv:
                out.add((kind, nv))
    return out


def _primary_value(columns: List[dict], row: list, primary: Tuple[str, ...]) -> Optional[str]:
    """The asset's display value for a row: the first present primary column."""
    lower = [str(c.get("name", "")).lower() for c in columns]
    for col in primary:
        if col in lower:
            i = lower.index(col)
            if i < len(row) and row[i] not in (None, ""):
                return str(row[i])
    return None


class _UnionFind:
    """Minimal union-find over identifier tokens (path-compressed)."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _pick_primary(name_counts: Counter) -> str:
    """Choose an asset's display name: most-reported, then shortest, then alpha."""
    return sorted(name_counts, key=lambda n: (-name_counts[n], len(n), n))[0]


def correlate(blocks: List[Tuple[dict, List[dict]]], asset_type: str = DEFAULT_TYPE) -> dict:
    """Resolve rows across all adapters into correlated assets of one *type*.

    A row contributes an asset of ``asset_type`` when it carries that type's
    primary column (e.g. ``host.name`` for devices, ``user.name`` for users);
    rows sharing any identity token *of that type* (hostname/IP/MAC for devices,
    email/SID/… for users, name for applications) are merged via union-find. A
    single row can feed several types in separate calls — a "user on host" row is
    a device here and a user under ``asset_type="user"`` — but types never merge
    into each other.

    Returns ``{assets, adapter_order, type}`` where each asset carries its
    names/aliases, identifiers, contributing adapters, the tokens that correlated
    it, and the per-query rows that belong to it (for fields and detail tables).
    """
    spec = _type_spec(asset_type)
    uf = _UnionFind()
    adapter_order: List[Tuple[str, str]] = []
    seen_ids: set = set()
    adapter_cat_map: Dict[str, str] = {}
    obs: List[Tuple[str, str, dict, list]] = []

    for info, records in blocks:
        aid = info.get("id", "?")
        aname = info.get("name", aid)
        adapter_cat_map[aid] = info.get("category", "")
        for rec in records:
            cols = rec.get("columns", [])
            rowtoks = []
            for row in rec.get("rows", []):
                disp = _primary_value(cols, row, spec.primary)
                if disp is None:
                    continue
                toks = _row_identities(cols, row, spec.identity)
                keys = [f"{k}:{v}" for k, v in toks]
                for kk in keys[1:]:
                    uf.union(keys[0], kk)
                if keys:
                    uf.find(keys[0])
                rowtoks.append((row, toks, keys, disp))
            if rowtoks:
                obs.append((aid, aname, rec, rowtoks))
                if aid not in seen_ids:
                    seen_ids.add(aid)
                    adapter_order.append((aid, aname))

    # Group observations into asset clusters by their union-find root.
    acc: Dict[str, dict] = {}
    for aid, aname, rec, rowtoks in obs:
        cols = rec.get("columns", [])
        cidx = []
        for i, c in enumerate(cols):
            ckind = _CLASSIFY_COLS.get(str(c.get("name", "")).lower())
            if ckind:
                cidx.append((i, ckind))
        for row, toks, keys, disp in rowtoks:
            root = uf.find(keys[0]) if keys else f"disp:{disp.lower()}"
            a = acc.setdefault(root, {
                "adapters": [], "adapter_ids": set(),
                "name_counts": Counter(), "identities": {},
                "token_adapters": {}, "obs": {},
                "classify": {}, "adapter_cats": set(),
            })
            if aid not in a["adapter_ids"]:
                a["adapter_ids"].add(aid)
                a["adapters"].append((aid, aname))
            a["name_counts"][disp] += 1
            a["adapter_cats"].add(adapter_cat_map.get(aid, ""))
            for k, v in toks:
                a["identities"].setdefault(k, set()).add(v)
                a["token_adapters"].setdefault(f"{k}:{v}", set()).add(aid)
            for i, ckind in cidx:
                if i < len(row):
                    _collect(a["classify"].setdefault(ckind, set()), row[i])
            o = a["obs"].setdefault(
                (aid, rec.get("query_id", "?")),
                {"adapter_id": aid, "adapter": aname, "record": rec, "rows": []},
            )
            o["rows"].append(row)

    assets = []
    for root, a in acc.items():
        primary = _pick_primary(a["name_counts"])
        match_by: Dict[str, set] = {}
        for tok, adset in a["token_adapters"].items():
            kind, _, val = tok.partition(":")
            if kind != "name" and len(adset) >= 2:
                match_by.setdefault(kind, set()).add(val)
        category = (
            _classify_device(a["classify"], a["adapter_cats"])
            if asset_type == "device" else ""
        )
        assets.append({
            "root": root,
            "primary_name": primary,
            "names": sorted(a["name_counts"]),
            "aliases": sorted(n for n in a["name_counts"] if n != primary),
            "identities": {k: sorted(v) for k, v in a["identities"].items()},
            "category": category,
            "adapters": [(i, n) for i, n in a["adapters"]],
            "adapter_ids": [i for i, _ in a["adapters"]],
            "match_by": {k: sorted(v) for k, v in match_by.items()},
            "obs": a["obs"],
        })
    return {"assets": assets, "adapter_order": adapter_order, "type": asset_type}


def _correlated_by_text(match_by: Dict[str, list]) -> str:
    """Render an asset's correlation reasons, e.g. ``host.ip 10.0.0.5``."""
    kinds = [k for k in _IDENT_ORDER if k in match_by]
    kinds += [k for k in match_by if k not in _IDENT_ORDER and k != "name"]
    return "; ".join(
        f"{_IDENT_LABELS.get(k, k)} " + ", ".join(match_by[k]) for k in kinds
    )


def _identifiers_text(identities: Dict[str, list]) -> str:
    """Render an asset's non-name identifiers, e.g. ``host.ip: 10.0.0.5``."""
    kinds = [k for k in _IDENT_ORDER if identities.get(k)]
    kinds += [k for k in identities if k not in _IDENT_ORDER and k != "name" and identities.get(k)]
    return "; ".join(
        f"{_IDENT_LABELS.get(k, k)}: " + ", ".join(identities[k]) for k in kinds
    )


def _col_index(columns: List[dict], name: str) -> Optional[int]:
    for i, c in enumerate(columns):
        if c.get("name") == name:
            return i
    return None


def _salient_index(columns: List[dict], value_idxs: List[int]) -> Optional[int]:
    """Pick the most identifying value column to summarize (or None)."""
    named = [(i, columns[i].get("name", "")) for i in value_idxs]
    for test in (lambda n: n.endswith(".name"), lambda n: "Name" in n):
        for i, n in named:
            if test(n):
                return i
    if len(value_idxs) == 1:  # a single value column (often a VALUES() list)
        return value_idxs[0]
    return None


def _collect(values: set, cell) -> None:
    if isinstance(cell, list):
        for x in cell:
            if x not in (None, ""):
                values.add(str(x))
    elif cell not in (None, ""):
        values.add(str(cell))


def build_host_view(records: List[dict]) -> dict:
    """Merge host-keyed saved results into golden records.

    ``records`` are db fetch records (with ``columns`` and ``rows``). Returns
    ``{columns, rows, host_count, contributing, excluded}``.
    """
    contributing: List[str] = []
    excluded: List[str] = []
    labels: List[str] = []
    hosts: dict = {}  # host.name -> {"ip": set, "attrs": {label: {"count","values"}}}

    for rec in records:
        cols = rec.get("columns", [])
        hn = _col_index(cols, HOST_KEY)
        if hn is None:
            excluded.append(rec.get("query_id", "?"))
            continue
        contributing.append(rec.get("query_id", "?"))
        label = f"{rec.get('query_id', '?')} {rec.get('name', '')}".strip()
        labels.append(label)
        hip = _col_index(cols, HOST_IP)
        value_idxs = [i for i, c in enumerate(cols) if c.get("name") not in (HOST_KEY, HOST_IP)]
        salient = _salient_index(cols, value_idxs)

        for row in rec.get("rows", []):
            if hn >= len(row) or row[hn] in (None, ""):
                continue
            host = str(row[hn])
            h = hosts.setdefault(host, {"ip": set(), "attrs": {}})
            if hip is not None and hip < len(row):
                _collect(h["ip"], row[hip])
            attr = h["attrs"].setdefault(label, {"count": 0, "values": set()})
            attr["count"] += 1
            if salient is not None and salient < len(row):
                _collect(attr["values"], row[salient])

    columns = [{"name": HOST_KEY}, {"name": HOST_IP}] + [{"name": lbl} for lbl in labels]
    rows = []
    for host in sorted(hosts):
        h = hosts[host]
        row = [host, ", ".join(sorted(h["ip"]))]
        for lbl in labels:
            attr = h["attrs"].get(lbl)
            if not attr:
                row.append("")
                continue
            vals = sorted(attr["values"])
            if vals:
                cell = f"{len(vals)}: " + ", ".join(vals[:_SAMPLE_CAP])
                if len(vals) > _SAMPLE_CAP:
                    cell += " …"
            else:
                cell = str(attr["count"])
            row.append(cell)
        rows.append(row)

    return {
        "columns": columns,
        "rows": rows,
        "host_count": len(rows),
        "contributing": contributing,
        "excluded": excluded,
    }


def inventory_types(blocks: List[Tuple[dict, List[dict]]]) -> List[dict]:
    """List the asset types with how many assets of each the data yields."""
    out = []
    for t in ASSET_TYPES.values():
        n = len(correlate(blocks, t.type)["assets"])
        out.append({"type": t.type, "label": t.label, "count": n})
    return out


def build_unified_inventory(
    blocks: List[Tuple[dict, List[dict]]], asset_type: str = DEFAULT_TYPE
) -> dict:
    """Correlate results across **all** adapters into one inventory of assets of
    the given type (``device``, ``user``, or ``application``).

    This is layer 3 — cross-adapter reconciliation. It folds every adapter's rows
    into one **asset** per correlated entity and records *which adapters* saw it.
    Assets are correlated on shared identifiers of their type (see ``correlate``),
    so an entity reported under two different names by two adapters becomes one
    row. Assets seen by more than one adapter are surfaced first.

    ``blocks`` is ``[(adapter_info, records), ...]``. Returns ``{type, columns,
    rows, asset_count, multi_adapter_count, correlated_count, adapters}``. The
    columns are the type's primary name, ``aliases``, ``identifiers``,
    ``seen_by``, ``adapter_count``, ``correlated_by``, then one per adapter.
    """
    spec = _type_spec(asset_type)
    res = correlate(blocks, asset_type)
    adapter_order = res["adapter_order"]
    kind_by_id = {info.get("id"): info.get("kind", "") for info, _ in blocks}
    primary_cols = set(spec.primary)
    show_category = asset_type == "device"

    columns = (
        [{"name": spec.primary[0]}, {"name": "aliases"}]
        + ([{"name": "category"}] if show_category else [])
        + [{"name": "identifiers"}, {"name": "seen_by"},
           {"name": "adapter_count"}, {"name": "correlated_by"}]
        + [{"name": aname} for _, aname in adapter_order]
    )

    def _summary(asset, aid):
        """Per-adapter cell: distinct salient values, else a query count."""
        vals: set = set()
        n_queries = 0
        for (a_id, _qid), o in asset["obs"].items():
            if a_id != aid:
                continue
            n_queries += 1
            cols = o["record"].get("columns", [])
            value_idxs = [
                i for i, c in enumerate(cols)
                if str(c.get("name", "")).lower() not in primary_cols
            ]
            salient = _salient_index(cols, value_idxs)
            if salient is not None:
                for row in o["rows"]:
                    if salient < len(row):
                        _collect(vals, row[salient])
        if not n_queries:
            return ""
        if vals:
            out = f"{len(vals)}: " + ", ".join(sorted(vals)[:_SAMPLE_CAP])
            return out + " …" if len(vals) > _SAMPLE_CAP else out
        return f"{n_queries} " + ("query" if n_queries == 1 else "queries")

    rows: List[list] = []
    multi = correlated = 0
    for asset in sorted(
        res["assets"],
        key=lambda a: (-len(a["adapter_ids"]), -len(a["aliases"]), a["primary_name"].lower()),
    ):
        by = set(asset["adapter_ids"])
        if len(by) > 1:
            multi += 1
        if asset["match_by"]:
            correlated += 1
        seen_names = [aname for aid, aname in adapter_order if aid in by]
        row = [asset["primary_name"], ", ".join(asset["aliases"])]
        if show_category:
            row.append(asset.get("category", ""))
        row += [
            _identifiers_text(asset["identities"]),
            ", ".join(seen_names),
            len(by),
            _correlated_by_text(asset["match_by"]),
        ]
        for aid, _ in adapter_order:
            row.append(_summary(asset, aid) if aid in by else "")
        rows.append(row)

    return {
        "type": asset_type,
        "columns": columns,
        "rows": rows,
        "asset_count": len(rows),
        "multi_adapter_count": multi,
        "correlated_count": correlated,
        "adapters": [
            {"id": aid, "name": aname, "kind": kind_by_id.get(aid, "")}
            for aid, aname in adapter_order
        ],
    }


def _asset_fields(asset: dict, primary_cols: set) -> List[dict]:
    """Flatten one asset's per-query rows into aggregated, tagged fields.

    The type's primary columns (the asset's own name) are excluded — everything
    else the queries carried becomes a field."""
    adapters_seen = asset["adapters"]  # ordered (id, name)
    adapter_names = {aid: aname for aid, aname in adapters_seen}
    field_vals: dict = {}   # field name -> {adapter_id: set(values)}
    field_order: List[str] = []

    for (aid, _qid), o in asset["obs"].items():
        cols = o["record"].get("columns", [])
        for i, c in enumerate(cols):
            name = str(c.get("name", ""))
            if name.lower() in primary_cols:
                continue
            if name not in field_vals:
                field_vals[name] = {}
                field_order.append(name)
            bucket = field_vals[name].setdefault(aid, set())
            for r in o["rows"]:
                if i < len(r):
                    _collect(bucket, r[i])

    fields: List[dict] = []
    for name in field_order:
        per = {aid: vals for aid, vals in field_vals[name].items() if vals}
        contributors = [aid for aid, _ in adapters_seen if aid in per]
        if not contributors:
            continue
        scope = "common" if len(contributors) > 1 else "specific"
        counts: Counter = Counter()
        for aid in contributors:
            for v in per[aid]:
                counts[v] += 1
        preferred = None
        if counts:
            top_c = max(counts.values())
            top = [v for v, c in counts.items() if c == top_c]
            if len(top) == 1:
                preferred = top[0]
            else:  # tie -> the value from the earliest-ordered adapter
                for aid, _ in adapters_seen:
                    hit = sorted(v for v in per.get(aid, ()) if v in top)
                    if hit:
                        preferred = hit[0]
                        break
        agree = len({tuple(sorted(per[aid])) for aid in contributors}) == 1
        fields.append({
            "name": name,
            "scope": scope,
            "adapters": [adapter_names[aid] for aid in contributors],
            "adapter_ids": contributors,
            "preferred": preferred,
            "agree": agree,
            "values_by_adapter": {
                adapter_names[aid]: sorted(per[aid]) for aid in contributors
            },
        })
    return fields


def build_asset_detail(
    blocks: List[Tuple[dict, List[dict]]], host: str, asset_type: str = DEFAULT_TYPE
) -> dict:
    """Full cross-adapter detail for a single correlated asset of ``asset_type``.

    Resolves assets with ``correlate`` (so ``host`` may match the primary name
    or any merged alias), then returns three views of the matched asset:

    - ``adapters`` — the adapters that saw it, plus ``names``/``aliases``,
      ``identities``, and ``correlated_by`` (the identifiers that merged records
      into this one asset).
    - ``fields`` — every attribute flattened to distinct values, each tagged
      ``common`` (reported by more than one adapter) or ``specific`` (only one),
      with a ``preferred`` best-guess value, per-adapter values, and whether the
      adapters ``agree``.
    - ``tables`` — the raw per-asset rows of each contributing query, kept as
      mini tables to expand under the asset.

    Returns ``{host, type, found, ...}``; ``found`` is False when no asset matches.
    """
    spec = _type_spec(asset_type)
    primary_cols = set(spec.primary)
    host = str(host)
    needle = host.rstrip(".").lower()
    res = correlate(blocks, asset_type)
    asset = None
    for a in res["assets"]:
        if needle == a["primary_name"].rstrip(".").lower() or any(
            needle == n.rstrip(".").lower() for n in a["names"]
        ):
            asset = a
            break

    if asset is None:
        return {"host": host, "type": asset_type, "found": False, "adapters": [],
                "names": [], "aliases": [], "identities": {}, "category": "",
                "correlated_by": {}, "fields": [], "tables": []}

    tables = []
    for (aid, qid), o in asset["obs"].items():
        cols = o["record"].get("columns", [])
        other = [
            i for i, c in enumerate(cols)
            if str(c.get("name", "")).lower() not in primary_cols
        ]
        tables.append({
            "adapter": o["adapter"],
            "adapter_id": aid,
            "query_id": qid,
            "query_name": o["record"].get("name", ""),
            "row_count": len(o["rows"]),
            "columns": [str(cols[i].get("name", "")) for i in other],
            "rows": [[(r[i] if i < len(r) else "") for i in other] for r in o["rows"]],
        })

    return {
        "host": asset["primary_name"],
        "type": asset_type,
        "found": True,
        "adapters": [{"id": aid, "name": aname} for aid, aname in asset["adapters"]],
        "names": asset["names"],
        "aliases": asset["aliases"],
        "identities": asset["identities"],
        "category": asset.get("category", ""),
        "correlated_by": asset["match_by"],
        "fields": _asset_fields(asset, primary_cols),
        "tables": tables,
    }
