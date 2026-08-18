"""Correlate saved query results into a unified, host-keyed view.

This is the intra-adapter merge (layer 2): take every saved result that carries
a ``host.name`` column and fold it into one **golden record per host** — the
"main table" of the *All Fetched Results* view. Results without ``host.name``
(e.g. service-aggregated queries) can't be a host row and are reported as
``excluded`` so the UI shows them as standalone sheets instead.

Each merged cell summarizes what a query captured for that host: the distinct
values of the query's most identifying column (a ``*.name``/``*Name`` field, or
the sole value column), or a plain record count when there's no obvious one.
Cross-adapter reconciliation (layer 3) will build on the same shape later.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

HOST_KEY = "host.name"
HOST_IP = "host.ip"
_SAMPLE_CAP = 6


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


def build_unified_inventory(blocks: List[Tuple[dict, List[dict]]]) -> dict:
    """Correlate host-keyed results across **all** adapters into one inventory.

    This is layer 3 — cross-adapter reconciliation. Where ``build_host_view``
    merges a single adapter's queries into a golden record per host, this folds
    every adapter's host-keyed results into one **asset per host** and records
    *which adapters* saw it. Assets seen by more than one adapter are surfaced
    first, so overlap between sources (e.g. a host present in both Elasticsearch
    and Tufin) is immediately visible.

    ``blocks`` is ``[(adapter_info, records), ...]`` where ``adapter_info`` is
    ``{"id", "name", ...}`` and ``records`` are db fetch records (with
    ``columns`` and ``rows``) — the same shape the exporters consume.

    Returns ``{columns, rows, asset_count, multi_adapter_count, adapters}``.
    The columns are ``host.name``, ``host.ip``, ``seen_by`` (the adapter names
    that saw the asset), ``adapter_count``, then one column per contributing
    adapter summarizing what that adapter captured for the host.
    """
    adapter_order: List[Tuple[str, str]] = []  # (id, name), host-keyed contributors
    seen_ids: set = set()
    # host.name -> {"ip": set, "by": {adapter_id: {"name", "queries": set, "values": set}}}
    hosts: dict = {}

    for info, records in blocks:
        aid = info.get("id", "?")
        aname = info.get("name", aid)
        contributed = False
        for rec in records:
            cols = rec.get("columns", [])
            hn = _col_index(cols, HOST_KEY)
            if hn is None:
                continue
            hip = _col_index(cols, HOST_IP)
            value_idxs = [
                i for i, c in enumerate(cols) if c.get("name") not in (HOST_KEY, HOST_IP)
            ]
            salient = _salient_index(cols, value_idxs)
            qid = rec.get("query_id", "?")
            for row in rec.get("rows", []):
                if hn >= len(row) or row[hn] in (None, ""):
                    continue
                contributed = True
                host = str(row[hn])
                h = hosts.setdefault(host, {"ip": set(), "by": {}})
                if hip is not None and hip < len(row):
                    _collect(h["ip"], row[hip])
                entry = h["by"].setdefault(
                    aid, {"name": aname, "queries": set(), "values": set()}
                )
                entry["queries"].add(qid)
                if salient is not None and salient < len(row):
                    _collect(entry["values"], row[salient])
        if contributed and aid not in seen_ids:
            seen_ids.add(aid)
            adapter_order.append((aid, aname))

    columns = (
        [{"name": HOST_KEY}, {"name": HOST_IP}, {"name": "seen_by"}, {"name": "adapter_count"}]
        + [{"name": aname} for _, aname in adapter_order]
    )

    rows: List[list] = []
    multi = 0
    # Most-shared assets first (they matter most), then by host name.
    for host in sorted(hosts, key=lambda h: (-len(hosts[h]["by"]), h)):
        h = hosts[host]
        by = h["by"]
        if len(by) > 1:
            multi += 1
        seen_names = [aname for aid, aname in adapter_order if aid in by]
        row = [host, ", ".join(sorted(h["ip"])), ", ".join(seen_names), len(by)]
        for aid, _ in adapter_order:
            entry = by.get(aid)
            if not entry:
                row.append("")
                continue
            vals = sorted(entry["values"])
            if vals:
                cell = f"{len(vals)}: " + ", ".join(vals[:_SAMPLE_CAP])
                if len(vals) > _SAMPLE_CAP:
                    cell += " …"
            else:
                n = len(entry["queries"])
                cell = f"{n} " + ("query" if n == 1 else "queries")
            row.append(cell)
        rows.append(row)

    return {
        "columns": columns,
        "rows": rows,
        "asset_count": len(rows),
        "multi_adapter_count": multi,
        "adapters": [{"id": aid, "name": aname} for aid, aname in adapter_order],
    }
