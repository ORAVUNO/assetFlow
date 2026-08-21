"""Effective-access impact of an object (and its members) on the rulebase.

Answers, in plain language a non-firewall admin can read: *which rules now apply
to this object — and therefore to any IP added to it — who can reach it, and
what it can reach.*

Why it matters, by example:
- An admin, instead of writing a new rule for a requested "A → B" flow, adds the
  requestor's IP to an object already used as the destination of an existing
  "A → B" rule. The requestor now inherits that rule. This module lists it:
  *"<A> → <new member> : <service> (allow)"*.
- If that source object A contains **several** addresses, they can now **all**
  reach the newly added member — often unintended. Because the impact line
  carries the rule's *full* source, that exposure is visible at a glance.

It works off the saved **effective rulebase** (TUF003), matching the object by
name in each rule's flattened source/destination cell — so no live call and no
group-membership expansion is needed: a member of the object inherits exactly
the rules that reference the object.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_DISABLED = ("true", "1", "yes", "on")


def _cell_tokens(cell: Any) -> List[str]:
    return [t.strip() for t in re.split(r"[,;]+", str(cell or "")) if t.strip()]


def _in_cell(name: str, cell: Any) -> bool:
    n = str(name or "").strip().lower()
    return bool(n) and any(t.lower() == n for t in _cell_tokens(cell))


def _rowdicts(rules: Optional[dict]) -> List[dict]:
    if not rules:
        return []
    cols = [c["name"] if isinstance(c, dict) else c for c in rules.get("columns", [])]
    return [dict(zip(cols, r)) for r in rules.get("rows", [])]


def _entry(r: dict) -> dict:
    return {
        "host.name": r.get("host.name", ""), "rule.uid": r.get("rule.uid", ""),
        "rule.name": r.get("rule.name", ""), "src_zone": r.get("src_zone", ""),
        "source": r.get("source", ""), "dst_zone": r.get("dst_zone", ""),
        "destination": r.get("destination", ""), "service": r.get("service", ""),
        "action": r.get("action", ""),
    }


def object_impact(object_name: str, rules: Optional[dict], device: Optional[str] = None) -> dict:
    """Rules that reference ``object_name``, split by the side it appears on.

    ``as_source`` rules → the object's members are a *source* (they can reach the
    rule's destination). ``as_destination`` rules → the object's members are a
    *destination* (they are reachable by the rule's source). Disabled rules are
    ignored. ``device`` optionally scopes to one ``host.name``.
    """
    as_source: List[dict] = []
    as_destination: List[dict] = []
    for r in _rowdicts(rules):
        if device and str(r.get("host.name", "")).strip().lower() != device.strip().lower():
            continue
        if str(r.get("disabled", "")).strip().lower() in _DISABLED:
            continue
        if _in_cell(object_name, r.get("source", "")):
            as_source.append(_entry(r))
        if _in_cell(object_name, r.get("destination", "")):
            as_destination.append(_entry(r))
    return {
        "object": object_name, "device": device or "",
        "as_source": as_source, "as_destination": as_destination,
        "rule_count": len(as_source) + len(as_destination),
    }


def member_sentences(object_name: str, impact: dict, member: Optional[str] = None) -> List[dict]:
    """Plain-language access lines for a member added to the object.

    Each carries the effective 5-tuple *for the member* and, when the member is a
    destination, the full set of sources that can now reach it (``exposure``) —
    the unintended-reachability signal.
    """
    who = member or f"any member of '{object_name}'"
    out: List[dict] = []
    for e in impact.get("as_source", []):
        out.append({
            "direction": "can reach", "rule.uid": e["rule.uid"],
            "text": f"{who} → {e['destination'] or 'Any'} : {e['service'] or 'Any'} ({e['action'] or '?'})",
            "reachable_by": "", "action": e["action"], "service": e["service"],
            "peer": e["destination"], "host.name": e["host.name"],
        })
    for e in impact.get("as_destination", []):
        out.append({
            "direction": "reachable by", "rule.uid": e["rule.uid"],
            "text": f"{e['source'] or 'Any'} → {who} : {e['service'] or 'Any'} ({e['action'] or '?'})",
            "reachable_by": e["source"], "action": e["action"], "service": e["service"],
            "peer": e["source"], "host.name": e["host.name"],
        })
    return out
