"""Reconcile detected firewall changes against approved change-request tickets.

The change log tells us *what* changed on each firewall (device + source +
destination + service + action). An enterprise's own ticketing system holds the
*authorization* (who requested/approved which access). This module joins the
two so every change gets a verdict — **authorized / over-provisioned /
unauthorized / not-applicable** — without depending on the implementer having
stamped the ticket id into the revision comment.

Matching is by **intent fingerprint**: for a rule change, does an *approved*
ticket for the same device, within its change window, request access that
**covers** the implemented 5-tuple? CIDR containment is used for source/
destination (a ticket's ``10.1.0.0/16`` covers an implemented ``10.1.2.0/24``),
and named objects are resolved to their addresses via the object inventory when
a mapping is supplied. When the implemented change is *broader* than the ticket
requested, it is flagged **over-provisioned**.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# The columns this module appends to each change row.
VERDICT_COLUMNS = ["authorization", "matched_ticket", "auth_confidence", "auth_reason"]

# Ticket statuses that actually authorize a change.
_APPROVED = {"approved", "scheduled", "implemented", "closed", "completed"}

_ANY = {"", "any", "*", "0.0.0.0/0", "::/0"}


def _split(field: Any) -> List[str]:
    return [t for t in re.split(r"[,\s]+", str(field or "").strip()) if t]


def norm_action(value: Any) -> str:
    a = str(value or "").strip().lower()
    if a in ("accept", "allow", "permit", "pass"):
        return "allow"
    if a in ("drop", "deny", "reject", "block"):
        return "deny"
    return a


def norm_service(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s in _ANY:
        return "any"
    m = re.match(r"^(\d+)\s*/\s*(tcp|udp|icmp|ip|sctp)$", s)
    if m:
        return f"{m.group(2)}/{m.group(1)}"
    m = re.match(r"^(tcp|udp|icmp|ip|sctp)\s*/\s*(\d+)$", s)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return s  # a named service (e.g. "https") — compared literally


def _type_match(ticket_type: str, change_type: str) -> bool:
    t = (ticket_type or "").strip().lower()
    if t in ("", "any"):
        return True
    alias = {"add": "added", "create": "added", "new": "added",
             "modify": "modified", "change": "modified", "update": "modified",
             "remove": "removed", "delete": "removed", "decommission": "removed"}
    return alias.get(t, t) == change_type


def _to_net(token: str, objects: Optional[Dict[str, str]]):
    """Return an ip_network for a token, resolving object names, else 'any' or
    the lowercased opaque string."""
    t = str(token or "").strip()
    if t.lower() in _ANY:
        return "any"
    if objects and t in objects and str(objects[t]).strip():
        t = str(objects[t]).strip()
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        return t.lower()


def _covers_token(ticket_tok, change_tok) -> bool:
    if ticket_tok == "any":
        return True
    if change_tok == "any":
        return False  # a specific ticket scope cannot cover "any"
    if isinstance(ticket_tok, str) or isinstance(change_tok, str):
        return str(ticket_tok).lower() == str(change_tok).lower()
    try:
        return change_tok.version == ticket_tok.version and change_tok.subnet_of(ticket_tok)
    except (TypeError, ValueError):
        return False


def _field_covers(ticket_field: Any, change_field: Any, objects) -> bool:
    """True if every token of the change is covered by some ticket token."""
    tt = [_to_net(x, objects) for x in _split(ticket_field)] or ["any"]
    if any(x == "any" for x in tt):
        return True
    ct = [_to_net(x, objects) for x in _split(change_field)] or ["any"]
    return all(any(_covers_token(t, c) for t in tt) for c in ct)


def _svc_covers(ticket_svc: Any, change_svc: Any) -> bool:
    ts = norm_service(ticket_svc)
    if ts == "any":
        return True
    return ts == norm_service(change_svc)


def _relate(ticket_covers_change: bool, change_covers_ticket: bool) -> str:
    if ticket_covers_change and change_covers_ticket:
        return "equal"
    if ticket_covers_change:
        return "covers"        # ticket ⊇ change — within the request
    if change_covers_ticket:
        return "broader"       # change ⊋ ticket — over-provisioned
    return "disjoint"          # no overlap — this ticket isn't about this change


def _parse_dt(value: Any) -> Optional[datetime]:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(str(value).strip(), fmt)
        except (ValueError, TypeError):
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _within_window(when: Optional[datetime], ticket: dict) -> bool:
    start = _parse_dt(ticket.get("window_start"))
    end = _parse_dt(ticket.get("window_end"))
    if when is None or (start is None and end is None):
        return True  # no window to enforce (or unparseable change time) → don't block
    if start is not None and when < start:
        return False
    if end is not None and when > end:
        return False
    return True


def match_change(change: Dict[str, Any], tickets: List[dict],
                 objects: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a verdict dict for one change row (already a name→value dict)."""
    entity = str(change.get("entity", "rule") or "rule")
    ctype = str(change.get("change_type", "")).lower()
    if entity != "rule":
        return _verdict("not_applicable", "", "",
                        "object change — reconciled by object/value, not the 5-tuple")
    if ctype == "moved":
        return _verdict("not_applicable", "", "", "rule reordered — no access change")

    device = str(change.get("host.name", "")).strip().lower()
    csrc, cdst = change.get("source", ""), change.get("destination", "")
    csvc, caction = change.get("service", ""), norm_action(change.get("rule.action", ""))
    when = _parse_dt(change.get("@timestamp", ""))

    best = None  # (rank, confidence, ticket)  — lower rank = better
    for t in tickets:
        if str(t.get("status", "")).strip().lower() not in _APPROVED:
            continue
        tdev = str(t.get("device", "")).strip().lower()
        if tdev and tdev not in ("any", "*") and tdev != device:
            continue
        if not _type_match(str(t.get("change_type", "")), ctype):
            continue
        taction = norm_action(t.get("action", ""))
        if taction and taction != "any" and caction and taction != caction:
            continue
        if not _within_window(when, t):
            continue

        # Per-field relation between the ticket's requested scope and the
        # implemented change: equal / covers (ticket ⊇ change) / broader (change
        # ⊋ ticket, i.e. over-provisioned) / disjoint (no overlap → not this ticket).
        rels = [
            _relate(_field_covers(t.get("source"), csrc, objects),
                    _field_covers(csrc, t.get("source"), objects)),
            _relate(_field_covers(t.get("destination"), cdst, objects),
                    _field_covers(cdst, t.get("destination"), objects)),
            _relate(_svc_covers(t.get("service"), csvc), _svc_covers(csvc, t.get("service"))),
        ]
        if "disjoint" in rels:
            continue
        if all(r in ("equal", "covers") for r in rels):
            cand = (0, "high" if all(r == "equal" for r in rels) else "medium", t)
        else:  # some field implemented broader than requested, none disjoint
            cand = (1, "medium", t)
        if best is None or cand[0] < best[0]:
            best = cand

    if best is None:
        return _verdict("unauthorized", "", "high", "no approved ticket covers this change")
    rank, conf, t = best
    tid = str(t.get("ticket_id", ""))
    if rank == 0:
        return _verdict("authorized", tid, conf, f"covered by approved ticket {tid}")
    return _verdict("over_provisioned", tid, conf,
                    f"matched ticket {tid} but implemented broader than requested")


def _verdict(status: str, ticket: str, confidence: str, reason: str) -> Dict[str, str]:
    return {"authorization": status, "matched_ticket": ticket,
            "auth_confidence": confidence, "auth_reason": reason}


def reconcile_changes(changes: Optional[dict], tickets: List[dict],
                      objects: Optional[Dict[str, str]] = None) -> dict:
    """Annotate a change log with an authorization verdict per row.

    ``changes`` is ``{columns, rows}`` (from ``db.change_log``); ``tickets`` is
    a list of ticket dicts (from ``db.list_tickets``); ``objects`` optionally
    maps object name → address for resolving named sources/destinations.
    Returns ``{columns, rows, summary}`` where columns are the change columns
    plus the four verdict columns.
    """
    cols = [c["name"] if isinstance(c, dict) else c for c in (changes or {}).get("columns", [])]
    rows = (changes or {}).get("rows", [])
    out_cols = cols + VERDICT_COLUMNS
    out_rows: List[list] = []
    summary = {"authorized": 0, "over_provisioned": 0, "unauthorized": 0, "not_applicable": 0}
    for row in rows:
        rec = dict(zip(cols, row))
        v = match_change(rec, tickets, objects)
        summary[v["authorization"]] = summary.get(v["authorization"], 0) + 1
        out_rows.append(list(row) + [v[c] for c in VERDICT_COLUMNS])
    return {
        "columns": [{"name": c} for c in out_cols],
        "rows": out_rows,
        "summary": summary,
        "ticket_count": len(tickets),
    }
