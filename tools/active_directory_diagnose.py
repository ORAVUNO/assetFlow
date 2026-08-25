#!/usr/bin/env python3
"""Standalone Active Directory (AD DS) connectivity + data diagnostic.

Uses the same LDAP client the assetFlow Active Directory adapter uses, but
prints what it discovers and every per-partition result / error instead of
degrading silently — so you can see *why* a resource returns little or nothing.
It is especially aimed at the DNS question ("I only get RootDNSServers"): it
shows the naming contexts the RootDSE advertises, the DNS application partitions
the adapter derives and searches, and a per-partition count of dnsZone /
dnsNode objects with the zone names, so you can tell whether your real zones
live in DomainDnsZones / ForestDnsZones and whether this bind can read them.

Needs ldap3 (pip install ldap3), same as the adapter.

Usage:
    python tools/active_directory_diagnose.py --host dc01.corp.local --user 'CORP\\svc'
    # (prompts for the password; or pass --password, or set AD_HOST / AD_USERNAME
    #  / AD_PASSWORD in the environment)

    # plain LDAP on 389, skip LDAPS cert validation, explicit base:
    python tools/active_directory_diagnose.py --host 10.0.0.1 --user u --no-ssl
    python tools/active_directory_diagnose.py --host dc01 --user u --insecure \
        --base-dn DC=corp,DC=local
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

# Import the real adapter code so the diagnostic exercises the same discovery
# and search paths the adapter uses.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assetflow import active_directory_client as ad_client  # noqa: E402
from assetflow import active_directory_runner as ad_runner  # noqa: E402
from assetflow.registry import load_registry  # noqa: E402

REGISTRY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "active_directory_registry.yaml",
)


def _hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def _count_zones_and_nodes(client, base: str):
    """Return (zone_names, node_count, error) for one DNS partition base."""
    try:
        zones = client.search(base, "(objectClass=dnsZone)", ["name", "dc"])
    except Exception as exc:  # noqa: BLE001
        return [], 0, f"dnsZone search failed: {exc}"
    names = []
    for z in zones:
        attrs = z.get("attributes", {})
        names.append(attrs.get("name") or attrs.get("dc") or z.get("dn", ""))
    try:
        nodes = client.search(base, "(objectClass=dnsNode)", ["name"])
        node_count = len(nodes)
        node_err = ""
    except Exception as exc:  # noqa: BLE001
        node_count, node_err = 0, f"  dnsNode search failed: {exc}"
    if node_err:
        print(node_err)
    return names, node_count, ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose the assetFlow AD adapter against a live DC.")
    ap.add_argument("--host", default=os.getenv("AD_HOST"), help="domain controller host/IP")
    ap.add_argument("--user", default=os.getenv("AD_USERNAME"), help="bind account (user@domain or DOMAIN\\user)")
    ap.add_argument("--password", default=os.getenv("AD_PASSWORD"), help="bind password (prompted if omitted)")
    ap.add_argument("--base-dn", default=os.getenv("AD_BASE_DN", ""), help="search base (default: auto-detected)")
    ap.add_argument("--port", type=int, default=None, help="LDAP port (default 636 LDAPS / 389)")
    ap.add_argument("--no-ssl", action="store_true", help="use plain LDAP instead of LDAPS")
    ap.add_argument("--insecure", action="store_true", help="skip LDAPS certificate validation")
    ap.add_argument("--limit", type=int, default=5, help="rows to fetch per resource in the run pass")
    args = ap.parse_args()

    if not args.host or not args.user:
        ap.error("provide --host and --user (or set AD_HOST / AD_USERNAME)")
    password = args.password or getpass.getpass(f"Password for {args.user}: ")

    client = ad_client.build_client(
        host=args.host, username=args.user, password=password,
        base_dn=args.base_dn or "", port=args.port,
        use_ssl=not args.no_ssl, verify_certs=not args.insecure,
    )

    _hr("Connection")
    try:
        info = ad_client.ping(client)
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED to connect: {exc}")
        return 1
    print(f"  {info.get('summary', '')}")

    _hr("Naming contexts (discovered)")
    root = client.root_dse()
    print(f"  base_dn (defaultNamingContext): {client.base_dn}")
    print(f"  configurationNamingContext:     {client.config_nc}")
    print(f"  rootDomainNamingContext:        {client.root_domain_nc}")
    advertised = root.get("namingContexts") or []
    if isinstance(advertised, str):
        advertised = [advertised]
    print(f"  RootDSE namingContexts advertised ({len(advertised)}):")
    for nc in advertised:
        print(f"    - {nc}")

    _hr("DNS partitions the adapter will search (derived)")
    parts = client.dns_partitions
    for base in parts:
        names, node_count, err = _count_zones_and_nodes(client, base)
        print(f"\n  {base}")
        if err:
            print(f"    {err}")
            continue
        print(f"    dnsZone objects: {len(names)}   dnsNode objects: {node_count}")
        for n in sorted(names):
            print(f"      zone: {n}")
    if not parts:
        print("  (none derived — is base_dn set / discovered?)")

    _hr(f"Every AD resource (first {args.limit} rows via the adapter runner)")
    reg = load_registry(REGISTRY)
    for q in reg.queries:
        try:
            result = ad_runner.run_query(client, q, limit=args.limit)
            n = len(result.rows)
            sample = ""
            if result.rows:
                first = dict(zip(result.column_names, result.rows[0]))
                keys = [k for k in ("user.name", "group.name", "ou.name", "host.name",
                                    "title", "zone.name", "record.name", "template.name",
                                    "ca.name", "msa.name", "owner", "domain.name") if first.get(k)]
                sample = "  e.g. " + ", ".join(f"{k}={first[k]}" for k in keys[:3])
            print(f"  {q.id} {q.name:<28} rows={n}{sample}")
        except Exception as exc:  # noqa: BLE001
            print(f"  {q.id} {q.name:<28} ERROR: {exc}")

    print("\nDone. If DNS shows only RootDNSServers, check whether your real zones")
    print("appear under DomainDnsZones/ForestDnsZones above, and whether those")
    print("partition searches reported an error (a permissions or referral issue).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
