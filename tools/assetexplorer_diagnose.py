#!/usr/bin/env python3
"""Standalone ManageEngine AssetExplorer connectivity + data diagnostic.

Read-only. Creates and changes nothing — it only issues GET /api/v3/assets calls
(the same list contract the assetFlow AssetExplorer adapter uses) and prints what
comes back, to answer the three questions a live box is needed to settle:

  1. FIELD NAMES — asks the list endpoint for a broad `fields_required` set and
     prints, per requested field, how many of a sample of assets came back
     populated. This tells us which field names actually return data (serial,
     category, MAC, OS, dates …) so the adapter's projection can be trimmed to
     the ones your build honors.

  2. DISPOSED ASSETS — reports the default total, then tries a few
     `search_criteria` shapes to fetch assets in the Disposed / Expired / Retired
     states, printing the total each shape returns. This tells us whether (and
     how) the v3 API can return disposed assets at all — the AE *report* reads the
     database directly, so the API may or may not expose them.

  3. UDF LABELS — probes the field-metadata endpoints and prints any
     udf api_name -> display label it finds, so custom columns can be auto-named.

Standard library only (no pip install). Talks to the AssetExplorer v3 REST API
over HTTPS.

Usage (on a machine that can reach AssetExplorer):
    # On-premises (technician API key):
    python assetexplorer_diagnose.py --host assetexplorer02.example.com:8443 \
        --api-key YOUR_TECHNICIAN_KEY

    # Cloud (OAuth access token) with a portal:
    python assetexplorer_diagnose.py --host sdpondemand.manageengine.com \
        --portal itdesk --access-token YOUR_ACCESS_TOKEN

    # Values can also come from the environment (AE_HOST, AE_PORTAL, AE_API_KEY,
    # AE_ACCESS_TOKEN); http:// is honored, otherwise https:// is assumed.

Paste the output back and the adapter's projection / disposed filter / UDF label
handling can be tuned to your exact instance.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# The broad projection the adapter would like to use. The probe reports which of
# these actually come back populated on your build.
CANDIDATE_FIELDS = [
    "name", "ip_addresses", "network_adapters", "mac_address", "operating_system",
    "product", "product_type", "type", "category", "asset_category", "state",
    "asset_tag", "barcode", "vendor", "serial_number", "org_serial_number",
    "department", "site", "location", "region", "user", "acquisition_date",
    "warranty_expiry", "expiry_date", "last_audit_on", "created_time",
    "last_updated_time", "description", "purchase_cost", "total_cost",
    "operational_cost", "current_cost", "udf_fields",
]

DISPOSED_STATES = ["Disposed", "Expired", "Retired"]


class AE:
    """Minimal read-only AssetExplorer v3 client for the probe."""

    def __init__(self, host, portal, api_key, access_token, timeout=60):
        scheme = "http" if host.lower().startswith("http://") else "https"
        host = host.split("://", 1)[-1].strip("/").split("/", 1)[0]
        self.base = f"{scheme}://{host}"
        if portal:
            self.base += f"/app/{portal.strip('/')}"
        self.api_key = api_key
        self.access_token = access_token
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context()

    def _headers(self):
        if self.api_key:
            return {"authtoken": self.api_key, "TECHNICIAN_KEY": self.api_key,
                    "Accept": "application/json"}
        return {"Authorization": f"Zoho-oauthtoken {self.access_token}",
                "Accept": "application/json"}

    def get(self, path, input_data=None):
        url = f"{self.base}/api/v3/{path.lstrip('/')}"
        if input_data is not None:
            url += "?" + urlencode({"input_data": json.dumps(input_data)})
        req = Request(url, headers=self._headers(), method="GET")
        with urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            return json.loads(r.read().decode("utf-8"))

    def assets(self, list_info):
        return self.get("assets", {"list_info": list_info})


def _total(payload):
    li = payload.get("list_info") if isinstance(payload, dict) else None
    if isinstance(li, dict) and li.get("total_count") is not None:
        return li.get("total_count")
    return "?"


def probe_fields(ae):
    print("\n" + "=" * 70)
    print("1) FIELD NAMES — which requested fields return data (sample of 50)")
    print("=" * 70)
    info = {"row_count": 50, "start_index": 1, "get_total_count": True,
            "fields_required": CANDIDATE_FIELDS}
    try:
        payload = ae.assets(info)
    except HTTPError as e:
        body = e.read().decode("utf-8", "ignore")[:400]
        print(f"  fields_required request FAILED (HTTP {e.code}): {body}")
        print("  -> retrying WITHOUT a projection (raw default) ...")
        payload = ae.assets({"row_count": 50, "start_index": 1, "get_total_count": True})
    assets = payload.get("assets") or []
    print(f"  default total_count: {_total(payload)}   (sample rows: {len(assets)})")
    if not assets:
        print("  no assets returned; check credentials / permissions.")
        return
    keys = {}
    for a in assets:
        for k, v in (a.items() if isinstance(a, dict) else []):
            populated = v not in (None, "", [], {})
            keys.setdefault(k, 0)
            if populated:
                keys[k] += 1
    print(f"  keys the list actually RETURNED ({len(keys)}), with populated count:")
    for k in sorted(keys):
        print(f"     {keys[k]:3d}/{len(assets)}  {k}")
    missing = [f for f in CANDIDATE_FIELDS if f not in keys]
    if missing:
        print(f"  requested but NOT returned by this build: {', '.join(missing)}")
    # Show one asset verbatim so the exact nesting/date shape is visible.
    print("\n  --- one sample asset (verbatim JSON) ---")
    print("  " + json.dumps(assets[0], indent=2)[:2000].replace("\n", "\n  "))


def probe_disposed(ae):
    print("\n" + "=" * 70)
    print("2) DISPOSED ASSETS — can the API return them, and how?")
    print("=" * 70)
    base = ae.assets({"row_count": 1, "start_index": 1, "get_total_count": True})
    print(f"  default list total_count (live assets): {_total(base)}")

    def try_criteria(label, list_info):
        try:
            p = ae.assets(list_info)
            print(f"  [{label}] total_count={_total(p)}  rows={len(p.get('assets') or [])}")
        except HTTPError as e:
            print(f"  [{label}] HTTP {e.code}: {e.read().decode('utf-8','ignore')[:160]}")
        except Exception as e:  # noqa
            print(f"  [{label}] error: {e}")

    for state in DISPOSED_STATES:
        # Shape A: field/condition/value
        try_criteria(f"search_criteria field=state.name is {state}", {
            "row_count": 1, "start_index": 1, "get_total_count": True,
            "search_criteria": {"field": "state.name", "condition": "is", "value": state}})
    # Shape B: a list of criteria
    try_criteria("search_criteria [state.name is Disposed]", {
        "row_count": 1, "start_index": 1, "get_total_count": True,
        "search_criteria": [{"field": "state.name", "condition": "is", "value": "Disposed"}]})
    # Shape C: filter_by name (some builds use a saved/filter id or name)
    try_criteria("filter_by name=All_Assets", {
        "row_count": 1, "start_index": 1, "get_total_count": True,
        "filter_by": {"name": "All_Assets"}})
    print("\n  If none of the disposed shapes exceed the live total, the v3 API")
    print("  likely cannot return disposed assets (the AE report reads the DB).")


def probe_udf_labels(ae):
    print("\n" + "=" * 70)
    print("3) UDF LABELS — udf api_name -> display label, from field metadata")
    print("=" * 70)
    found = False
    for path in ("assets/udf_fields", "asset_fields", "assets/fields",
                 "asset_type", "udf_fields"):
        try:
            payload = ae.get(path)
        except Exception as e:  # noqa
            print(f"  {path}: not available ({getattr(e,'code',e)})")
            continue
        recs = None
        if isinstance(payload, dict):
            for k, v in payload.items():
                if k not in ("response_status", "list_info") and isinstance(v, list):
                    recs = v
                    break
        elif isinstance(payload, list):
            recs = payload
        hits = 0
        for rec in (recs or []):
            if not isinstance(rec, dict):
                continue
            api = rec.get("name") or rec.get("api_name") or rec.get("column_name")
            label = rec.get("display_name") or rec.get("label") or rec.get("display_label")
            if api and label and str(api).startswith("udf_"):
                print(f'     "{api}": "{label}",')
                hits += 1
        if hits:
            print(f"  ({path}: {hits} udf labels)")
            found = True
            break
    if not found:
        print("  No UDF label metadata endpoint responded; set AE_UDF_LABELS")
        print("  manually (see config/assetexplorer_udf_labels.example.json).")


def main():
    ap = argparse.ArgumentParser(description="AssetExplorer read-only diagnostic")
    ap.add_argument("--host", default=os.getenv("AE_HOST"))
    ap.add_argument("--portal", default=os.getenv("AE_PORTAL", ""))
    ap.add_argument("--api-key", default=os.getenv("AE_API_KEY", ""))
    ap.add_argument("--access-token", default=os.getenv("AE_ACCESS_TOKEN", ""))
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    if not args.host:
        sys.exit("error: --host (or AE_HOST) is required")
    if not (args.api_key or args.access_token):
        sys.exit("error: provide --api-key (on-prem) or --access-token (Cloud)")

    ae = AE(args.host, args.portal, args.api_key, args.access_token, args.timeout)
    print(f"AssetExplorer diagnostic -> {ae.base}/api/v3")
    try:
        probe_fields(ae)
        probe_disposed(ae)
        probe_udf_labels(ae)
    except HTTPError as e:
        sys.exit(f"\nHTTP {e.code}: {e.read().decode('utf-8','ignore')[:300]}")
    except URLError as e:
        sys.exit(f"\nconnection error: {e}")
    print("\nDone. Paste this output back to tune the adapter to your instance.")


if __name__ == "__main__":
    main()
