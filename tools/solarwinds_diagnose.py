#!/usr/bin/env python3
"""Standalone SolarWinds / NCM connectivity + data diagnostic.

Runs the same SWQL the assetFlow SolarWinds adapter uses, but prints every
result and every error instead of swallowing them — so you can see *why* the
NCM config-posture resources (SW005 config inventory, SW006 config changes,
SW007 compliance) return no data: either the box has no archived configs / no
compliance runs, or a SWQL entity/field your NCM version doesn't have.

Standard library only (no pip install). Talks to the SWIS JSON query endpoint
over HTTPS with Basic auth, auto-probing ports 17774 then 17778.

Usage:
    python solarwinds_diagnose.py --host 10.10.3.34 --user admin
    # (you'll be prompted for the password; or pass --password, or set
    #  SWIS_HOSTNAME / SWIS_USERNAME / SWIS_PASSWORD in the environment)

    python solarwinds_diagnose.py --host 10.10.3.34 --user admin --port 17778
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

QUERY_PATH = "/SolarWinds/InformationService/v3/Json/Query"
CANDIDATE_PORTS_DEFAULT = [17774, 17778]


class Swis:
    """Minimal SWIS client: POST a SWQL statement, get back parsed JSON."""

    def __init__(self, host, user, password, ports, timeout=60):
        self.host = host
        self.ports = ports
        self.timeout = timeout
        self.token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        self.ctx = ssl._create_unverified_context()
        self.active_port = None

    def _url(self, port):
        return f"https://{self.host}:{port}{QUERY_PATH}"

    def query(self, swql):
        """Return (rows, error_str). rows is a list of dicts; error_str is '' on success."""
        body = json.dumps({"query": swql}).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {self.token}",
        }
        ports = [self.active_port] if self.active_port else self.ports
        last_err = ""
        for port in ports:
            req = Request(self._url(port), data=body, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    payload = resp.read().decode("utf-8")
                self.active_port = port
                data = json.loads(payload) if payload else {}
                return data.get("results", []), ""
            except HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "ignore")
                    detail = (json.loads(detail).get("Message") or detail)[:300]
                except Exception:
                    pass
                if exc.code == 400:
                    # Endpoint is a live SWIS server; the *query* was rejected.
                    self.active_port = port
                    return None, f"HTTP 400 (SWQL rejected): {detail or 'bad query'}"
                if exc.code in (401, 403):
                    return None, f"HTTP {exc.code} (auth/permission denied)"
                last_err = f":{port} HTTP {exc.code} {detail}"
            except URLError as exc:
                last_err = f":{port} unreachable ({getattr(exc, 'reason', exc)})"
            except Exception as exc:  # noqa: BLE001
                last_err = f":{port} {exc}"
        return None, f"could not reach SWIS — {last_err}"


# --------------------------------------------------------------------------- #

def _c(text, color):
    if not sys.stdout.isatty():
        return text
    codes = {"green": 32, "red": 31, "yellow": 33, "cyan": 36, "bold": 1}
    return f"\033[{codes[color]}m{text}\033[0m"


OK = _c("PASS", "green")
FAIL = _c("FAIL", "red")
WARN = _c("WARN", "yellow")


def count(swis, swqls, label):
    """Try each SWQL until one succeeds; print the count. Returns int or None."""
    for swql in swqls:
        rows, err = swis.query(swql)
        if err:
            last = err
            continue
        n = None
        if rows:
            v = rows[0]
            n = v.get("n", next(iter(v.values()), None))
        try:
            n = int(n)
        except (TypeError, ValueError):
            n = 0
        print(f"  {OK}  {label}: {_c(n, 'bold')}   [{swql.split('FROM',1)[-1].strip()}]")
        return n
    print(f"  {FAIL}  {label}: {last}")
    return None


def main():
    ap = argparse.ArgumentParser(description="SolarWinds/NCM SWIS diagnostic")
    ap.add_argument("--host", default=os.getenv("SWIS_HOSTNAME"), help="SWIS host/IP")
    ap.add_argument("--user", default=os.getenv("SWIS_USERNAME"), help="Orion username")
    ap.add_argument("--password", default=os.getenv("SWIS_PASSWORD"), help="Orion password (prompted if omitted)")
    ap.add_argument("--port", type=int, help="SWIS port (default: probe 17774 then 17778)")
    args = ap.parse_args()

    host = args.host or input("SolarWinds host/IP: ").strip()
    user = args.user or input("Orion username: ").strip()
    password = args.password or getpass.getpass("Orion password: ")
    ports = [args.port] if args.port else CANDIDATE_PORTS_DEFAULT

    swis = Swis(host, user, password, ports)

    print(_c(f"\n== SolarWinds SWIS diagnostic — {host} ==", "cyan"))

    # 1) connectivity
    rows, err = swis.query("SELECT TOP 1 FullName FROM Metadata.Entity")
    if err:
        print(f"  {FAIL}  connect: {err}")
        print(_c("\nCannot reach/authenticate SWIS — fix this first "
                 "(host, port, credentials, network).", "red"))
        return 2
    print(f"  {OK}  connect: SWIS answered on port {_c(swis.active_port, 'bold')}")

    ver, _ = swis.query("SELECT TOP 1 Version FROM Orion.Info")
    if ver:
        print(f"        Orion version: {ver[0].get('Version', '?')}")

    # 2) core inventory (should be non-zero on any Orion)
    print(_c("\n-- Inventory (NPM) --", "cyan"))
    count(swis, ["SELECT COUNT(NodeID) AS n FROM Orion.Nodes"], "Orion.Nodes (all monitored devices)")

    # 3) NCM presence + data
    print(_c("\n-- NCM (config posture: SW005/SW006) --", "cyan"))
    # Whether NCM is installed is decided by whether its entities actually resolve
    # (a COUNT that returns even 0 means the entity exists), NOT by a Metadata.Entity
    # probe — that probe is unreadable for some scoped accounts and gives a false
    # "not installed".
    ncm_nodes = count(swis, [
        "SELECT COUNT(NodeID) AS n FROM NCM.Nodes",
        "SELECT COUNT(NodeID) AS n FROM Cirrus.Nodes",
    ], "NCM-managed nodes")

    configs = count(swis, [
        "SELECT COUNT(ConfigID) AS n FROM NCM.ConfigArchive",
        "SELECT COUNT(ConfigID) AS n FROM Cirrus.ConfigArchive",
    ], "Archived configs (NCM.ConfigArchive)")

    # NCM entity resolves (returned an int, even 0) => module is installed.
    ncm_present = (ncm_nodes is not None) or (configs is not None)

    # sample archive row + config types (only meaningful if configs exist)
    if configs:
        rows, err = swis.query(
            "SELECT TOP 1 NodeID, ConfigID, ConfigType, DownloadTime "
            "FROM NCM.ConfigArchive ORDER BY DownloadTime DESC")
        if err:
            rows, err = swis.query(
                "SELECT TOP 1 NodeID, ConfigID, ConfigType, DownloadTime "
                "FROM Cirrus.ConfigArchive ORDER BY DownloadTime DESC")
        if rows:
            print(f"        newest config: {json.dumps(rows[0], default=str)}")
        types, err = swis.query(
            "SELECT ConfigType, COUNT(ConfigID) AS n FROM NCM.ConfigArchive GROUP BY ConfigType")
        if not err and types:
            summary = ", ".join(f"{t.get('ConfigType')}={t.get('n')}" for t in types)
            print(f"        config types: {summary}")

    # 4) compliance (SW007)
    print(_c("\n-- Compliance (SW007) --", "cyan"))
    count(swis, [
        "SELECT COUNT(PolicyReportID) AS n FROM NCM.PolicyReportResults",
        "SELECT COUNT(ID) AS n FROM NCM.PolicyReportResults",
        "SELECT COUNT(PolicyID) AS n FROM Cirrus.PolicyReportViolations",
        "SELECT COUNT(ID) AS n FROM NCM.PolicyViolations",
    ], "Policy results / violations")

    # 5) verdict
    print(_c("\n== Verdict ==", "cyan"))
    if not ncm_present:
        print(_c("NCM entities do not resolve — the NCM module is not installed on this box. "
                 "SW005–SW007 will always be empty. Inventory (SW001–SW004) is unaffected.", "yellow"))
    elif configs == 0 and (ncm_nodes or 0) == 0:
        print(_c("NCM IS installed (its entities resolve), but it reports 0 managed nodes and "
                 "0 archived configs. So SW005/SW006 are empty for a real reason, not an adapter "
                 "bug. Two possible causes:\n"
                 "  1) NCM isn't managing any devices / not archiving — add nodes to NCM and run "
                 "a 'Download Configs' job (My Dashboards > NCM > Configuration Management).\n"
                 "  2) This account lacks NCM rights — SWIS hides NCM rows per-account. Re-run "
                 "this script with an NCM-admin account, or compare against the NCM node count in "
                 "the web console. If an admin account sees configs, grant this account NCM access.",
                 "yellow"))
    elif configs == 0:
        print(_c(f"NCM manages {ncm_nodes} nodes but has 0 archived configs. Schedule/run a "
                 "'Download Configs' job in NCM, then re-run this script.", "yellow"))
    else:
        print(_c(f"NCM has {configs} archived configs across {ncm_nodes} nodes — data EXISTS. "
                 "If SW005/SW006 still show nothing in the app, that's a mapping bug: send the "
                 "'newest config' line above (its columns) so the query can be matched to your "
                 "schema.", "green"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
