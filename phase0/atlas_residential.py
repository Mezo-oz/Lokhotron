#!/usr/bin/env python3
"""Residential RU vantage without recruiting anyone: RIPE Atlas.

The gap this closes. Every vantage this project can *buy* is a datacentre box, and
DESIGN.md's Correction 3 says the measurement that matters most -- residential -- is the
one you cannot buy. OONI gives residential signal but it is other people's measurements
against other people's targets. RIPE Atlas gives **controlled** measurements from probes
in Russian consumer networks, aimed at a host we own, with the probe hosts having opted in
years ago. That is the ethical difference from a residential proxy, and it is the whole
reason this is usable at all.

What it cannot do: run the battery. Atlas probes execute a fixed set of measurement types,
so there is no lok-wire, no AF_PACKET capture, no injected-RST detection. Do not read an
Atlas result as a Lokhotron verdict -- the vocabulary in CONTRACT.md does not apply here.

What it can do, and why each earns its place:
  sslcert   -- a full TLS handshake to our own host. An SNI-triggered reset or a substituted
               certificate shows up directly, from a consumer vantage. This is the closest
               thing to the `injected_rst_at_sni` question that Atlas can answer.
  traceroute-- shows *where* on the path a probe dies, which separates "blocked near the
               user" from "blocked at the border" -- a distinction the DC boxes cannot make.
  ping      -- cheap reachability baseline to interpret the other two against.

Hard rule, same as the battery: every target is a host we own. Never point this at a third
party -- that is where Art. 274.1 lands (deploy/LEGAL-RU.md).

Usage:
    export ATLAS_API_KEY=...          # atlas.ripe.net -> your profile -> API keys
    python phase0/atlas_residential.py --target <our-echo-server-ip> --dry-run
    python phase0/atlas_residential.py --target <our-echo-server-ip> --probes 25

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://atlas.ripe.net/api/v2"


def post(path: str, body: dict, key: str) -> dict:
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Key " + key,
            "User-Agent": "phase0-atlas/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit("Atlas API %s: %s" % (e.code, e.read().decode()[:600]))


def get(path: str, key: str | None = None) -> dict:
    headers = {"User-Agent": "phase0-atlas/1.0"}
    if key:
        headers["Authorization"] = "Key " + key
    req = urllib.request.Request(API + path, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def build(target: str, n: int, port: int) -> dict:
    # `nat` biases probe selection toward RFC1918-behind-NAT hosts, which is the practical
    # marker of a home connection rather than a rack. It is a bias, not a guarantee -- record
    # the probe ASNs from the results and classify properly at analysis time.
    probes = [{"type": "country", "value": "RU", "requested": n, "tags": {"include": ["nat"]}}]
    return {
        "definitions": [
            {
                "type": "sslcert",
                "af": 4,
                "target": target,
                "port": port,
                "description": "RU residential -> our host: TLS handshake (SNI-block check)",
                "is_oneoff": True,
            },
            {
                "type": "traceroute",
                "af": 4,
                "target": target,
                "protocol": "ICMP",
                "description": "RU residential -> our host: where does the path die",
                "is_oneoff": True,
            },
            {
                "type": "ping",
                "af": 4,
                "target": target,
                "description": "RU residential -> our host: reachability baseline",
                "is_oneoff": True,
            },
        ],
        "probes": probes,
        "is_oneoff": True,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True, help="a host WE OWN (the echo server)")
    ap.add_argument("--probes", type=int, default=25)
    ap.add_argument("--port", type=int, default=443, help="sslcert port; 443 unless you moved it")
    ap.add_argument("--dry-run", action="store_true", help="print the request and the credit cost")
    ap.add_argument("--results", metavar="MSM_ID", help="fetch results for a measurement id")
    args = ap.parse_args()

    key = os.environ.get("ATLAS_API_KEY")

    if args.results:
        for r in get("/measurements/%s/results/?format=json" % args.results, key):
            print(json.dumps(r)[:400])
        return

    body = build(args.target, args.probes, args.port)

    if args.dry_run:
        print(json.dumps(body, indent=2))
        print("\n3 one-off measurements x %d probes." % args.probes)
        print("Nothing was sent. Drop --dry-run to create them.")
        return

    if not key:
        sys.exit("set ATLAS_API_KEY (atlas.ripe.net -> profile -> API keys, "
                 "permission: create a new user-defined measurement)")

    try:
        me = get("/credits/", key)
        print("credit balance: %s" % me.get("current_balance"))
    except Exception:
        pass

    out = post("/measurements/", body, key)
    ids = out.get("measurements", [])
    print("created:", ids)
    for i in ids:
        print("  https://atlas.ripe.net/measurements/%s/" % i)
    print("\nResults land within a few minutes. Fetch with:")
    if ids:
        print("  python phase0/atlas_residential.py --target %s --results %s" % (args.target, ids[0]))


if __name__ == "__main__":
    main()
