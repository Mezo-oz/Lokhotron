#!/usr/bin/env python3
"""OONI residential-vs-datacenter reachability gap read (Phase 0's one job).

Correction 3 in DESIGN.md claims a cheap RU VPS may sit behind a *different* TSPU box, or
none — so a datacenter vantage could be categorically wrong about the consumer path. That
claim is load-bearing for how much a VPS-only Phase 1 is allowed to conclude, and until now
it has been an argument, not a measurement.

This is the recruitment-free first read on it: take OONI's existing Russian coverage for
circumvention-tool reachability, split the reporting ASNs into consumer-operator networks
and hosting/datacenter networks, and compare the block rates. No volunteers, no new
vantages, no risk to anyone.

What it CANNOT do, stated up front because the number is easy to over-read:
  * These are tool/endpoint reachability tests (Tor, Psiphon, Telegram, ...), not the
    VPN-protocol handshake shaping Lokhotron actually measures. Directional only.
  * OONI probes on hosting ASNs are few and self-selected; they are not our DC sensor.
  * "anomaly" is OONI's heuristic, not a confirmed block (confirmed_count is reported
    separately).
  * A gap here supports Correction 3; the absence of one does not refute it, because the
    two sides are not the same measurement.

Once the RU VPS exists, --dc-measurements swaps our own probe results in for the hosting
side, which is the comparison DESIGN.md actually asks for ("run the same reachability
checks from your DC VPS and diff them").

Stdlib only, so it runs on a bare sensor box.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path

OONI_AGGREGATION = "https://api.ooni.io/api/v1/aggregation"
RIPESTAT_AS_NAMES = "https://stat.ripe.net/data/as-names/data.json"

HERE = Path(__file__).resolve().parent
CLASSES_PATH = HERE / "asn_classes.json"
CACHE_PATH = HERE / "cache" / "asn_names.json"

# Tool-reachability tests. DESIGN.md §Phase 0 names telegram/tor/torsf; psiphon and
# riseupvpn are included as the closest thing OONI has to a VPN-reachability signal.
# vanilla_tor is deliberately excluded: ~95% of its RU measurements are failures
# (measurement errors, not blocking), so its rate says more about the test than the path.
DEFAULT_TESTS = ("tor", "torsf", "psiphon", "telegram", "riseupvpn")

USER_AGENT = "lokhotron-phase0-gapread/0.1 (+https://github.com/Mezo-oz/Lokhotron)"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def fetch_json(url: str, params: dict, retries: int = 3, timeout: int = 60) -> dict:
    full = f"{url}?{urllib.parse.urlencode(params)}"
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(full, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
            time.sleep(1.5 * (attempt + 1))
    raise SystemExit(f"giving up on {full}: {last}")


def ooni_by_asn(cc: str, test_name: str, since: str, until: str) -> list[dict]:
    """Per-ASN aggregation for one test. Returns [] if the test has no coverage."""
    data = fetch_json(
        OONI_AGGREGATION,
        {
            "probe_cc": cc,
            "test_name": test_name,
            "since": since,
            "until": until,
            "axis_x": "probe_asn",
        },
    )
    result = data.get("result", [])
    return result if isinstance(result, list) else [result]


def resolve_asn_names(asns: list[int], cache: dict, chunk: int = 100) -> dict:
    """ASN -> RIPE holder name, cached on disk. Names are what the classifier reads, so
    resolving them (rather than hardcoding AS numbers) keeps the buckets auditable."""
    missing = [a for a in asns if str(a) not in cache]
    for i in range(0, len(missing), chunk):
        batch = missing[i : i + chunk]
        data = fetch_json(RIPESTAT_AS_NAMES, {"resource": ",".join(f"AS{a}" for a in batch)})
        names = data.get("data", {}).get("names", {})
        for asn in batch:
            cache[str(asn)] = names.get(str(asn)) or ""
        time.sleep(0.3)  # be a polite RIPEstat client
    return cache


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class Classifier:
    """Buckets an ASN by its RIPE holder name.

    Word-boundary keyword rules over a verified name, plus explicit per-ASN overrides.
    Anything unmatched stays `unclassified` and is reported with its name rather than
    quietly dropped — an unclassified tail carrying real volume is a reason to distrust the
    headline number, so it has to stay visible.
    """

    def __init__(self, spec: dict):
        self.overrides = {str(k): v for k, v in spec.get("overrides", {}).items()}
        self.rules = []
        for rule in spec.get("rules", []):
            pats = [
                re.compile(r"(?<![a-z0-9])" + re.escape(k.lower()) + r"(?![a-z0-9])")
                for k in rule["match"]
            ]
            self.rules.append((rule["class"], pats))

    def classify(self, asn: int, name: str) -> str:
        if str(asn) in self.overrides:
            return self.overrides[str(asn)]
        low = (name or "").lower()
        for cls, pats in self.rules:
            if any(p.search(low) for p in pats):
                return cls
        return "unclassified"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval, so a bucket built from 30 measurements cannot be read
    with the same confidence as one built from 30,000."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((centre - spread) / denom, (centre + spread) / denom)


class Bucket:
    def __init__(self) -> None:
        self.anomaly = 0
        self.ok = 0
        self.failure = 0
        self.confirmed = 0
        self.asns: dict[int, dict] = {}

    def add(self, row: dict) -> None:
        self.anomaly += row.get("anomaly_count") or 0
        self.ok += row.get("ok_count") or 0
        self.failure += row.get("failure_count") or 0
        self.confirmed += row.get("confirmed_count") or 0
        self.asns[row["probe_asn"]] = row

    @property
    def graded(self) -> int:
        """Measurements that produced a verdict. Failures are excluded: the test could not
        run, which says nothing about whether the path is blocked."""
        return self.anomaly + self.ok

    @property
    def rate(self) -> float | None:
        return self.anomaly / self.graded if self.graded else None

    def ci(self) -> tuple[float, float]:
        return wilson(self.anomaly, self.graded)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def render_report(report: dict, names: dict) -> str:
    m = report["meta"]
    out: list[str] = []
    out.append("# OONI gap read — consumer-operator vs datacenter reachability")
    out.append("")
    out.append(
        f"Country `{m['cc']}` · window `{m['since']} .. {m['until']}` · ASNs with "
        f"≥{m['min_n']} graded measurements per test · produced by `phase0/ooni_gap.py`."
    )
    out.append("")
    out.append(
        "Block rate = `anomaly / (anomaly + ok)`. OONI **failures are excluded from the "
        "denominator** — the test could not run, which is not evidence of blocking — and are "
        "reported separately. Intervals are 95% Wilson."
    )
    if m.get("dc_source"):
        out.append("")
        out.append(
            f"**The datacenter side here is our own probe** (`{m['dc_source']}`), not OONI "
            "hosting-ASN measurements."
        )

    out.append("")
    out.append("## Headline")
    out.append("")
    out.append("| test | side | ASNs | graded n | block rate | 95% CI | failures |")
    out.append("|---|---|---:|---:|---:|---|---:|")
    for t in m["tests"]:
        r = report["tests"].get(t)
        if not r or (not r["consumer"]["graded"] and not r["hosting"]["graded"]):
            continue
        for label, key in (("consumer ISP", "consumer"), ("hosting/DC", "hosting"),
                           ("_unclassified_", "unclassified")):
            b = r[key]
            ci = f"{pct(b['ci'][0])}–{pct(b['ci'][1])}" if b["graded"] else "—"
            out.append(
                f"| `{t}` | {label} | {b['asn_count']} | {b['graded']} | "
                f"**{pct(b['rate'])}** | {ci} | {b['failure']} |"
            )
        gap = "n/a" if r["gap_pp"] is None else f"{r['gap_pp']:+.1f} pp"
        verdict = "intervals disjoint" if r["intervals_disjoint"] else "intervals overlap"
        out.append(f"| `{t}` | **gap (consumer − DC)** | | | **{gap}** | {verdict} | |")

    out.append("")
    out.append("## Coverage of the classification")
    out.append("")
    out.append("| test | classified n | unclassified n | unclassified share |")
    out.append("|---|---:|---:|---:|")
    for t in m["tests"]:
        r = report["tests"].get(t)
        if not r:
            continue
        cls_n = r["consumer"]["graded"] + r["hosting"]["graded"]
        unc_n = r["unclassified"]["graded"]
        total = cls_n + unc_n
        share = pct(unc_n / total) if total else "n/a"
        out.append(f"| `{t}` | {cls_n} | {unc_n} | {share} |")
    out.append("")
    out.append(
        "An unclassified tail carrying real volume is a reason to distrust the headline, so it "
        "is reported rather than dropped — with its own block rate in the table above. The tail "
        "is mostly small regional ISPs, so a tail rate close to the consumer bucket's is "
        "evidence the classification choice did not manufacture the gap. Extend "
        "`phase0/asn_classes.json` to shrink it."
    )

    out.append("")
    out.append("## Datacenter side, per ASN")
    out.append("")
    out.append(
        "The DC bucket is small and heterogeneous — pooling it hides the thing Correction 3 is "
        "about, so here is every ASN in it."
    )
    for t in m["tests"]:
        r = report["tests"].get(t)
        if not r or not r["hosting"].get("per_asn"):
            continue
        out.append("")
        out.append(f"**`{t}`**")
        out.append("")
        out.append("| ASN | holder | graded n | block rate | 95% CI |")
        out.append("|---|---|---:|---:|---|")
        for row in r["hosting"]["per_asn"]:
            out.append(
                f"| AS{row['asn']} | {row['name']} | {row['graded']} | "
                f"**{pct(row['rate'])}** | {pct(row['ci'][0])}–{pct(row['ci'][1])} |"
            )

    out.append("")
    out.append("## Bucket membership")
    by_class: dict[str, list[tuple[int, str]]] = {}
    for asn, info in report["asns"].items():
        by_class.setdefault(info["class"], []).append((int(asn), info["name"]))
    for cls in ("consumer_isp", "hosting_dc", "unclassified"):
        rows = sorted(by_class.get(cls, []))
        out.append("")
        out.append(f"**{cls}** ({len(rows)} ASNs)")
        out.append("")
        if not rows:
            out.append("_none_")
            continue
        out.append("| ASN | RIPE holder |")
        out.append("|---|---|")
        for asn, name in rows:
            out.append(f"| AS{asn} | {name or '_(no name)_'} |")

    out.append("")
    out.append("## What this can and cannot say")
    out.append("")
    out.append(
        "- These are **tool/endpoint reachability** tests, not VPN-protocol handshake shaping. "
        "The gap is directional evidence about DESIGN.md Correction 3, not a prediction of what "
        "Lokhotron's battery will see."
    )
    out.append(
        "- OONI probes on hosting ASNs are **few and self-selected** — someone chose to run "
        "ooniprobe on a VPS. They are not our DC sensor and may not sit behind the same "
        "equipment as the VPS we eventually rent."
    )
    out.append(
        "- `anomaly` is OONI's heuristic, not a confirmed block; `confirmed` is tracked "
        "separately in the JSON output."
    )
    out.append(
        "- A gap **supports** Correction 3. The absence of one does **not** refute it: these are "
        "different populations measured by the same test, not the same measurement from two "
        "vantages. That comparison needs `--dc-measurements` and a real RU VPS."
    )
    out.append(
        "- Classification is by RIPE holder name, so a renamed or mis-registered holder lands in "
        "the unclassified tail rather than in the wrong bucket."
    )
    return "\n".join(out)


# ---------------------------------------------------------------------------

def main() -> int:
    # The report is full of ±, ≥ and en dashes; a cp1252 console would otherwise kill the
    # run *after* the work is done.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    today = date.today()
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cc", default="RU")
    ap.add_argument("--since", default=str(today - timedelta(days=30)))
    ap.add_argument("--until", default=str(today))
    ap.add_argument("--tests", nargs="*", default=list(DEFAULT_TESTS))
    ap.add_argument("--min-n", type=int, default=20,
                    help="minimum graded measurements for an ASN to join a bucket")
    ap.add_argument("--dc-measurements", metavar="FILE",
                    help='our own DC probe results, {"test": {"anomaly": n, "ok": n}}; '
                         "replaces the OONI hosting side once the RU VPS exists")
    ap.add_argument("--out-json", metavar="FILE")
    ap.add_argument("--out-md", metavar="FILE")
    args = ap.parse_args()

    spec = json.loads(CLASSES_PATH.read_text(encoding="utf-8"))
    clf = Classifier(spec)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8")) if CACHE_PATH.exists() else {}

    raw: dict[str, list[dict]] = {}
    for test in args.tests:
        print(f"fetching {test} ...", file=sys.stderr)
        raw[test] = ooni_by_asn(args.cc, test, args.since, args.until)

    all_asns = sorted({
        row["probe_asn"]
        for rows in raw.values()
        for row in rows
        if (row.get("anomaly_count") or 0) + (row.get("ok_count") or 0) >= args.min_n
    })
    print(f"resolving {len(all_asns)} ASN names ...", file=sys.stderr)
    cache = resolve_asn_names(all_asns, cache)
    CACHE_PATH.write_text(
        json.dumps(cache, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8"
    )

    dc_override = None
    if args.dc_measurements:
        dc_override = json.loads(Path(args.dc_measurements).read_text(encoding="utf-8"))

    report = {
        "meta": {
            "cc": args.cc,
            "since": args.since,
            "until": args.until,
            "tests": args.tests,
            "min_n": args.min_n,
            "source": OONI_AGGREGATION,
            "names_source": RIPESTAT_AS_NAMES,
            "dc_source": args.dc_measurements,
        },
        "tests": {},
        "asns": {},
    }

    for test in args.tests:
        buckets = {"consumer_isp": Bucket(), "hosting_dc": Bucket(), "unclassified": Bucket()}
        for row in raw[test]:
            asn = row["probe_asn"]
            graded = (row.get("anomaly_count") or 0) + (row.get("ok_count") or 0)
            if graded < args.min_n:
                continue
            name = cache.get(str(asn), "")
            cls = clf.classify(asn, name)
            buckets[cls].add(row)
            report["asns"].setdefault(str(asn), {"name": name, "class": cls})

        entry = {}
        for label, key in (("consumer", "consumer_isp"), ("hosting", "hosting_dc"),
                           ("unclassified", "unclassified")):
            b = buckets[key]
            lo, hi = b.ci()
            entry[label] = {
                "graded": b.graded, "anomaly": b.anomaly, "ok": b.ok,
                "failure": b.failure, "confirmed": b.confirmed,
                "rate": b.rate, "ci": [lo, hi], "asn_count": len(b.asns),
            }
        # The DC bucket is small and, in practice, wildly heterogeneous — one provider can
        # be near-clean while its neighbour is fully blocked. A pooled rate hides exactly
        # the thing Correction 3 is about, so keep the per-ASN detail.
        per_asn = []
        for asn, row in buckets["hosting_dc"].asns.items():
            a = row.get("anomaly_count") or 0
            g = a + (row.get("ok_count") or 0)
            per_asn.append({
                "asn": asn, "name": cache.get(str(asn), ""), "graded": g, "anomaly": a,
                "rate": (a / g if g else None), "ci": list(wilson(a, g)),
            })
        entry["hosting"]["per_asn"] = sorted(per_asn, key=lambda r: -r["graded"])

        if dc_override and test in dc_override:
            d = dc_override[test]
            graded = d.get("anomaly", 0) + d.get("ok", 0)
            entry["hosting"] = {
                "graded": graded, "anomaly": d.get("anomaly", 0), "ok": d.get("ok", 0),
                "failure": d.get("failure", 0), "confirmed": 0,
                "rate": (d["anomaly"] / graded if graded else None),
                "ci": list(wilson(d.get("anomaly", 0), graded)),
                "asn_count": 1, "source": "own_dc_probe",
            }

        c_rate, h_rate = entry["consumer"]["rate"], entry["hosting"]["rate"]
        entry["gap_pp"] = None if c_rate is None or h_rate is None else 100 * (c_rate - h_rate)
        # Non-overlapping 95% intervals: a conservative "these two differ".
        entry["intervals_disjoint"] = bool(
            c_rate is not None and h_rate is not None
            and (entry["consumer"]["ci"][0] > entry["hosting"]["ci"][1]
                 or entry["hosting"]["ci"][0] > entry["consumer"]["ci"][1])
        )
        report["tests"][test] = entry

    if args.out_json:
        Path(args.out_json).write_text(
            json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8"
        )
    md = render_report(report, cache)
    if args.out_md:
        Path(args.out_md).write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
