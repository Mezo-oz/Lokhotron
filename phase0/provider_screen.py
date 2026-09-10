#!/usr/bin/env python3
"""Screen candidate RU hosting providers on the two axes that decide whether you can rent them.

1. **Can we lawfully pay them?** Live OFAC screen against the SDN list, its alternate-names
   (alias) file, and the consolidated non-SDN list. For a US-operated project this is the
   gate: transacting with a designated person is strict liability, and intent is no defence.
   Aeza Group sits in `providers.json` as a control case — if the screen stops firing on
   Aeza, the screen is broken, not clean.

2. **What would we be measuring from there?** Whether the provider's ASNs appear in OONI's
   Russian coverage at all, and if so at what block rate. The Phase 0 finding was that block
   rates spread 87-96 pp *between* RU hosting providers, so the vantage a provider gives you
   is provider-specific. Most candidates turn out to have no OONI coverage at all, which is
   itself the answer: you cannot preview them, so diversify instead of optimising.

THIS IS A SCREENING AID, NOT A CLEARANCE. A name match is not proof of designation, and the
absence of a match is not permission to pay anyone. Both need a human, and above hobby scale
they need a lawyer. See deploy/LEGAL-RU.md.

Stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path

from ooni_gap import DEFAULT_TESTS, fetch_json, ooni_by_asn, pct, wilson

HERE = Path(__file__).resolve().parent
PROVIDERS_PATH = HERE / "providers.json"
OFAC_DIR = HERE / "cache" / "ofac"

RIPESTAT_SEARCH = "https://stat.ripe.net/data/searchcomplete/data.json"

# OFAC publishes these as redirects to a signed S3 URL; urllib follows them.
OFAC_SOURCES = {
    "SDN": "https://www.treasury.gov/ofac/downloads/sdn.csv",
    "SDN_ALT": "https://www.treasury.gov/ofac/downloads/alt.csv",
    "CONSOLIDATED": "https://www.treasury.gov/ofac/downloads/consolidated/cons_prim.csv",
}

USER_AGENT = "lokhotron-provider-screen/0.1 (+https://github.com/Mezo-oz/Lokhotron)"

# Tokens too generic to match on: they would hit unrelated sanctions entries.
STOPWORDS = {
    "llc", "ltd", "jsc", "inc", "sa", "sl", "bv", "srl", "sro", "plc", "gmbh", "as", "ooo",
    "group", "hosting", "cloud", "server", "servers", "tech", "technologies", "technology",
    "the", "and", "com", "ru", "limited", "company", "co", "corp", "holding", "holdings",
    "data", "net", "networks", "network", "systems", "system", "service", "services",
    # Legal-form suffixes. These identify a jurisdiction's company law, not a company.
    "s.l.", "b.v.", "s.r.o.", "a.s.", "s.a.", "n.v.", "sarl", "fzco", "dmcc", "oao", "zao",
    "pjsc", "ojsc", "cjsc", "gmbh.", "l.l.c", "l.l.c.", "spa", "pte", "pty", "kft",
    # Lithuanian/Latvian/Estonian legal forms. "uab" matched UAB FLAVOUR LABS against
    # Melbikomas UAB -- the same shape as the earlier s.l. and b.v. false positives.
    "uab", "ab", "sia", "oü", "ou",
}


def download_ofac(name: str, url: str, max_age_hours: float) -> Path:
    """Fetch an OFAC list, cached briefly. Sanctions data must be fresh: a stale copy is how
    you 'clear' someone designated last week."""
    OFAC_DIR.mkdir(parents=True, exist_ok=True)
    path = OFAC_DIR / f"{name}.csv"
    if path.exists():
        age_h = (time.time() - path.stat().st_mtime) / 3600
        if age_h < max_age_hours:
            return path
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = resp.read()
    path.write_bytes(data)
    return path


def load_ofac_entries(max_age_hours: float) -> list[dict]:
    """Every entry across the OFAC files, tagged individual vs entity.

    The distinction matters: 'Ihor' is one of the most common Ukrainian given names, so a
    token match against designated *people* named Ihor says nothing about whether the hosting
    company IHOR is designated. Person matches are kept but demoted, because they still
    matter when a designated individual owns the provider (as with Aeza's four).
    """
    entries: list[dict] = []
    kinds: dict[str, str] = {}
    for name, url in OFAC_SOURCES.items():
        try:
            path = download_ofac(name, url, max_age_hours)
        except Exception as e:  # a failed list must be loud, never silently "no hits"
            print(f"WARNING: could not fetch OFAC {name}: {e}", file=sys.stderr)
            entries.append({"list": name, "name": "__FETCH_FAILED__", "kind": "unknown",
                            "raw": str(e)})
            continue
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 2:
                    continue
                ent_num = (row[0] or "").strip()
                # SDN/CONS: num, name, type, program, ...   ALT: num, altnum, alttype, altname
                is_alt = name == "SDN_ALT"
                entity = row[3] if is_alt and len(row) > 3 else row[1]
                entity = (entity or "").strip().strip('"')
                if not entity or entity == "-0-":
                    continue
                if is_alt:
                    kind = kinds.get(ent_num, "unknown")
                else:
                    raw_kind = (row[2] or "").strip().lower() if len(row) > 2 else ""
                    kind = "individual" if raw_kind == "individual" else "entity"
                    kinds[ent_num] = kind
                entries.append({"list": name, "name": entity, "kind": kind,
                                "raw": " | ".join(c.strip() for c in row[:6])[:200]})
    return entries


def tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9.]+", (text or "").lower()) if len(t) > 2 and t not in STOPWORDS}


def strip_as_handle(holder: str) -> str:
    """RIPE holder strings are 'HANDLE Legal Name' ("SELECTEL-MSK JSC Selectel"). The handle
    is an operational label, not a company name, and matching on its geographic fragments
    ('msk', 'region', 'east') generates pure noise."""
    parts = (holder or "").split(None, 1)
    if len(parts) == 2 and re.fullmatch(r"[A-Za-z0-9._-]+", parts[0]) and parts[0].upper() == parts[0]:
        return parts[1]
    return holder


def document_frequency(entries: list[dict]) -> dict[str, int]:
    """How many sanctions entries each token appears in. Used to keep only *distinctive*
    tokens: 'region', 'center' and 'msk' appear in hundreds of entries and match nothing
    meaningful, while 'aeza' or 'selectel' appear only if that company is actually listed."""
    df: dict[str, int] = {}
    for e in entries:
        for t in tokens(e["name"]):
            df[t] = df.get(t, 0) + 1
    return df


def screen_names(needles: list[str], entries: list[dict],
                 df: dict[str, int], max_df: int) -> list[dict]:
    """Flag OFAC entries sharing a *distinctive* token with a provider's brand or legal name.

    Still deliberately over-inclusive — a false positive costs a human 30 seconds, a false
    negative costs an IEEPA violation — but a token that appears in more than `max_df`
    sanctions entries carries no signal, so keeping it only buries the real hits.
    """
    want: set[str] = set()
    for n in needles:
        want |= {t for t in tokens(n) if df.get(t, 0) <= max_df}
    hits = []
    for e in entries:
        if e["name"] == "__FETCH_FAILED__":
            hits.append({"list": e["list"], "entity": "LIST FETCH FAILED", "kind": "unknown",
                         "matched": "", "df": 0, "fetch_failed": True})
            continue
        overlap = want & tokens(e["name"])
        if overlap:
            hits.append({"list": e["list"], "entity": e["name"], "kind": e["kind"],
                         "matched": ",".join(sorted(overlap)),
                         "df": min(df.get(t, 0) for t in overlap), "fetch_failed": False})
    return hits


def resolve_asns(name: str) -> list[tuple[int, str]]:
    """RIPEstat name -> ASNs, for --refresh-asns."""
    data = fetch_json(RIPESTAT_SEARCH, {"resource": name})
    out = []
    for cat in data.get("data", {}).get("categories", []):
        if cat.get("category") != "ASNs":
            continue
        for s in cat.get("suggestions", []):
            m = re.match(r"AS(\d+)", s.get("value", ""))
            if m:
                out.append((int(m.group(1)), s.get("description", "")))
    return out


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    today = date.today()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cc", default="RU")
    ap.add_argument("--since", default=str(today - timedelta(days=90)),
                    help="wider default window than the gap read: small providers need time "
                         "to accumulate any OONI coverage at all")
    ap.add_argument("--until", default=str(today))
    ap.add_argument("--tests", nargs="*", default=list(DEFAULT_TESTS))
    ap.add_argument("--min-n", type=int, default=10)
    ap.add_argument("--ofac-max-age-hours", type=float, default=24.0)
    ap.add_argument("--max-df", type=int, default=25,
                    help="ignore name tokens appearing in more than this many sanctions "
                         "entries; they are generic words, not identifiers")
    ap.add_argument("--refresh-asns", action="store_true",
                    help="re-resolve provider names to ASNs via RIPEstat and rewrite providers.json")
    ap.add_argument("--out-md", metavar="FILE")
    args = ap.parse_args()

    spec = json.loads(PROVIDERS_PATH.read_text(encoding="utf-8"))
    providers = spec["providers"]

    if args.refresh_asns:
        for p in providers:
            found = resolve_asns(p["name"])
            if found:
                p["asns"] = sorted({a for a, _ in found})
                p["holders"] = [d for _, d in found]
            time.sleep(0.3)
        PROVIDERS_PATH.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n",
                                  encoding="utf-8")
        print("providers.json refreshed", file=sys.stderr)

    print("fetching OFAC lists ...", file=sys.stderr)
    ofac = load_ofac_entries(args.ofac_max_age_hours)
    df = document_frequency(ofac)
    print(f"  {len(ofac)} sanctions entries loaded, {len(df)} distinct name tokens",
          file=sys.stderr)

    print("fetching OONI coverage ...", file=sys.stderr)
    per_test: dict[str, dict[int, dict]] = {}
    for t in args.tests:
        per_test[t] = {r["probe_asn"]: r for r in ooni_by_asn(args.cc, t, args.since, args.until)}

    rows = []
    for p in providers:
        needles = [p["name"]] + [strip_as_handle(h) for h in p.get("holders", [])]
        hits = screen_names(needles, ofac, df, args.max_df)
        cov = []
        for t in args.tests:
            anomaly = ok = 0
            seen = []
            for asn in p["asns"]:
                r = per_test[t].get(asn)
                if not r:
                    continue
                a = r.get("anomaly_count") or 0
                o = r.get("ok_count") or 0
                if a + o <= 0:
                    continue
                anomaly += a
                ok += o
                seen.append((asn, a, o))
            graded = anomaly + ok
            if graded >= args.min_n:
                cov.append({"test": t, "graded": graded, "anomaly": anomaly,
                            "rate": anomaly / graded, "ci": list(wilson(anomaly, graded)),
                            "asns": seen})
        rows.append({"provider": p, "ofac": hits, "coverage": cov})

    out: list[str] = []
    out.append("# Provider screen — candidate RU sensor hosts")
    out.append("")
    out.append(f"Generated {today} · OONI window `{args.since} .. {args.until}` · country "
               f"`{args.cc}` · OONI coverage shown where a provider's ASNs carry "
               f"≥{args.min_n} graded measurements.")
    out.append("")
    out.append(f"OFAC screen: {len(ofac):,} entries across SDN, SDN alternate-names and the "
               f"consolidated non-SDN list, matched on name tokens appearing in ≤{args.max_df} "
               "entries (rarer tokens are identifiers; common ones like *region* or *center* "
               "are noise).")
    out.append("")
    out.append("**Screening aid, not clearance.** A name match is not proof of designation; the "
               "absence of one is not permission to pay. Sanctions decisions need a human, and "
               "above hobby scale a lawyer — see [../deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).")
    out.append("")
    out.append("| provider | reg. | ASNs | OFAC screen | prior review | OONI coverage |")
    out.append("|---|---|---|---|---|---|")
    for r in rows:
        p = r["provider"]
        real_hits = [h for h in r["ofac"] if not h["fetch_failed"]]
        failed = [h for h in r["ofac"] if h["fetch_failed"]]
        ents = [h for h in real_hits if h["kind"] == "entity"]
        people = [h for h in real_hits if h["kind"] != "entity"]
        if failed:
            flag = "**UNKNOWN — list fetch failed**"
        elif ents:
            flag = f"**{len(ents)} ENTITY HIT(S) — review**"
        elif people:
            flag = f"{len(people)} person-name collision(s)"
        else:
            flag = "no match"
        if r["coverage"]:
            cov = "; ".join(f"`{c['test']}` {pct(c['rate'])} (n={c['graded']})"
                            for c in r["coverage"])
        else:
            cov = "_none_"
        asns = ", ".join(f"AS{a}" for a in p["asns"][:4]) + ("..." if len(p["asns"]) > 4 else "")
        review = p.get("screen_review", "")
        verdict = "—"
        if review:
            verdict = "**do not transact**" if review.startswith("DESIGNATED") else "cleared by hand"
        out.append(f"| {p['name']} | {p.get('country','?')} | {asns} | {flag} | {verdict} | {cov} |")

    out.append("")
    out.append("## OFAC matches, for human review")
    out.append("")
    out.append("Entity matches first — those are the ones that decide whether you may pay a "
               "company. Person-name collisions are listed after, and are usually exactly that: "
               "`Ihor` is a common Ukrainian given name, not evidence about a hosting company. "
               "`df` is how many sanctions entries share the matched token; low means "
               "distinctive.")
    out.append("")
    any_entity = False
    for r in rows:
        ents = [h for h in r["ofac"] if not h["fetch_failed"] and h["kind"] == "entity"]
        if not ents:
            continue
        any_entity = True
        out.append(f"### {r['provider']['name']} — {len(ents)} entity match(es)")
        out.append("")
        for h in sorted(ents, key=lambda h: h["df"])[:12]:
            out.append(f"- `{h['list']}` on `{h['matched']}` (df={h['df']}): {h['entity']}")
        out.append("")
    if not any_entity:
        out.append("_No candidate matched an OFAC entity. Aeza is in the candidate set as a "
                   "control case, so zero entity hits means the screen is broken — investigate "
                   "before trusting it._")
        out.append("")
    out.append("Recorded human review verdicts live in `providers.json` (`screen_review`), so a "
               "hit count that grows past what was reviewed is visible on the next run.")
    out.append("")
    out.append("**Person-name collisions** (demoted; check only if that person owns the provider)")
    out.append("")
    for r in rows:
        people = [h for h in r["ofac"] if not h["fetch_failed"] and h["kind"] != "entity"]
        if people:
            toks = sorted({h["matched"] for h in people})
            out.append(f"- {r['provider']['name']}: {len(people)} on {', '.join('`'+t+'`' for t in toks[:5])}")

    out.append("")
    out.append("## Providers with OONI signal")
    out.append("")
    out.append("| provider | test | graded n | block rate | 95% CI | contributing ASNs |")
    out.append("|---|---|---:|---:|---|---|")
    for r in rows:
        for c in r["coverage"]:
            asns = ", ".join(f"AS{a} (n={x+y})" for a, x, y in c["asns"])
            out.append(f"| {r['provider']['name']} | `{c['test']}` | {c['graded']} | "
                       f"**{pct(c['rate'])}** | {pct(c['ci'][0])}–{pct(c['ci'][1])} | {asns} |")

    md = "\n".join(out)
    if args.out_md:
        Path(args.out_md).write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
