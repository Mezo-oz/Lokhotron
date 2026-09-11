# Provider screen — candidate RU sensor hosts

Generated 2026-09-11 · OONI window `2026-06-13 .. 2026-09-11` · country `RU` · OONI coverage shown where a provider's ASNs carry ≥10 graded measurements.

OFAC screen: 40,075 entries across SDN, SDN alternate-names and the consolidated non-SDN list, matched on name tokens appearing in ≤25 entries (rarer tokens are identifiers; common ones like *region* or *center* are noise).

**Screening aid, not clearance.** A name match is not proof of designation; the absence of one is not permission to pay. Sanctions decisions need a human, and above hobby scale a lawyer — see [../deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).

| provider | reg. | ASNs | OFAC screen | prior review | OONI coverage |
|---|---|---|---|---|---|
| Selectel | RU | AS49505, AS50340, AS61976, AS198652 | no match | cleared by hand | `tor` 53.4% (n=58); `psiphon` 1.6% (n=62); `telegram` 46.4% (n=56) |
| Timeweb | RU | AS9123, AS51789 | no match | — | `tor` 99.6% (n=1375); `psiphon` 9.3% (n=1421); `telegram` 98.4% (n=1418) |
| Beget | RU | AS198610, AS213533 | no match | — | `tor` 25.0% (n=28); `psiphon` 6.1% (n=33); `telegram` 6.5% (n=31) |
| VDSina | RU | AS48282, AS216071 | no match | — | _none_ |
| Aeza | RU | AS210644 | **3 ENTITY HIT(S) — review** | **do not transact** | _none_ |
| IHOR | RU | AS199228, AS209641 | 9 person-name collision(s) | cleared by hand | `tor` 88.7% (n=106); `torsf` 41.4% (n=29); `psiphon` 0.9% (n=109); `telegram` 99.1% (n=108) |
| MTW | RU | AS48347 | **4 ENTITY HIT(S) — review** | cleared by hand | `torsf` 63.6% (n=11); `psiphon` 83.2% (n=202) |
| Cloud.ru | RU | AS208677 | no match | — | `tor` 98.6% (n=210); `torsf` 43.5% (n=23); `psiphon` 1.4% (n=215); `telegram` 99.5% (n=208) |
| Sprinthost | RU | AS35278, AS200563, AS201499 | no match | — | _none_ |
| Fornex | ES | AS48018, AS44051, AS16003, AS40840 | no match | cleared by hand | _none_ |
| Majordomo | RU | AS43362 | no match | — | _none_ |
| Rusonyx | RU | AS41535, AS205952 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| FirstByte | RU | AS204997, AS210703, AS205090 | **19 ENTITY HIT(S) — review** | cleared by hand | `tor` 86.9% (n=1828); `psiphon` 1.2% (n=1827); `telegram` 93.7% (n=1795) |
| Adman | RU | AS57494 | no match | — | _none_ |
| RU-CENTER | RU | AS5537, AS25537, AS39494, AS48287 | no match | — | _none_ |
| Yandex Cloud | RU | AS200350, AS13238 | no match | — | _none_ |
| Xelent / ATOMDATA | RU | AS199860 | no match | — | _none_ |
| DataLine | RU | AS34570, AS35297 | no match | — | _none_ |
| HOSTKEY | NL | AS57043 | no match | cleared by hand | _none_ |
| DDoS-Guard | RU | AS57724 | **22 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| StormWall | CZ | AS59796 | no match | — | _none_ |
| G-Core | LU | AS199524 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| EDIS | EU | AS57169 | no match | cleared by hand | `psiphon` 19.2% (n=26) |
| Melbicom | LT | AS56630 | no match | cleared by hand | _none_ |
| RASCOM | RU | AS20764 | no match | — | _none_ |
| Mastertel | RU | AS29226 | no match | — | `tor` 100.0% (n=10); `psiphon` 91.0% (n=234) |

## OFAC matches, for human review

Entity matches first — those are the ones that decide whether you may pay a company. Person-name collisions are listed after, and are usually exactly that: `Ihor` is a common Ukrainian given name, not evidence about a hosting company. `df` is how many sanctions entries share the matched token; low means distinctive.

### Aeza — 3 entity match(es)

- `SDN` on `aeza` (df=3): AEZA GROUP LLC
- `SDN` on `aeza` (df=3): AEZA INTERNATIONAL, LTD.
- `SDN` on `aeza` (df=3): AEZA LOGISTIC LLC

### MTW — 4 entity match(es)

- `SDN` on `ekspert` (df=4): RSV-EKSPERT OOO
- `SDN` on `ekspert` (df=4): LIMITED LIABILITY COMPANY EMS EKSPERT
- `SDN_ALT` on `ekspert` (df=4): OBSHCHESTVO S OGRANICHENNOI OTVETSTVENNOSTIU CHIP EKSPERT
- `SDN_ALT` on `ekspert` (df=4): OOO CHIP EKSPERT

### Rusonyx — 8 entity match(es)

- `SDN` on `astra` (df=8): FOREIGN LIMITED LIABILITY COMPANY DANA ASTRA
- `SDN` on `astra` (df=8): ASTRA
- `SDN` on `astra` (df=8): PUBLIC JOINT STOCK COMPANY ASTRA GROUP
- `SDN_ALT` on `astra` (df=8): FLLC DANA ASTRA
- `SDN_ALT` on `astra` (df=8): IOOO DANA ASTRA
- `SDN_ALT` on `astra` (df=8): ZTAA DANA ASTRA
- `SDN_ALT` on `astra` (df=8): INOSTRANNOYE OBSHCHESTVO S OGRANICHENNOY OTVETSTVENNOSTYU DANA ASTRA
- `SDN_ALT` on `astra` (df=8): ZAMEZHNAYE TAVARYSTVA Z ABMEZHAVANAY ADKAZNASTSYU DANA ASTRA

### FirstByte — 19 entity match(es)

- `SDN` on `first` (df=19): FIRST OF OCTOBER ANTIFASCIST RESISTANCE GROUP
- `SDN` on `first` (df=19): FIRST OIL JV CO LTD
- `SDN` on `first` (df=19): FIRST OCEAN ADMINISTRATION GMBH
- `SDN` on `first` (df=19): FIRST OCEAN GMBH & CO KG
- `SDN` on `first` (df=19): FIRST EAST EXPORT BANK PLC
- `SDN` on `first` (df=19): FIRST ISLAMIC INVESTMENT BANK LIMITED
- `SDN` on `first` (df=19): NON-STATE PENSION FUND FIRST INDUSTRIAL ALLIANCE
- `SDN` on `first` (df=19): LIMITED LIABILITY COMPANY FIRST LOGISTICS COMPANY
- `SDN` on `first` (df=19): ALLIANCE FIRST TRADING L.L.C
- `SDN` on `first` (df=19): FIRST VPN SERVICE
- `SDN_ALT` on `first` (df=19): FIRST FURAT TRADING LLC
- `SDN_ALT` on `first` (df=19): FIRST CREDIT BANK

### DDoS-Guard — 22 entity match(es)

- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS (IRGC)-QODS FORCE
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS AIR FORCE
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS AL-GHADIR MISSILE COMMAND
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS AEROSPACE FORCE SELF SUFFICIENCY JIHAD ORGANIZATION
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS RESEARCH AND SELF-SUFFICIENCY JEHAD ORGANIZATION
- `SDN` on `guard` (df=22): IRANIAN ISLAMIC REVOLUTIONARY GUARD CORPS CYBER-ELECTRONIC COMMAND
- `SDN` on `guard` (df=22): MINISTRY OF STATE SECURITY BORDER GUARD GENERAL BUREAU
- `SDN` on `guard` (df=22): ISLAMIC REVOLUTIONARY GUARD CORPS INTELLIGENCE ORGANIZATION
- `SDN` on `guard` (df=22): OBSHCHESTVO S OGRANICHENNOI OTVETSTVENNOSTYU GUARD KAPITAL
- `SDN_ALT` on `guard` (df=22): REVOLUTIONARY GUARD
- `SDN_ALT` on `guard` (df=22): IRAN'S REVOLUTIONARY GUARD CORPS

### G-Core — 8 entity match(es)

- `SDN` on `core` (df=1): SHENG CORE TECHNOLOGY CO LIMITED
- `SDN` on `labs` (df=7): LIMITED LIABILITY COMPANY RSK LABS
- `SDN` on `labs` (df=7): VALERIAN LABS, INC.
- `SDN` on `labs` (df=7): VALERIAN LABS DISTRIBUTION CORP.
- `SDN` on `labs` (df=7): UAB FLAVOUR LABS
- `SDN_ALT` on `labs` (df=7): KATRANJI LABS
- `SDN_ALT` on `labs` (df=7): RSK LABS OOO
- `SDN_ALT` on `labs` (df=7): HOLLYWOOD VAPE LABS, INC.

Recorded human review verdicts live in `providers.json` (`screen_review`), so a hit count that grows past what was reviewed is visible on the next run.

**Person-name collisions** (demoted; check only if that person owns the provider)

- IHOR: 9 on `ihor`

## Providers with OONI signal

| provider | test | graded n | block rate | 95% CI | contributing ASNs |
|---|---|---:|---:|---|---|
| Selectel | `tor` | 58 | **53.4%** | 40.8%–65.7% | AS49505 (n=13), AS50340 (n=45) |
| Selectel | `psiphon` | 62 | **1.6%** | 0.3%–8.6% | AS49505 (n=14), AS50340 (n=48) |
| Selectel | `telegram` | 56 | **46.4%** | 34.0%–59.3% | AS49505 (n=10), AS50340 (n=46) |
| Timeweb | `tor` | 1375 | **99.6%** | 99.1%–99.8% | AS9123 (n=1367), AS51789 (n=8) |
| Timeweb | `psiphon` | 1421 | **9.3%** | 7.9%–10.9% | AS9123 (n=1413), AS51789 (n=8) |
| Timeweb | `telegram` | 1418 | **98.4%** | 97.6%–98.9% | AS9123 (n=1410), AS51789 (n=8) |
| Beget | `tor` | 28 | **25.0%** | 12.7%–43.4% | AS198610 (n=28) |
| Beget | `psiphon` | 33 | **6.1%** | 1.7%–19.6% | AS198610 (n=33) |
| Beget | `telegram` | 31 | **6.5%** | 1.8%–20.7% | AS198610 (n=31) |
| IHOR | `tor` | 106 | **88.7%** | 81.2%–93.4% | AS209641 (n=106) |
| IHOR | `torsf` | 29 | **41.4%** | 25.5%–59.3% | AS209641 (n=29) |
| IHOR | `psiphon` | 109 | **0.9%** | 0.2%–5.0% | AS209641 (n=109) |
| IHOR | `telegram` | 108 | **99.1%** | 94.9%–99.8% | AS209641 (n=108) |
| MTW | `torsf` | 11 | **63.6%** | 35.4%–84.8% | AS48347 (n=11) |
| MTW | `psiphon` | 202 | **83.2%** | 77.4%–87.7% | AS48347 (n=202) |
| Cloud.ru | `tor` | 210 | **98.6%** | 95.9%–99.5% | AS208677 (n=210) |
| Cloud.ru | `torsf` | 23 | **43.5%** | 25.6%–63.2% | AS208677 (n=23) |
| Cloud.ru | `psiphon` | 215 | **1.4%** | 0.5%–4.0% | AS208677 (n=215) |
| Cloud.ru | `telegram` | 208 | **99.5%** | 97.3%–99.9% | AS208677 (n=208) |
| FirstByte | `tor` | 1828 | **86.9%** | 85.3%–88.4% | AS205090 (n=1828) |
| FirstByte | `psiphon` | 1827 | **1.2%** | 0.8%–1.8% | AS205090 (n=1827) |
| FirstByte | `telegram` | 1795 | **93.7%** | 92.5%–94.7% | AS205090 (n=1795) |
| EDIS | `psiphon` | 26 | **19.2%** | 8.5%–37.9% | AS57169 (n=26) |
| Mastertel | `tor` | 10 | **100.0%** | 72.2%–100.0% | AS29226 (n=10) |
| Mastertel | `psiphon` | 234 | **91.0%** | 86.7%–94.1% | AS29226 (n=234) |