# Provider screen — candidate RU sensor hosts

Generated 2026-09-09 · OONI window `2026-06-11 .. 2026-09-09` · country `RU` · OONI coverage shown where a provider's ASNs carry ≥10 graded measurements.

OFAC screen: 40,031 entries across SDN, SDN alternate-names and the consolidated non-SDN list, matched on name tokens appearing in ≤25 entries (rarer tokens are identifiers; common ones like *region* or *center* are noise).

**Screening aid, not clearance.** A name match is not proof of designation; the absence of one is not permission to pay. Sanctions decisions need a human, and above hobby scale a lawyer — see [../deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).

| provider | reg. | ASNs | OFAC screen | prior review | OONI coverage |
|---|---|---|---|---|---|
| Selectel | RU | AS49505, AS50340, AS61976, AS198652 | no match | cleared by hand | `tor` 56.5% (n=62); `psiphon` 1.5% (n=67); `telegram` 50.0% (n=60) |
| Timeweb | RU | AS9123, AS51789 | no match | — | `tor` 99.6% (n=1416); `psiphon` 9.0% (n=1464); `telegram` 98.4% (n=1460) |
| Beget | RU | AS198610, AS213533 | no match | — | `tor` 16.0% (n=25); `psiphon` 3.7% (n=27); `telegram` 7.4% (n=27) |
| VDSina | RU | AS48282, AS216071 | no match | — | _none_ |
| Aeza | RU | AS210644 | **3 ENTITY HIT(S) — review** | **do not transact** | _none_ |
| IHOR | RU | AS199228, AS209641 | 9 person-name collision(s) | cleared by hand | `tor` 89.5% (n=105); `torsf` 40.0% (n=30); `psiphon` 0.9% (n=108); `telegram` 100.0% (n=107) |
| MTW | RU | AS48347 | **4 ENTITY HIT(S) — review** | cleared by hand | `torsf` 58.3% (n=12); `psiphon` 79.7% (n=212); `telegram` 90.0% (n=10) |
| Cloud.ru | RU | AS208677 | no match | — | `tor` 98.6% (n=210); `torsf` 39.1% (n=23); `psiphon` 1.4% (n=215); `telegram` 99.5% (n=208) |
| Sprinthost | RU | AS35278, AS200563, AS201499 | no match | — | _none_ |
| Fornex | ES | AS48018, AS44051, AS16003, AS40840 | no match | cleared by hand | _none_ |
| Majordomo | RU | AS43362 | no match | — | _none_ |
| Rusonyx | RU | AS41535, AS205952 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| FirstByte | RU | AS204997, AS210703, AS205090 | **19 ENTITY HIT(S) — review** | cleared by hand | `tor` 87.1% (n=1878); `psiphon` 1.2% (n=1877); `telegram` 93.9% (n=1845) |
| Adman | RU | AS57494 | no match | — | _none_ |
| RU-CENTER | RU | AS5537, AS25537, AS39494, AS48287 | no match | — | _none_ |
| Yandex Cloud | RU | AS200350, AS13238 | no match | — | _none_ |
| Xelent / ATOMDATA | RU | AS199860 | no match | — | _none_ |
| DataLine | RU | AS34570, AS35297 | no match | — | _none_ |
| HOSTKEY | NL | AS57043 | no match | cleared by hand | _none_ |
| DDoS-Guard | RU | AS57724 | **22 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| StormWall | CZ | AS59796 | no match | — | _none_ |
| G-Core | LU | AS199524 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| EDIS | EU | AS57169 | no match | cleared by hand | `psiphon` 17.6% (n=34) |
| Melbicom | LT | AS56630 | no match | cleared by hand | _none_ |

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
| Selectel | `tor` | 62 | **56.5%** | 44.1%–68.1% | AS49505 (n=13), AS50340 (n=49) |
| Selectel | `psiphon` | 67 | **1.5%** | 0.3%–8.0% | AS49505 (n=14), AS50340 (n=53) |
| Selectel | `telegram` | 60 | **50.0%** | 37.7%–62.3% | AS49505 (n=10), AS50340 (n=50) |
| Timeweb | `tor` | 1416 | **99.6%** | 99.1%–99.8% | AS9123 (n=1408), AS51789 (n=8) |
| Timeweb | `psiphon` | 1464 | **9.0%** | 7.7%–10.6% | AS9123 (n=1456), AS51789 (n=8) |
| Timeweb | `telegram` | 1460 | **98.4%** | 97.6%–98.9% | AS9123 (n=1452), AS51789 (n=8) |
| Beget | `tor` | 25 | **16.0%** | 6.4%–34.7% | AS198610 (n=25) |
| Beget | `psiphon` | 27 | **3.7%** | 0.7%–18.3% | AS198610 (n=27) |
| Beget | `telegram` | 27 | **7.4%** | 2.1%–23.4% | AS198610 (n=27) |
| IHOR | `tor` | 105 | **89.5%** | 82.2%–94.0% | AS209641 (n=105) |
| IHOR | `torsf` | 30 | **40.0%** | 24.6%–57.7% | AS209641 (n=30) |
| IHOR | `psiphon` | 108 | **0.9%** | 0.2%–5.1% | AS209641 (n=108) |
| IHOR | `telegram` | 107 | **100.0%** | 96.5%–100.0% | AS209641 (n=107) |
| MTW | `torsf` | 12 | **58.3%** | 32.0%–80.7% | AS48347 (n=12) |
| MTW | `psiphon` | 212 | **79.7%** | 73.8%–84.6% | AS48347 (n=212) |
| MTW | `telegram` | 10 | **90.0%** | 59.6%–98.2% | AS48347 (n=10) |
| Cloud.ru | `tor` | 210 | **98.6%** | 95.9%–99.5% | AS208677 (n=210) |
| Cloud.ru | `torsf` | 23 | **39.1%** | 22.2%–59.2% | AS208677 (n=23) |
| Cloud.ru | `psiphon` | 215 | **1.4%** | 0.5%–4.0% | AS208677 (n=215) |
| Cloud.ru | `telegram` | 208 | **99.5%** | 97.3%–99.9% | AS208677 (n=208) |
| FirstByte | `tor` | 1878 | **87.1%** | 85.5%–88.5% | AS205090 (n=1878) |
| FirstByte | `psiphon` | 1877 | **1.2%** | 0.8%–1.8% | AS205090 (n=1877) |
| FirstByte | `telegram` | 1845 | **93.9%** | 92.7%–94.9% | AS205090 (n=1845) |
| EDIS | `psiphon` | 34 | **17.6%** | 8.3%–33.5% | AS57169 (n=34) |
