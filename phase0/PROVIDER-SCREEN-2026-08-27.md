# Provider screen — candidate RU sensor hosts

Generated 2026-08-27 · OONI window `2026-05-29 .. 2026-08-27` · country `RU` · OONI coverage shown where a provider's ASNs carry ≥10 graded measurements.

OFAC screen: 39,947 entries across SDN, SDN alternate-names and the consolidated non-SDN list, matched on name tokens appearing in ≤25 entries (rarer tokens are identifiers; common ones like *region* or *center* are noise).

**Screening aid, not clearance.** A name match is not proof of designation; the absence of one is not permission to pay. Sanctions decisions need a human, and above hobby scale a lawyer — see [../deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).

| provider | reg. | ASNs | OFAC screen | prior review | OONI coverage |
|---|---|---|---|---|---|
| Selectel | RU | AS49505, AS50340, AS61976, AS198652 | no match | cleared by hand | `tor` 57.4% (n=54); `psiphon` 6.3% (n=63); `telegram` 50.9% (n=55) |
| Timeweb | RU | AS9123, AS51789 | no match | — | `tor` 99.5% (n=1617); `psiphon` 7.4% (n=1675); `telegram` 98.2% (n=1671) |
| Beget | RU | AS198610, AS213533 | no match | — | `tor` 16.0% (n=25); `psiphon` 3.7% (n=27); `telegram` 7.4% (n=27) |
| VDSina | RU | AS48282, AS216071 | no match | — | _none_ |
| Aeza | RU | AS210644 | **3 ENTITY HIT(S) — review** | **do not transact** | _none_ |
| IHOR | RU | AS199228, AS209641 | 9 person-name collision(s) | cleared by hand | `tor` 83.7% (n=98); `torsf` 41.9% (n=31); `psiphon` 1.0% (n=101); `telegram` 100.0% (n=100) |
| MTW | RU | AS48347 | **4 ENTITY HIT(S) — review** | cleared by hand | `tor` 90.9% (n=11); `torsf` 60.0% (n=10); `psiphon` 79.1% (n=325); `telegram` 80.0% (n=10) |
| Cloud.ru | RU | AS208677 | no match | — | `tor` 98.5% (n=201); `torsf` 40.0% (n=20); `psiphon` 1.9% (n=206); `telegram` 98.5% (n=202) |
| Sprinthost | RU | AS35278, AS200563, AS201499 | no match | — | _none_ |
| Fornex | ES | AS48018, AS44051, AS16003, AS40840 | no match | cleared by hand | _none_ |
| Majordomo | RU | AS43362 | no match | — | _none_ |
| Rusonyx | RU | AS41535, AS205952 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| FirstByte | RU | AS204997, AS210703, AS205090 | **19 ENTITY HIT(S) — review** | cleared by hand | `tor` 80.1% (n=2103); `psiphon` 0.3% (n=2102); `telegram` 98.5% (n=2066) |
| Adman | RU | AS57494 | no match | — | _none_ |
| RU-CENTER | RU | AS5537, AS25537, AS39494, AS48287 | no match | — | _none_ |
| Yandex Cloud | RU | AS200350, AS13238 | no match | — | `tor` 60.0% (n=20); `psiphon` 5.0% (n=20); `telegram` 63.6% (n=22) |
| Xelent / ATOMDATA | RU | AS199860 | no match | — | _none_ |
| DataLine | RU | AS34570, AS35297 | no match | — | _none_ |
| HOSTKEY | NL | AS57043 | no match | cleared by hand | _none_ |
| DDoS-Guard | RU | AS57724 | **22 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| StormWall | CZ | AS59796 | no match | — | _none_ |
| G-Core | LU | AS199524 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |

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
| Selectel | `tor` | 54 | **57.4%** | 44.2%–69.7% | AS49505 (n=15), AS50340 (n=39) |
| Selectel | `psiphon` | 63 | **6.3%** | 2.5%–15.2% | AS49505 (n=18), AS50340 (n=45) |
| Selectel | `telegram` | 55 | **50.9%** | 38.1%–63.6% | AS49505 (n=15), AS50340 (n=40) |
| Timeweb | `tor` | 1617 | **99.5%** | 99.0%–99.7% | AS9123 (n=1609), AS51789 (n=8) |
| Timeweb | `psiphon` | 1675 | **7.4%** | 6.2%–8.8% | AS9123 (n=1667), AS51789 (n=8) |
| Timeweb | `telegram` | 1671 | **98.2%** | 97.4%–98.7% | AS9123 (n=1663), AS51789 (n=8) |
| Beget | `tor` | 25 | **16.0%** | 6.4%–34.7% | AS198610 (n=25) |
| Beget | `psiphon` | 27 | **3.7%** | 0.7%–18.3% | AS198610 (n=27) |
| Beget | `telegram` | 27 | **7.4%** | 2.1%–23.4% | AS198610 (n=27) |
| IHOR | `tor` | 98 | **83.7%** | 75.1%–89.7% | AS209641 (n=98) |
| IHOR | `torsf` | 31 | **41.9%** | 26.4%–59.2% | AS209641 (n=31) |
| IHOR | `psiphon` | 101 | **1.0%** | 0.2%–5.4% | AS209641 (n=101) |
| IHOR | `telegram` | 100 | **100.0%** | 96.3%–100.0% | AS209641 (n=100) |
| MTW | `tor` | 11 | **90.9%** | 62.3%–98.4% | AS48347 (n=11) |
| MTW | `torsf` | 10 | **60.0%** | 31.3%–83.2% | AS48347 (n=10) |
| MTW | `psiphon` | 325 | **79.1%** | 74.3%–83.1% | AS48347 (n=325) |
| MTW | `telegram` | 10 | **80.0%** | 49.0%–94.3% | AS48347 (n=10) |
| Cloud.ru | `tor` | 201 | **98.5%** | 95.7%–99.5% | AS208677 (n=201) |
| Cloud.ru | `torsf` | 20 | **40.0%** | 21.9%–61.3% | AS208677 (n=20) |
| Cloud.ru | `psiphon` | 206 | **1.9%** | 0.8%–4.9% | AS208677 (n=206) |
| Cloud.ru | `telegram` | 202 | **98.5%** | 95.7%–99.5% | AS208677 (n=202) |
| FirstByte | `tor` | 2103 | **80.1%** | 78.3%–81.7% | AS204997 (n=1), AS205090 (n=2102) |
| FirstByte | `psiphon` | 2102 | **0.3%** | 0.2%–0.7% | AS204997 (n=1), AS205090 (n=2101) |
| FirstByte | `telegram` | 2066 | **98.5%** | 97.9%–99.0% | AS204997 (n=1), AS205090 (n=2065) |
| Yandex Cloud | `tor` | 20 | **60.0%** | 38.7%–78.1% | AS200350 (n=20) |
| Yandex Cloud | `psiphon` | 20 | **5.0%** | 0.9%–23.6% | AS200350 (n=20) |
| Yandex Cloud | `telegram` | 22 | **63.6%** | 43.0%–80.3% | AS200350 (n=22) |