# Provider screen — candidate RU sensor hosts

Generated 2026-09-01 · OONI window `2026-06-03 .. 2026-09-01` · country `RU` · OONI coverage shown where a provider's ASNs carry ≥10 graded measurements.

OFAC screen: 39,949 entries across SDN, SDN alternate-names and the consolidated non-SDN list, matched on name tokens appearing in ≤25 entries (rarer tokens are identifiers; common ones like *region* or *center* are noise).

**Screening aid, not clearance.** A name match is not proof of designation; the absence of one is not permission to pay. Sanctions decisions need a human, and above hobby scale a lawyer — see [../deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).

| provider | reg. | ASNs | OFAC screen | prior review | OONI coverage |
|---|---|---|---|---|---|
| Selectel | RU | AS49505, AS50340, AS61976, AS198652 | no match | cleared by hand | `tor` 53.4% (n=58); `psiphon` 6.2% (n=65); `telegram` 48.1% (n=54) |
| Timeweb | RU | AS9123, AS51789 | no match | — | `tor` 99.6% (n=1528); `psiphon` 7.9% (n=1581); `telegram` 98.6% (n=1577) |
| Beget | RU | AS198610, AS213533 | no match | — | `tor` 16.0% (n=25); `psiphon` 3.7% (n=27); `telegram` 7.4% (n=27) |
| VDSina | RU | AS48282, AS216071 | no match | — | _none_ |
| Aeza | RU | AS210644 | **3 ENTITY HIT(S) — review** | **do not transact** | _none_ |
| IHOR | RU | AS199228, AS209641 | 9 person-name collision(s) | cleared by hand | `tor` 88.8% (n=98); `torsf` 40.6% (n=32); `psiphon` 1.0% (n=101); `telegram` 100.0% (n=100) |
| MTW | RU | AS48347 | **4 ENTITY HIT(S) — review** | cleared by hand | `tor` 90.9% (n=11); `torsf` 54.5% (n=11); `psiphon` 78.1% (n=279); `telegram` 81.8% (n=11) |
| Cloud.ru | RU | AS208677 | no match | — | `tor` 98.5% (n=206); `torsf` 38.1% (n=21); `psiphon` 1.9% (n=211); `telegram` 98.6% (n=207) |
| Sprinthost | RU | AS35278, AS200563, AS201499 | no match | — | _none_ |
| Fornex | ES | AS48018, AS44051, AS16003, AS40840 | no match | cleared by hand | _none_ |
| Majordomo | RU | AS43362 | no match | — | _none_ |
| Rusonyx | RU | AS41535, AS205952 | **8 ENTITY HIT(S) — review** | cleared by hand | _none_ |
| FirstByte | RU | AS204997, AS210703, AS205090 | **19 ENTITY HIT(S) — review** | cleared by hand | `tor` 85.1% (n=2024); `psiphon` 0.7% (n=2023); `telegram` 96.8% (n=1988) |
| Adman | RU | AS57494 | no match | — | _none_ |
| RU-CENTER | RU | AS5537, AS25537, AS39494, AS48287 | no match | — | _none_ |
| Yandex Cloud | RU | AS200350, AS13238 | no match | — | `tor` 80.0% (n=15); `psiphon` 6.7% (n=15); `telegram` 81.2% (n=16) |
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
| Selectel | `tor` | 58 | **53.4%** | 40.8%–65.7% | AS49505 (n=15), AS50340 (n=43) |
| Selectel | `psiphon` | 65 | **6.2%** | 2.4%–14.8% | AS49505 (n=16), AS50340 (n=49) |
| Selectel | `telegram` | 54 | **48.1%** | 35.4%–61.1% | AS49505 (n=11), AS50340 (n=43) |
| Timeweb | `tor` | 1528 | **99.6%** | 99.1%–99.8% | AS9123 (n=1520), AS51789 (n=8) |
| Timeweb | `psiphon` | 1581 | **7.9%** | 6.7%–9.3% | AS9123 (n=1573), AS51789 (n=8) |
| Timeweb | `telegram` | 1577 | **98.6%** | 97.9%–99.1% | AS9123 (n=1569), AS51789 (n=8) |
| Beget | `tor` | 25 | **16.0%** | 6.4%–34.7% | AS198610 (n=25) |
| Beget | `psiphon` | 27 | **3.7%** | 0.7%–18.3% | AS198610 (n=27) |
| Beget | `telegram` | 27 | **7.4%** | 2.1%–23.4% | AS198610 (n=27) |
| IHOR | `tor` | 98 | **88.8%** | 81.0%–93.6% | AS209641 (n=98) |
| IHOR | `torsf` | 32 | **40.6%** | 25.5%–57.7% | AS209641 (n=32) |
| IHOR | `psiphon` | 101 | **1.0%** | 0.2%–5.4% | AS209641 (n=101) |
| IHOR | `telegram` | 100 | **100.0%** | 96.3%–100.0% | AS209641 (n=100) |
| MTW | `tor` | 11 | **90.9%** | 62.3%–98.4% | AS48347 (n=11) |
| MTW | `torsf` | 11 | **54.5%** | 28.0%–78.7% | AS48347 (n=11) |
| MTW | `psiphon` | 279 | **78.1%** | 72.9%–82.6% | AS48347 (n=279) |
| MTW | `telegram` | 11 | **81.8%** | 52.3%–94.9% | AS48347 (n=11) |
| Cloud.ru | `tor` | 206 | **98.5%** | 95.8%–99.5% | AS208677 (n=206) |
| Cloud.ru | `torsf` | 21 | **38.1%** | 20.8%–59.1% | AS208677 (n=21) |
| Cloud.ru | `psiphon` | 211 | **1.9%** | 0.7%–4.8% | AS208677 (n=211) |
| Cloud.ru | `telegram` | 207 | **98.6%** | 95.8%–99.5% | AS208677 (n=207) |
| FirstByte | `tor` | 2024 | **85.1%** | 83.5%–86.6% | AS205090 (n=2024) |
| FirstByte | `psiphon` | 2023 | **0.7%** | 0.4%–1.2% | AS205090 (n=2023) |
| FirstByte | `telegram` | 1988 | **96.8%** | 96.0%–97.5% | AS205090 (n=1988) |
| Yandex Cloud | `tor` | 15 | **80.0%** | 54.8%–93.0% | AS200350 (n=15) |
| Yandex Cloud | `psiphon` | 15 | **6.7%** | 1.2%–29.8% | AS200350 (n=15) |
| Yandex Cloud | `telegram` | 16 | **81.2%** | 57.0%–93.4% | AS200350 (n=16) |