# Legal and sanctions risk check — before renting the RU sensor

**This is a research summary, not legal advice, and nobody here is your lawyer.** It is a
structured read of public sources as of **2026-08-27**, written so you can make an informed
decision and so a lawyer has something concrete to react to. OONI — who have more experience
putting measurement software in hostile jurisdictions than anyone — say plainly that in some
countries *any* form of active network measurement may be illegal or treated as espionage, and
that you should consult a lawyer licensed in the relevant country before running it. That advice
applies here.

Russian internet law changes several times a year. **Re-read this before you rent, not when you
first read it.** Dated claims below carry their date for that reason.

---

## The headline: the sharpest near-term risk is American, not Russian

The obvious worry is Russian law. But for a **US-operated** project, the exposure that is most
likely to actually bite — strict liability, no intent requirement, enforced against you at home —
is **US sanctions at the moment you pay the hosting bill**.

On **1 July 2025** OFAC designated **Aeza Group** (a St. Petersburg hosting provider), together
with Aeza Logistic LLC, Cloud Solutions LLC, its UK branch Aeza International Ltd, and four
individuals, as a bulletproof-hosting operation serving ransomware and infostealer crews. A US
person transacting with an SDN commits an IEEPA violation; it is **strict liability** — "I was
doing censorship research" is not a defence, and neither is not knowing.

Note what that means for our own tooling: **`phase0/asn_classes.json` lists `aeza` as a hosting
brand.** The gap read would happily bucket it as a legitimate DC vantage. Classification for
measurement and eligibility for procurement are different questions, and the tool answers only the
first.

Payment mechanics make this worse rather than better. Russian hosts typically want Russian cards
or crypto, and the crypto rail is closing: the EU's 20th package bans transactions with Russian
crypto services outright **from 24 May 2026**, with the 21st package (July 2026) extending to
third-country providers used by Russia, and OFAC has designated crypto addresses tied to Russian
bulletproof hosting. The practical path of least resistance for paying a Russian VPS is very close
to the path that is sanctioned.

**Before paying anyone:**

1. Check the provider, its parent, and its affiliates against the OFAC SDN list — by name **and
   known aliases**, since designations name subsidiaries and branches separately (the Aeza action
   covered four entities and four people).
2. Re-check at **renewal**, not just at signup. Designations land mid-contract.
3. Decide the payment rail **in advance** and keep the receipts. Do not improvise through crypto
   or a settlement intermediary; that is the sanctioned channel.
4. If the spend or the profile grows beyond a hobby VPS, get a sanctions opinion. EO 14071's
   service prohibitions run US→Russia and so do not obviously cover *buying* hosting, but the
   IT/cloud service prohibitions make the analysis less clean than it looks.

---

## Russian-side exposure, by layer

The three-tree split (DESIGN.md) turns out to be load-bearing legally, not just operationally. The
layers have genuinely different exposure.

### Sensing (this repo, the RU VPS) — low, with one hard rule

- **Using circumvention tools is not itself criminally prosecutable.** HRW's July 2025 report
  states a person cannot be prosecuted directly for using such tools. Since the law passed
  **22 July 2025** (in force September 2025), VPN use is however an **aggravating circumstance** in
  other criminal cases, and searching "extremist" material — including via VPN — is an
  administrative offence.
- **Computer-crime exposure is low *because of how the battery is built*.** Art. 272 (unlawful
  access) requires access **plus** a consequence — destruction, blocking, modification or copying
  of information. Art. 274.1 (critical information infrastructure) carries 2–6 years, and is the
  article that would matter if you touched infrastructure you do not own. Our probes talk **only to
  an echo server we control**, with our own consent, and copy nothing from anyone.
- **Therefore, a hard design rule, not a preference: the battery never points at a host we do not
  own.** No third-party scanning, no "let's just check what Rostelecom's resolver does," ever.
  That single constraint is what keeps the sensing layer boring in Russian law. It is already how
  `probe` is written; this is the reason it must stay that way.
- **We are not offering a service to anyone.** The sensor provides no third party with access to
  blocked resources, so it is not a VPN/anonymiser service under the 2017 rules and not an
  information-dissemination organiser. Self-measurement is a different activity, and the
  distinction is worth being able to articulate.

### Publishing (the write-up, the bundles) — this is where RU law actually reaches us

- **Since 1 March 2024, disseminating information about circumvention tools is prohibited** —
  guides, reviews, even lists of working services. Roskomnadzor claimed **8,700+ sites blocked**
  under it by 10 April 2025, and advertising circumvention tools draws fines of **50,000–80,000 RUB**
  for individuals.
- A signed bundle saying "use this transport in this region" is, functionally, exactly what that
  rule targets. Against a US-based publisher the realistic enforcement is **blocking plus
  designation**, not prosecution — but plan for the blocking, because it hits distribution.
- **Precedent worth taking seriously: Roskomsvoboda**, an internet-freedom *research* organisation,
  was designated a "foreign agent" in December 2022 and shut down in September 2025. Russia also
  blocked **OONI Explorer** in 2024. Measurement and research projects are designation targets in
  their own right — publishing findings is the act that draws attention, not running the sensor.

### Volunteers / client-as-sensor — highest risk, already deferred

Recruiting people in Russia to run sensors is the highest-human-risk path available, and this check
reinforces the existing decision: **don't**. Phase 3's opt-in client-as-sensor with k-anonymous,
edge-aggregated telemetry is the design that gets residential signal without a named volunteer
carrying the risk. Nothing here changes that ordering, and the founding principle (the client never
runs on anyone who did not install it) is the ethical floor underneath it.

---

## Renting mechanics: identity, and why not to be clever about it

- Hosting providers serving Russia must be in Roskomnadzor's register (from **1 February 2024**);
  ~472 organisations were listed by late November 2024. Draft rules would extend the reported data
  to **recipients of services**.
- Identity verification is tightening generally: from **1 September 2026**, `.ru`/`.рф` domain
  registration and renewal require registrant verification (Gosuslugi, a Russian digital signature,
  Russian corporate documents, or payment from a Russian/EAEU bank account).
- Practical read: renting is increasingly identity-bound, and a foreigner may simply be unable to
  buy from some providers. **Do not solve that with false registration details.** Fraudulent
  registration converts a boring hosting contract into an offence of its own and destroys the "I am
  a researcher measuring my own server" posture that keeps the sensing layer defensible. If a
  provider won't sell to you honestly, pick another provider.

## Enforcement climate (2026) — also a measurement-validity problem

- **February 2026:** the FSB gained the power to *demand* mobile operators shut down cellular
  service, with the "security threat" justification requirement removed.
- Operators were directed to block access for detected VPN users by **15 April 2026** or risk IT
  accreditation and whitelist status; some operators meter international mobile traffic above
  15 GB/month, effectively taxing VPN use.
- ISPs are themselves prosecuted for letting traffic bypass TSPU: administrative fines up to
  **5m RUB**, and Criminal Code Art. 274.2 provides up to 3 years for repeat violations.

The last point cuts both ways for us. It confirms TSPU compliance is enforced at the operator —
which is the mechanism Correction 3 rests on — and it means our sensor's own traffic pattern may be
throttled or blocked as a side effect. That is a **measurement-validity** issue as much as a legal
one, and it is another argument for the `timeout_indistinct` rate being tracked as a first-class
number.

---

## Decision checklist (do these in order, before creating anything)

1. **OFAC-screen the candidate provider**, its parent and affiliates, by name and alias. Aeza is
   the known-designated example; absence from this doc is not clearance.
2. **Fix the payment rail** and confirm it avoids Russian crypto services and settlement
   intermediaries. If you cannot pay cleanly, that provider is out.
3. **Rent in your own name with accurate details.** No false registration data, ever.
4. **Confirm the hard rule holds in the deployed config:** every probe target is a host you own.
   Check `lokhotron-sensor.env` before enabling the timer.
5. **Keep the name invariant** — "Lokhotron"/лохотрон appears on no RU-facing infrastructure,
   hostname, payload, or working tree. Not cosmetic: the name links the box to the public repo,
   and the repo is the publishing layer that carries the exposure this whole document is about.
   The deploy scripts enforce it via `LOK_PREFIX` rather than leaving it to memory — see
   [DEPLOY.md](DEPLOY.md) "The name invariant". Note this is *broader* than the client-facing
   rule in STATUS.md, which binds only artifacts that reach a client; both now stand, and
   STATUS.md records both.
6. **Assume the published findings get blocked in Russia,** and keep the client tree separate so a
   designation against the publishing side does not reach the client's trust anchor.
7. **If you may travel to Russia or a jurisdiction with a close law-enforcement relationship to it,
   talk to a lawyer first.** This is the one item where the personal stakes are categorically
   different from the project stakes.
8. **Re-run this check before renting.** Two of the facts above changed within the last twelve
   months.

## Re-check triggers

Anything below invalidates part of this document: a new OFAC designation touching a candidate
provider; the draft rule on reporting hosting *service recipients* being adopted; any prosecution
under the March 2024 dissemination ban reaching a foreign publisher; a change to Art. 274.1's
scope; or a designation action against a measurement project.

---

## Sources

- OONI, *Risks: things you should know before running OONI Probe* — https://ooni.org/about/risks/
- OONI, *Russia blocked OONI Explorer* (2024) — https://ooni.org/post/2024-russia-blocked-ooni-explorer
- US Treasury, *Sanctions on Aeza Group* (1 July 2025) — https://home.treasury.gov/news/press-releases/sb0185
- Chainalysis, *OFAC sanctions Aeza Group* — https://www.chainalysis.com/blog/ofac-sanctions-aeza-group-bulletproof-hosting-crypto-payments-july-2025/
- Human Rights Watch, *Disrupted, Throttled, and Blocked* (30 July 2025) — https://www.hrw.org/report/2025/07/30/disrupted-throttled-and-blocked/state-censorship-control-and-increasing-isolation
- Zona Media, *Russia's internet censorship in 2026* (7 April 2026) — https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026
- Zona Media, *Search and be fined* (15 July 2025) — https://en.zona.media/article/2025/07/15/searchban
- Freedom House, *Freedom on the Net 2025: Russia* — https://freedomhouse.org/country/russia/freedom-net/2025
- Gorodissky, *Russia introduced new requirements for hosting providers* — https://www.gorodissky.com/publications/articles/russia-introduced-new-requirements-for-hosting-providers/
- Council of the EU, *21st sanctions package* (23 July 2026) — https://www.consilium.europa.eu/en/press/press-releases/2026/07/23/21st-package-of-sanctions-eu-hits-russian-energy-financial-services-and-crypto-hard/
- Wikipedia, *Roskomsvoboda* (foreign-agent designation, shutdown) — https://en.wikipedia.org/wiki/Roskomsvoboda
- OFAC, *Russian Harmful Foreign Activities Sanctions* program page — https://ofac.treasury.gov/sanctions-programs-and-country-information/russian-harmful-foreign-activities-sanctions
