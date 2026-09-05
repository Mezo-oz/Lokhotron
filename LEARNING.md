# Learning log

A teaching log of every change to this repo, newest first. Each entry explains not just what
changed but why it was done that way, in plain language, so the code never outruns understanding.

## 2026-09-04 — A dead sensor is not a censorship finding — uncommitted (on top of 9ae0b34)

**What changed:** The script that runs the probe every ten minutes on a rented Russian box used
to write "the connection died with no distinguishing shape" whenever *anything* went wrong —
including the probe program being missing, the config file being unreadable, or the box having
been suspended by the provider. Now it checks that the instrument is fit before each run and,
if it isn't, writes a separate kind of row that means "no measurement was taken", with the
reason. The contract that defines the vocabulary gained that new word, and its version went
from 0.1 to 0.2.

**The breakdown.**

*The bash side (`deploy/run-battery.sh`).* The old script was one line: run the probe, and if it
fails for any reason, `|| echo '{"kind":"timeout_indistinct"}'`. Think of a smoke detector wired
so that a dead battery makes it sound the alarm. Every failure of the *detector* looked like
*smoke*. Over an unattended week, a suspended box would have produced hundreds of rows saying
"the censor blocks everything uniformly" — a wall of confident, false findings.

The fix is a **precondition gate**: before the probe runs, the script proves each thing it is
about to rely on. Is the config readable? Is the key 64 hex characters? Does the probe binary
exist? Do we hold the capability the capture needs? Each check that fails calls one function,
`not_evaluated reason detail`, which writes the row and exits. This is the same pattern as a
pilot's pre-flight checklist: it does not make the plane fly better, it stops you taking off in
a plane that cannot fly and then blaming the weather.

One check looks like bit-twiddling and is worth demystifying. Linux **capabilities** are the
root superpower chopped into ~40 separate permissions; `CAP_NET_RAW` is the one that lets a
program open a raw socket and see packets below the normal TCP/UDP layers, which is how the probe
spots a forged RST. The kernel publishes the current process's capability set as a hex number in
`/proc/self/status` on the `CapEff:` line. `CAP_NET_RAW` is capability number 13, so we ask "is
bit 13 set?" with `(( ((16#$capeff >> 13) & 1) == 0 ))`. Read it left to right: `16#` tells bash
the string is base-16; `>> 13` slides the number thirteen places right so bit 13 becomes bit 0;
`& 1` keeps only that lowest bit. It is exactly the same as checking one switch on a long switch
panel — you count over to the thirteenth and look at it. Why check at all, when the probe already
degrades gracefully without the capability? Because "degrades" here means *moves rows between
columns*: without capture, an injected RST looks like a plain timeout, so a real finding would be
filed under the null verdict. A measurement that silently changes what it measures is not a
weaker measurement; it is a different one.

The script also stopped throwing away **stderr**. Programs have two output streams: stdout (the
answer) and stderr (commentary and complaints). The old `2>/dev/null` sent all complaints to a
black hole — so when the probe failed, nothing recorded *why*. Now stderr goes to a temp file
(`mktemp`), and gets carried into the row: as the `detail` on a `not_evaluated` row, or as a
sibling `"stderr"` field beside a real verdict. That sibling placement is deliberate: the verdict
is a claim about the censor and is aggregated; the stderr is a note for the operator and must
never be aggregated, so they sit next to each other, not inside each other.

Small but real: `set -uo pipefail` without `-e`. `-e` ("exit on any error") sounds safe, but here
every failure has a handler that must run *and write a row*; `-e` would kill the script before
the handler could. `-u` (undefined variable is an error) and `pipefail` (a pipeline fails if any
stage fails) stay on because they catch typos rather than hide outcomes.

*The Rust side (`crates/lok-contract/src/lib.rs`).* `Verdict` is an **enum**: a type whose value
must be exactly one of a listed set of variants — a form with radio buttons, where you can tick
one and only one. It gained a variant, `NotEvaluated { reason, detail }`. The question you settled
was whether this belonged *in* the enum or as a separate field the wrapper adds on the side. The
argument for "in": Rust's `match` on an enum is **exhaustive** — the compiler refuses to build
any code that handles some variants and forgets one. So every future consumer that switches on a
verdict will be *forced* to decide what to do with "no measurement", instead of discovering the
side field months later. A state that lives outside the enum is a state you can forget. Inside,
forgetting is a compile error, and the compile error is the whole product.

`reason` is itself a small enum, `NotEvaluatedReason`, rather than a free string — the same
closed-vocabulary principle as the verdicts: strings drift ("no-cap", "nocap", "missing
capability"), enum variants can't. `detail` *is* a free string, and that's allowed precisely
because nothing aggregates on it. The `#[serde(default, skip_serializing_if = "String::is_empty")]`
line means: when reading JSON, a missing `detail` becomes `""` rather than an error, and when
writing, an empty one is left out. **serde** is the library that turns Rust values into JSON and
back; those attributes are instructions to it, not to Rust.

There is also a tiny helper, `is_measurement()`, which is `!matches!(self, Verdict::NotEvaluated
{ .. })`. `matches!` is a macro that asks "does this value have this shape?" and returns a bool;
`{ .. }` means "whatever the fields hold, I don't care". It exists so a consumer can filter rows in
one obvious call rather than each re-inventing the check.

The **contract version** bumped 0.1 → 0.2. It's a *minor* bump because the change is additive:
nothing old changed meaning. But the contract also says an old reader treats unknown verdicts as
`timeout_indistinct` — which would turn the fix back into the bug. Hence the new rule in
CONTRACT.md: don't feed 0.2 sensor rows to a 0.1 reader.

*One more, in the rig scripts.* `echo "$out" | grep -q X` became `grep -q X <<< "$out"`. `grep -q`
exits as soon as it finds a match and stops reading; if `echo` is still writing into the pipe, it
gets a SIGPIPE signal and fails, and with `pipefail` on, a *successful match* can read as failure.
`<<<` is a **here-string**: bash hands the text to grep as its stdin with no second process and no
pipe, so there is nothing to break. The bug was latent here (the outputs are tiny and fit the pipe
buffer), but it bit dpi-bench, and it costs one line to make it impossible.

**Scary-parts amnesty.** The only thing here that looks like wizardry is `16#$capeff >> 13 & 1`,
and it is just "convert from hex, count to the thirteenth switch, read it". Everything else is
if-statements.

**Check yourself.** The probe already handles a missing `CAP_NET_RAW` by falling back to a plain
TCP probe and still producing a verdict. So why does the wrapper refuse to run it at all in that
case, instead of accepting the weaker verdict?

<details><summary>Answer</summary>
Because the fallback doesn't produce a weaker verdict, it produces a <em>wrong column</em>. Without
the capture, an injected RST is indistinguishable from an ordinary timeout, so a real RST-block
would be recorded as <code>timeout_indistinct</code> — the null verdict — and the week's headline
metric ("how much lands in the null column") would be inflated by the instrument, not the censor.
A run that changes what it measures is not a measurement of the same thing, so it is filed as
<code>not_evaluated</code> with <code>reason: no_capability</code>.
</details>
