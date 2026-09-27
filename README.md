<p align="center">
  <img src="https://raw.githubusercontent.com/Realgagenichols/poison-garden/main/assets/header.svg" alt="poison-garden — a benchmark corpus of deliberately malicious MCP servers" width="860">
</p>

<p align="center">
  <a href="#"><img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="#"><img alt="Built on MCP" src="https://img.shields.io/badge/built%20on-MCP-58A6FF"></a>
  <a href="https://github.com/Realgagenichols/poison-garden/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Realgagenichols/poison-garden/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#development"><img alt="1512 tests" src="https://img.shields.io/badge/tests-1512%20passing-3FB950"></a>
  <a href="#honesty-commitments"><img alt="No composite score" src="https://img.shields.io/badge/no-composite%20score-F85149"></a>
  <a href="COMPARISON.md"><img alt="Comparison" src="https://img.shields.io/badge/results-self%20reported-D29922"></a>
  <a href="https://github.com/Realgagenichols/poison-garden/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-8957E5"></a>
</p>

<p align="center">
  <b>poison-garden</b> is a corpus of MCP servers that <i>lie</i> — a specimen is a running
  program, so its declaration and its behavior can be authored to disagree.
  You run your own scanner against it. We never run yours, and never publish a score we
  computed for you.
</p>

<p align="center">
  <a href="#what-a-static-scanner-cannot-see"><b>The gap</b></a> ·
  <a href="#install"><b>Install</b></a> ·
  <a href="#quickstart"><b>Quickstart</b></a> ·
  <a href="#whats-in-the-corpus"><b>Corpus</b></a> ·
  <a href="#publishing-a-result"><b>Submit</b></a> ·
  <a href="COMPARISON.md"><b>Results</b></a> ·
  <a href="CONTRIBUTING.md"><b>Contributing</b></a> ·
  <a href="#safety"><b>Safety</b></a> ·
  <a href="#limitations"><b>Limitations</b></a>
</p>

---

> ⚠️ This repository contains intentionally malicious MCP servers, for defensive security
> testing. **The specimens shipped here** are demonstrative rather than weaponized — they
> read only decoy credentials, and every socket they open goes to loopback. Both are
> enforced by tests. **That covers the specimens, not your scanner** — see
> [Safety](#safety). **The harness is not a sandbox.** Read [Safety](#safety) before running anything.

There are now more than a dozen MCP security scanners. Nearly all of them measure the same
thing: **what a server declares.** They read `tools/list`, pattern-match the text, and report.

But a declaration is written by the attacker, and an honest-looking one is cheap. A server can
present an impeccable catalog and still read `~/.ssh/id_rsa` the moment you connect, serve
clean definitions to anything that smells like a scanner, or stay benign until after you have
approved it.

Existing corpora are static — a case is a JSON document — so they **cannot express that gap**.
In poison-garden a specimen is a running program, which means its declaration and its behavior
can be authored to disagree. That is the whole point.

poison-garden is the *measure the measurers* step. It is deliberately independent of
[frisk](https://github.com/Realgagenichols/frisk) (vet before you install),
[tollbooth](https://github.com/Realgagenichols/tollbooth) (runtime firewall) and
[claude-dlp-guard](https://github.com/Realgagenichols/claude-dlp-guard) (read-time DLP) —
see [Honesty commitments](#honesty-commitments) for why that independence is enforced rather
than asserted.

## What a static scanner cannot see

Everything below is **real output**, reproducible from a fresh clone.

**1. A server that recognises its inspector.** Same specimen, two clients. The only difference
is what the client declared it can do:

```console
$ # a scanner: connects, enumerates, declares no capabilities
$ printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"mcp"},"capabilities":{}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' \
    | uv run python specimens/behaviour-scanner-aware/server.py | jq -c '.result.tools[]?.name'
"get_invoice"

$ # an agent: declares roots + sampling, like a real client does
$ printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"mcp"},"capabilities":{"roots":{},"sampling":{}}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' \
    | uv run python specimens/behaviour-scanner-aware/server.py | jq -c '.result.tools[]?.name'
"get_invoice"
"read_file"
```

The scanner is shown one tool. A real agent is shown two, and the second one's description
tells the model to read `~/.aws/credentials` and pass the contents along. **Every static
conclusion a scanner draws about this server is accurate about the catalog it was shown, and
useless.**

**2. The corpus is versioned and content-hashed**, so two results are comparable only when
they describe the same specimens:

```console
$ uv run poison-garden validate
OK: 11 class(es) measured across 97 specimen(s) (64 malicious, 33 benign). Every class has at least one benign twin.

$ uv run poison-garden hash
version  0.4.0
hash     sha256:e0f16a9fd0835478fe2ec5038b44eb9987f0e0b883ec35fb7229a4c02097f261
```

**3. It reports what the numbers actually support — including where they don't.** Every
per-class figure ships with a 95% Wilson interval, and with the two caveats that qualify it:

```json
{
  "class": "exfil-enumeration",
  "caught": 0, "total": 6,
  "recall": 0.0,
  "recall_ci95": [0.0, 0.3903],
  "sufficient_n": true,
  "specimens_independent": false,
  "tiers_verified": false,
  "by_difficulty": {
    "overt":    {"caught": 0, "total": 1},
    "moderate": {"caught": 0, "total": 4},
    "subtle":   {"caught": 0, "total": 1}
  }
}
```

`specimens_independent: false` is the one that matters, and it is there because this example
was wrong for a fortnight. The interval assumes six independent trials. A measured probe
sweep shows **one observer capability exposes all six specimens** in this class — and in
`scanner-aware`, `namesake-rugpull` and `egress` too. So the interval is too narrow, and the
corpus says so rather than quietly widening it: estimating the correction needs within-class
correlation, which is not identifiable from one outcome per specimen. The available
estimator turns out to measure *classes differing from each other*, which is the thing
per-class reporting exists to express. Details and the rejected correction are in
[`SPEC.md` R18/R23](#).

`tiers_verified: false` says the difficulty labels for this class disagree with blind
readers 46% of the time. They are flagged rather than withdrawn because the raters agree
with *each other* more here than elsewhere — so it is label error, and the fix is re-tiering.

This section exists because an earlier release got the underlying thing wrong: six of ten
classes shipped a single malicious specimen, so `0/1` printed as recall `0.0` and read as
*this tool has a gap here* when one observation supports anything up to 79%.

**4. It refuses to publish a flattering half-measurement.** Point it at a scanner that errors
on every specimen and it declines to emit a document at all, rather than reporting a clean
sweep with no control:

```console
$ uv run poison-garden run --scanner "./broken-scanner {target}" --out result.json
refusing to emit a result: refusing to emit a result with no scorable benign twins. Recall
without a false-positive rate is a flattering half-measurement: any scanner reaches 100%
recall by flagging everything, and the twins are the only thing that makes that visible (R9).

$ echo $?
3
```

## Install

Not yet on PyPI. Install from source:

```bash
git clone https://github.com/Realgagenichols/poison-garden
cd poison-garden
uv sync
uv run poison-garden --help
```

## Quickstart

You bring the scanner. We never run it for you.

**First, check your scanner is wired up.** This takes seconds and tells you the one thing
the result document cannot: whether your exit codes are actually reaching us.

```bash
uv run poison-garden selftest --scanner "your-scanner {target}"
```

**The interface `{target}` assumes.** It expands to the command that *launches* one
specimen — an interpreter and a path, substituted as argv, never through a shell — and your
scanner signals findings by **exit code**.

If your scanner wants that command as a **single quoted string** rather than as separate
argv elements, embed the placeholder and it is joined for you — verified working against
Cisco's scanner:

```bash
--scanner 'cisco-ai-mcp-scanner --analyzers yara stdio --stdio-command={target}'
--scanner 'velox-mcp-audit --stdio={target}'
```

If your scanner instead takes an MCP **config file** (Snyk's `agent-scan`, formerly
`mcp-scan`, among them), `{target}` will hand it an interpreter path to parse as JSON and it
will not work. That gap is real and open — see [Limitations](#limitations).

**If your scanner has an exit code meaning it *failed*, declare it** with `--error-on`.
Otherwise a failed scan scores as a clean one: at least one MCP scanner exits 0 while
printing that its result should not be trusted, which reads as "examined it, found nothing."

```bash
uv run poison-garden run --scanner "…" --error-on 2 --out result.json
```

```bash
# Run YOUR scanner over the corpus.
uv run poison-garden run \
  --scanner "your-scanner {target}" \
  --scanner-name "your-scanner 1.4.0" \
  --out results/your-scanner-1.4.0.json

# A scanner whose exit codes differ
uv run poison-garden run --scanner "…" --flag-on 2 --out result.json

# Opt into per-class attribution if your scanner emits SARIF (optional; without it,
# scoring falls back to exit codes and nothing is lost)
uv run poison-garden run --scanner "…" --sarif --out result.json

# Check a submission the way CI will, without modifying it
uv run poison-garden validate-result results/
```

The runner pre-flights each specimen to confirm it serves a catalog, then invokes your command
once per specimen and derives a verdict from the **exit code** — no integration work to get a
first number. You get per-class recall **and** the false-positive rate over the benign twins.
Never one without the other, and never a single composite score.

### Options

| flag | applies to | meaning |
|---|---|---|
| `--scanner TEMPLATE` | `run` | your command, containing `{target}` (required) |
| `--scanner-name NAME` | `run` | identity recorded in the document. Your command line is **never** recorded — a template can carry a token |
| `--out PATH` | `run` | where to write the result document |
| `--flag-on {nonzero,N}` | `run` | exit code that counts as flagged (default `nonzero`) |
| `--sarif` | `run` | parse stdout as SARIF for per-class attribution (optional) |
| `--timeout SECONDS` | `run` | scanner budget per specimen (default 120) |
| `--corpus PATH` | `validate`, `hash`, `run` | corpus root (default `specimens`) |
| `--check` | `leaderboard` | verify the committed page is current instead of writing it |
| `--debug` | *before* the subcommand | include exception detail on an internal failure |

### Exit codes

| code | meaning |
|---|---|
| `0` | the operation succeeded |
| `1` | the corpus (or a submission) is invalid — a real, reportable finding |
| `2` | poison-garden itself failed: bad usage or an unexpected exception |
| `3` | poison-garden **refused** to emit a result, and was right to |

`3` exists because a refusal is the tool working correctly. Collapsing it into `2` would leave
CI unable to tell *"your scanner errored every specimen, so there is no measurement here"*
from *"poison-garden fell over"*.

### Gating a build on it

```yaml
# .github/workflows/poison-garden.yml
name: poison-garden
on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: astral-sh/setup-uv@v8

      - name: Check out the corpus
        run: git clone --depth 1 https://github.com/Realgagenichols/poison-garden /tmp/pg

      - name: Run our scanner against it
        working-directory: /tmp/pg
        run: |
          uv sync
          uv run poison-garden run \
            --scanner "$GITHUB_WORKSPACE/our-scanner {target}" \
            --scanner-name "our-scanner ${{ github.sha }}" \
            --out /tmp/result.json
          # exit 3 means poison-garden refused — treat that as a build failure, not a pass
```

## What's in the corpus

| Family | What the specimen does |
|---|---|
| **Declaration classes** | Instruction injection, hidden/invisible content, sensitive-parameter capture, capability/scope mismatch, impersonation, metadata hygiene |
| **`credential-access`** | Impeccable catalog; reads a credential path the moment you connect |
| **`exfil-enumeration`** | Embeds a credential into a tool description — the theft rides the channel the scanner is already reading |
| **`namesake-rugpull`** | Two tools under one name; which one resolves changes as the session goes on |
| **`scanner-aware`** | Serves clean definitions to an inspector, poisoned ones to a real agent |
| **`egress`** | Opens an outbound socket nothing in its catalog implies — loopback only, so the signal is the connection rather than the destination |

Every class ships with **benign twins** — specimens that superficially resemble it but are
legitimate. A scanner that flags everything scores zero on the twins, which is the point. The
twins are tested to trip a naive rule, because a control nothing could ever flag proves
nothing.

Every malicious specimen also declares a **difficulty tier** — `overt`, `moderate`, or
`subtle` — chosen by its author and never inferred from whether a scanner caught it. Results
report caught/total per tier within each class, because a single percentage cannot tell apart
the two situations a maintainer most needs to distinguish: a scanner that catches the obvious
phrasing and nothing else, and one that misses both. `6/6 overt, 0/2 subtle` is a bug report.
`75%` is a grade.

The tier rubric is in [`CONTRIBUTING.md`](CONTRIBUTING.md), and it has been **tested rather
than assumed**: eight blind raters over 60 specimens reach Krippendorff's α ≈ 0.83 on
malicious specimens. Agreement on benign twins is weaker and not yet demonstrated reliable,
so no published figure carries a twin's tier — see
[`docs/tier-reliability.md`](docs/tier-reliability.md), which also records what that study
failed to establish.

## Publishing a result

Results are submitted by pull request into [`results/`](results/). CI validates the schema, the
corpus hash, and that your stated figures agree with your own per-specimen verdicts.

**Maintainers never recompute, adjust, or editorialize a submitted figure.** There is
deliberately no code path that repairs a document — validation either accepts it as you
published it, or rejects it with a reason. The [comparison page](COMPARISON.md) is generated
from what is committed; there is no hand-maintained table, and **no ranking**.

**This project does not score other people's tools.** It is a registrar, not a referee.

## Honesty commitments

These are enforced in CI, not promised in prose.

- **Every class has a benign twin.** A corpus release fails validation otherwise.
- **The corpus contains specimens that `frisk` fails.** This project's author also maintains
  [frisk](https://github.com/Realgagenichols/frisk), an MCP scanner. Every release ships at
  least three specimens frisk does not flag, registered in [`KNOWN-MISSES.md`](KNOWN-MISSES.md)
  and counted by CI at release. If frisk ever scored 100%, that would be a defect in this
  corpus, not a feature of that scanner.
- **Specimens are not derived from frisk's detector fixtures.** A corpus written from the same
  source as a scanner's rules cannot measure that scanner. Verified by
  [`scripts/audit_n1_independence.py`](scripts/audit_n1_independence.py), which compares served
  catalogs — not source files — and fails on any shared six-word phrase.
- **No composite score.** Per-class figures and a false-positive rate. A headline number
  invites exactly the rank-ordering this project refuses, and hides the one class where a tool
  did badly. The result schema is asserted key-by-key, because a composite score can be named
  `accuracy` and no wordlist would catch it.
- **No precision the corpus cannot support.** Every per-class recall figure ships with a 95%
  Wilson confidence interval, and a class holding fewer than five scorable specimens is
  rendered as insufficient rather than as a number. This one is here because the corpus
  failed it: the first run against a real scanner reported classes of one specimen, and `0/1`
  printed as "0%" reads as *this tool has a gap here* when the data supports anything up to
  79%. That is the same flattering precision the no-composite-score rule exists to refuse,
  arriving through a door that rule did not cover.

The current self-report — the author running this corpus against his own scanner, which is
what every vendor is invited to do — is in [`COMPARISON.md`](COMPARISON.md). Its most
interesting row is `scanner-aware`, which frisk misses.

## Safety

**The harness is not a sandbox.** It is important to be exact about this, because the
repository contains deliberately malicious code and you are entitled to know what does and does
not protect you.

**The loopback guarantee covers the specimens, not your scanner.** An earlier version of
this banner said "no packet can leave your machine". Scoped to specimens that was true and
it is enforced by tests — but it is not the promise a reader takes from it. You run *your*
scanner over this corpus, and several MCP scanners are cloud-backed: they upload what they
inspect. Running the documented quickstart with one of those sends 97 deliberately
malicious server definitions to a third party. poison-garden has no way to detect that and
does not try to stop it; it is your scanner and your call. It should simply not be
discovered after the fact from a sentence of ours.

A related consequence for the figures: at least one scanner warns it may return results
from vendor-side recognition of a server rather than from inspecting the one in front of
it. A verdict reached that way is not a measurement of this corpus, and nothing in a result
document can distinguish the two.

What the harness *does*: it pre-flights each specimen with `$HOME` pointed at a throwaway
directory seeded with fake credentials, hands it a loopback address to "exfiltrate" to, and
strips the environment down to a short allowlist.

What it *does not* do: contain the process. `$HOME` substitution is a naming convention, not a
jail. A program that consults the passwd database (`pwd.getpwuid`), expands `~username`, or
simply opens an absolute path reaches your real home directory regardless — there is no
seatbelt, no namespace, and no filesystem restriction. We measured that rather than assuming
it.

**And during a scan, your scanner spawns the specimen — so poison-garden does not control the
specimen's environment. You do.** The throwaway home covers only our own pre-flight handshake.

So the guarantee is about **these specimens**, not about arbitrary ones:

- Every specimen in this corpus discloses nothing it did not itself ship. A credential-access
  specimen opens a path and discards the contents unread into any output; anything a specimen
  embeds is a decoy shipped inside its own directory.
- Egress targets a loopback sink supplied by the runner, and there is deliberately no fallback
  address — when no sink is configured, a specimen opens no socket at all.
- That is enforced by tests which scan every shipped file for each known way around the
  substitution, and which are themselves checked against a list of measured bypasses so the
  guard cannot quietly stop catching anything.

**Therefore: do not run third-party or modified specimens under this harness.** If you add a
specimen, the guard checks it — but the guard is a source scan, and a source scan is a weaker
thing than containment.

## Limitations

Stated plainly, because a benchmark that oversells itself is worse than none.

- **Two things limit "any scanner, no adapter", and the smaller one is the target shape.**
  Of six MCP scanners surveyed, three take a launch command, three take a config file, and
  three take both — so neither shape is the general case. `{target}` reaches the
  launch-command ones, including those wanting a single quoted string (see Quickstart).
  Config-only scanners need a wrapper you write; a `{config}` mode is deferred until a
  vendor asks, so it can be built against a real invocation rather than a guess.
  **The binding constraint is exit codes, not shape**: at least one scanner has no
  exit-code-on-finding flag at all, so R6 cannot reach it whatever the target looks like.
  R5's claim is currently too strong and this is the honest extent of it.
- **A cloud-backed scanner's verdict may not be about your specimen.** At least one scanner
  warns that it can return results from vendor-side recognition of a server rather than
  from inspecting the one in front of it. poison-garden cannot detect this, so a result
  document cannot distinguish "examined the specimen" from "recognised something like it".
  If your scanner works that way, say so in your submission.
- **Real containment is not implemented.** See [Safety](#safety). A seatbelt profile or
  container is tracked work, not a shipped feature.
- **The egress class demonstrates an undeclared socket, not a remote destination.** A corpus
  of deliberately malicious code published to strangers has exactly one safe destination, so
  every specimen reaches loopback and nothing else. The property under test is *undeclared
  network capability, exercised unprompted* — a timezone converter that opens a socket before
  serving a request — which is observable whatever it dials. If your scanner deliberately
  ignores loopback, it will score low here; that is a real difference in what we each think
  the finding is, and worth saying so in your submission rather than treating as a bug.
- **Our pre-flight is itself an enumeration.** A specimen whose behavior depends on how many
  times it has run must declare that in its manifest; the shipped rug-pull counts in-process
  precisely so our pre-flight consumes none of your scanner's enumerations.
- **Exit-code scoring is coarse.** Without SARIF, flagging a specimen credits every class it
  carries. That is the honest reading of a coarser instrument, not a bug — but it is why
  `--sarif` exists.
- **Some classes have one attacker.** `impersonation` and `scope-mismatch` currently ship a
  single malicious specimen each, and a population of one cannot distinguish "this scanner has
  a gap" from "this one case is hard". Those figures are weak evidence and are labelled as
  such.

## Development

```bash
# The venv must live OUTSIDE the repo if the repo is under ~/Desktop or another
# synced/watched tree: something there sets UF_HIDDEN on .venv/**/*.pth, CPython
# silently skips hidden .pth files, and the editable install stops reaching sys.path.
# pytest keeps passing; the installed console script breaks.
export UV_PROJECT_ENVIRONMENT="$HOME/.venvs/poison-garden"

uv sync
uv run pytest -q                    # 1512 tests
uv run --frozen ruff check .        # unpiped: read the exit code, not the last line

# The N1 independence audit needs a frisk checkout alongside this repo
uv run python scripts/audit_n1_independence.py
```

### Adding a specimen

One directory under `specimens/`, containing `server.py` and `manifest.toml`. The manifest
declares `declaration` and `behavior` classes **independently** — a specimen whose declaration
is empty and whose behavior is hostile is exactly the case a static corpus cannot express.

Every attack class needs a benign twin, and `uv run poison-garden validate` fails without one.
Write the twin to be genuinely tempting: it is the only thing standing between this corpus and
a scanner that scores well by flagging everything.

## License

MIT.
