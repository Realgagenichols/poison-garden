# poison-garden

**A benchmark corpus of deliberately malicious MCP servers. Run your own scanner against it
and find out what you catch.**

> ⚠️ This repository contains intentionally malicious MCP servers, for defensive security
> testing. **The specimens shipped here** are demonstrative rather than weaponized — they
> read only decoy credentials and attempt no real network egress, and that is enforced by
> tests. **The harness is not a sandbox.** Read [Safety](#safety) before running anything.

---

## The problem

There are now more than a dozen MCP security scanners. Nearly all of them measure the same
thing: **what a server declares.** They read `tools/list`, pattern-match the text, and report.

But a declaration is written by the attacker, and an honest-looking one is cheap. A server can
present an impeccable catalog and still read `~/.ssh/id_rsa` the moment you connect, serve
clean definitions to anything that smells like a scanner, or stay benign until after you have
approved it.

Existing corpora are static — a case is a JSON document — so they cannot express that gap.
**In poison-garden a specimen is a running program**, which means its declaration and its
behavior can be authored to disagree. That is the whole point.

## How it works

You bring the scanner. We never run it for you.

```bash
uv tool install poison-garden

poison-garden run --scanner "your-scanner {target}" --out result.json
```

The runner boots each specimen in a throwaway `$HOME` seeded with decoy credentials, invokes
your command once per specimen, and derives a verdict from the exit code — **no integration
work required to get a first number.** Scanners that emit SARIF can opt into per-class
attribution instead.

You get one result document containing per-class recall *and* the false-positive rate over
the benign twins. Never one without the other, and never a single composite score:

```
  hidden-content     4/4  100%
  hygiene            1/2   50%
  impersonation      0/1    0%
  injection          3/4   75%
  scope-mismatch     1/1  100%
  sensitive-params   2/2  100%
  false positives    0/6    0%
```

A specimen the scanner could not be asked about — one that fails to start, or whose scan
times out — is recorded as `error` and leaves **both** the numerator and the denominator. It
is never counted as a miss, because a broken specimen is a defect in this corpus, not a
finding about your tool.

The document records the corpus version and hash it describes, and the exact exit-code
mapping applied, so every figure in it is recomputable from its own per-specimen verdicts.
It records your scanner's *name*, never your command line — a template can contain a token.

**One limitation worth stating plainly:** during a scan, your scanner spawns the specimen,
so poison-garden does not control the specimen's environment — you do. Our throwaway home
covers only our own pre-flight handshake. See [Safety](#safety).

## Publishing a result

Results are submitted by pull request into [`results/`](results/). CI validates the schema,
the corpus hash, and that your stated figures agree with your own per-specimen verdicts.

Maintainers never recompute, adjust, or editorialize a submitted figure. The comparison page
is generated mechanically from what is committed — there is no hand-maintained table, and no
ranking.

**This project does not score other people's tools.** It is a registrar, not a referee.

## What's in the corpus

| Family | What the specimen does |
|---|---|
| Declaration classes | Instruction injection, hidden/invisible content, sensitive-parameter capture, capability/scope mismatch, impersonation, metadata hygiene |
| Honest declaration, hostile behavior | Clean catalog; reads decoy credentials or attempts egress during enumeration |
| Exfiltration over the enumeration channel | Reads a decoy credential and embeds it into a tool description — the theft rides the channel the scanner is reading |
| Namesake rug-pull | Two tools under one name where the one that resolves changes between enumerations |
| Scanner-aware | Serves clean definitions when the handshake looks like a scanner, poisoned ones otherwise |

Every class ships with a **benign twin** — a specimen that superficially resembles it but is
legitimate. A scanner that flags everything scores zero here, which is the point.

## Honesty commitments

These are enforced in CI, not promised in prose:

- **Every class has a benign twin.** A corpus release fails validation otherwise.
- **The corpus contains specimens that `frisk` fails.** This project's author also maintains
  [frisk](https://github.com/Realgagenichols/frisk), an MCP scanner. Every release ships at
  least three specimens frisk does not flag, listed in `KNOWN-MISSES.md`. If frisk ever
  scored 100%, that would be a defect in this corpus, not a feature of that scanner.
- **Specimens are not derived from frisk's detector fixtures.** A corpus written from the same
  source as a scanner's rules cannot measure that scanner.
- **No composite score.** Per-class figures and a false-positive rate. A headline number
  invites exactly the rank-ordering this project refuses to do.

## Safety

**The harness is not a sandbox.** It is important to be exact about this, because the
repository contains deliberately malicious code and you are entitled to know what does and
does not protect you.

What the harness *does*: it runs each specimen with `$HOME` pointed at a throwaway directory
seeded with fake credentials, hands it a loopback address to "exfiltrate" to, and strips the
environment down to a short allowlist.

What it *does not* do: contain the process. `$HOME` substitution is a naming convention, not
a jail. A program that consults the passwd database (`pwd.getpwuid`), expands `~username`, or
simply opens an absolute path reaches your real home directory regardless — there is no
seatbelt, no namespace, and no filesystem restriction. We measured this rather than assuming
it; see `poison_garden/runner/sandbox.py`.

So the guarantee is about **these specimens**, not about arbitrary ones:

- Every specimen in this corpus reads only decoys and attempts egress only to loopback.
  That is enforced by tests (`tests/test_sandbox.py`) which grep every shipped specimen for
  each known way around the substitution, and which are themselves checked against a list of
  measured bypasses so the guard cannot quietly stop catching anything.
- Specimens demonstrate the *detectable signal* of an attack class. They are not working
  exploits and are useless lifted out of the corpus.

**Therefore: do not run third-party or modified specimens under this harness.** If you add a
specimen, the guard checks it — but the guard is a source scan, and a source scan is a
weaker thing than containment. Real isolation (a seatbelt profile or container) is a tracked
requirement, not a shipped feature.

## Development

```bash
# The venv must live OUTSIDE the repo if the repo is under ~/Desktop or another
# synced/watched tree: something there sets UF_HIDDEN on .venv/**/*.pth, CPython
# silently skips hidden .pth files, and the editable install stops reaching sys.path.
# pytest keeps passing; the installed console script breaks.
export UV_PROJECT_ENVIRONMENT="$HOME/.venvs/poison-garden"

uv sync
uv run pytest -q
uv run ruff check .
```

Diagnose that failure mode with:

```bash
ls -lO "$UV_PROJECT_ENVIRONMENT"/lib/python3.12/site-packages/*.pth   # `hidden` in flags = broken
```

## License

MIT.
