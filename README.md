# poison-garden

**A benchmark corpus of deliberately malicious MCP servers. Run your own scanner against it
and find out what you catch.**

> ⚠️ This repository contains intentionally malicious MCP servers, for defensive security
> testing. They are demonstrative, not weaponized: every specimen is inert outside the
> harness, reads only decoy credentials from a throwaway home directory, and sends nothing
> anywhere but a loopback sink. See [Safety](#safety).

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
the benign twins. Never one without the other, and never a single composite score.

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

- Specimens read **decoy** credentials from a throwaway home directory created by the runner.
  No specimen reads any real path under your home directory.
- Egress attempts target a **loopback sink** supplied by the runner. No specimen contains a
  public hostname or IP address.
- Specimens demonstrate the *detectable signal* of an attack class. They are not working
  exploits and are useless lifted out of the corpus.
- The harness is the only supported way to run them.

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
