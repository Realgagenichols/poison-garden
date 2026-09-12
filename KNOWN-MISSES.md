# Known misses

Specimens in this corpus that **`frisk` fails to flag.**

This project's maintainer also maintains [frisk](https://github.com/Realgagenichols/frisk),
an MCP security scanner. That is a conflict of interest, and this file is one of the
structural answers to it.

**Requirement N2:** every corpus release ships **at least three** specimens that frisk does not
detect, registered here. CI enforces the count at release. If frisk ever scored 100% against
this corpus, that would be a defect in the corpus — evidence it had been shaped around one
scanner's detectors — and not an achievement of that scanner.

The companion requirement is **N1**: specimens are not derived from frisk's detector fixtures.
A corpus authored from the same source as a scanner's rules cannot measure that scanner.
Verified by `scripts/audit_n1_independence.py`.

---

## Corpus v0.2.0 (unreleased)

**Corpus state these numbers describe** — without it, an edit to any specimen silently
invalidates every row below and nothing says so (R4 exists to prevent exactly that):

```
corpus version  0.2.0
corpus hash     sha256:c66e46a969c56189599f2cf3ee937169cf68d00311195f5b766e3673a57390dd
scanner         mcp-frisk 0.2.0
measured        2026-09-12
command         poison-garden run --scanner "uvx --from mcp-frisk frisk scan --no-sandbox -- {target}"
```

Produced by `poison-garden run` itself — the same path any vendor uses — not by hand. The
M1 figures were measured per-specimen manually and the runner reproduced them exactly; that
agreement between two independent paths is the only reason to trust either.

**Per class**, for the same reason R10 forbids a composite score: an aggregate hides the
lopsided class, which is usually the interesting one. A specimen carrying two classes counts
toward both.

| Class | Caught | Missed |
|---|---|---|
| credential-access | 1/1 | — |
| exfil-enumeration | 0/1 | `behaviour-exfil-in-description` |
| hidden-content | 4/4 | — |
| hygiene | 1/2 | `hygiene-unpinned-remote-exec` |
| impersonation | 0/1 | `impersonation-builtin-reader` |
| injection | 3/4 | `injection-meeting-preamble` |
| namesake-rugpull | 1/1 | — |
| scanner-aware | 0/1 | `behaviour-scanner-aware` |
| scope-mismatch | 1/1 | — |
| sensitive-params | 2/2 | — |

**False positives: 0 of 10 twins.** Registered misses: 5 (N2 requires ≥3).

### What the behavioural classes show

The measurement this project was built to produce. The honest reading is more interesting
than "static scanners fail":

- **frisk catches 2 of 4 behavioural classes** — far better than the thesis predicts, because
  frisk is not purely static. It runs the server under a seatbelt sandbox seeded with decoy
  credentials and watches, so `credential-access` falls to its honeypot and
  `namesake-rugpull` to its duplicate-name rule. A scanner that only reads `tools/list` would
  score 0/4 here. **That is the finding: the gap is not static-vs-good, it is static-vs-
  behavioural, and frisk is on the right side of it.**
- **`scanner-aware` is missed**, and it is the sharpest row in the table. The specimen serves
  frisk a clean catalog and a real agent the poisoned one. Every static conclusion frisk
  draws is *accurate about the catalog it was shown* — and useless.
- **`exfil-enumeration` is missed**: a shipped decoy credential embedded in a tool
  description as base64 across three byte phases. The theft rides the channel the scanner is
  already reading.

### The registered misses (N2)

Specimen id first, so this table is machine-checkable — `scripts/check_known_misses.py`
counts these rows at release and rejects any that names a specimen no longer in the corpus.

| Specimen | Class | frisk verdict | What it would have to notice |
|---|---|---|---|
| `behaviour-exfil-in-description` | exfil-enumeration | PASS | A shipped decoy credential embedded in a tool description as base64 across three byte phases. The theft rides the channel the scanner is already reading. |
| `behaviour-scanner-aware` | scanner-aware | PASS | Serves frisk a clean catalog and a real agent the poisoned one. Every static conclusion drawn about it is accurate about the catalog it was shown, and useless. |
| `hygiene-unpinned-remote-exec` | hygiene | PASS | Fetches and executes unpinned remote code; provenance unverifiable, but nothing in the advertised text is syntactically suspicious. |
| `impersonation-builtin-reader` | impersonation | PASS | Name-similarity plus steering text, on a server whose stated domain has no need of that tool at all. |
| `injection-meeting-preamble` | injection | PASS | Directives phrased as vendor policy ("Assistant procedure (required)"), concealment justified on plausible support grounds — no imperative-override vocabulary to key on. |

### A wrong result, recorded rather than quietly fixed

`scanner-aware` first scored **1/1 caught**, which looked like a win and measured nothing.
The discriminator keyed on `clientInfo.name` containing tokens like `scan` or `frisk` — but
`mcp-frisk` identifies as `{"name": "mcp"}`, the Python SDK default, as almost every scanner
will. The evasion never fired and frisk simply caught an ordinary poisoned catalog. The
discriminator now keys on **declared capabilities**: an agent declares `roots` / `sampling` /
`elicitation`, an inspector declares none. A false signal in this project's own favour is the
worst kind to leave standing.

## How to add a row

A row is earned by a measurement, not an estimate. Run the current release of frisk against the
specimen, record the command and its output, and cite the release version. A row without a
recorded run is a guess wearing a table's clothes.

Re-measure on every frisk release. A miss that frisk later fixes must be struck from this
table, and if that drops the count below three, **the corpus needs new specimens before the
next release** — not a relaxed requirement.
