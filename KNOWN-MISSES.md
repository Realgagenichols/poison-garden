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

## Corpus v0.3.0 (unreleased)

**Corpus state these numbers describe** — without it, an edit to any specimen silently
invalidates every row below and nothing says so (R4 exists to prevent exactly that):

```
corpus version  0.3.0
corpus hash     sha256:da68fbf55e963b2a0ded8ed727d83b994db1f995843190e8eb0fe246d5406eb6
specimens       88
scanner         mcp-frisk 0.2.0
measured        2026-09-14
command         poison-garden run --scanner "uvx --from mcp-frisk frisk scan --no-sandbox -- {target}"
```

Produced by `poison-garden run` itself — the same path any vendor uses — not by hand.

**Per class.** An aggregate would hide the lopsided class, which is usually the interesting
one (R10). A specimen carrying two classes counts toward both. Intervals are Wilson 95%
(R18); tier counts are R20, reported as counts because a tier holds one or two specimens and
a percentage over two would be the same overclaim R18 exists to stop.

| Class | Caught | 95% CI | By tier | Missed |
|---|---|---|---|---|
| credential-access | 4/6 | 30–90% | moderate 2/3 · overt 1/1 · subtle 1/2 | 2 |
| exfil-enumeration | 0/6 | 0–39% | moderate 0/4 · overt 0/1 · subtle 0/1 | 6 |
| hidden-content | 6/6 | 61–100% | moderate 3/3 · overt 2/2 · subtle 1/1 | — |
| hygiene | 1/6 | 3–56% | moderate 1/3 · overt 0/2 · subtle 0/1 | 5 |
| impersonation | 1/6 | 3–56% | moderate 0/3 · overt 0/2 · subtle 1/1 | 5 |
| injection | 4/7 | 25–84% | moderate 1/2 · overt 2/3 · subtle 1/2 | 3 |
| namesake-rugpull | 1/6 | 3–56% | moderate 1/4 · overt 0/1 · subtle 0/1 | 5 |
| scanner-aware | 0/6 | 0–39% | moderate 0/3 · overt 0/1 · subtle 0/2 | 6 |
| scope-mismatch | 3/6 | 19–81% | moderate 2/4 · overt 0/1 · subtle 1/1 | 3 |
| sensitive-params | 3/6 | 19–81% | moderate 1/3 · overt 2/2 · subtle 0/1 | 3 |

**False positives: 4 of 30 twins.** Registered misses below: 12 (N2 requires ≥3).
Full per-specimen verdicts in [`results/mcp-frisk-0.2.0.json`](results/mcp-frisk-0.2.0.json);
every figure above is recomputable from it.

### What the v0.3.0 expansion changed

v0.2.2 measured six of ten classes with a **single** malicious specimen each. Those figures
were not merely small — they read as precise, and were not:

| Class | v0.2.2 | v0.3.0 | |
|---|---|---|---|
| namesake-rugpull | 1/1 — "100%" | **1/6** | the one specimen was the one frisk catches |
| scope-mismatch | 1/1 — "100%" | **3/6** | |
| sensitive-params | 2/2 — "100%" | **3/6** | |
| credential-access | 1/1 — "100%" | **4/6** | |
| hygiene | 1/2 — "50%" | **1/6** | |
| scanner-aware | 0/1 | **0/6** | |
| **false positives** | **0/10** | **4/30** | the old twin set had no discriminating power at all |

Four classes that read as clean sweeps were sweeps of one specimen. The 95% interval on
`1/1` runs from 21% to 100%, so publishing "100%" implied precision the corpus could not
support — the same flattering half-truth R10 refuses for composite scores, arriving through
a door R10 did not cover. R18 and R19 exist because of this table.

The false-positive row is the sharper finding. `0/10` was not a good precision score; it was
a control that never fired. All four of the twins frisk now flags were independently audited
and confirmed benign — decoded byte by byte, schemas walked for every composition keyword at
every depth — so they are genuine false positives rather than mislabelled specimens.

### What the behavioural classes show

- **`exfil-enumeration` is missed entirely, 0/6.** The enumeration response *is* the
  exfiltration channel, so the scanner is reading the wire the theft rides on. Placement and
  encoding do the rest: a schema `default`, a resource URI query string, semver build
  metadata, schema key names, and a payload cut into twelve-character fragments across
  prompt arguments.
- **`scanner-aware` is missed entirely, 0/6**, and remains the sharpest row here. Six
  specimens serve an inspector a clean catalog and an agent a poisoned one, keyed on
  declared capabilities, `clientInfo` shape, default client identity, handshake completion,
  sweep order, and re-enumeration. Every static conclusion frisk draws about them is
  *accurate about the catalog it was shown* — and useless.
- **`namesake-rugpull` fell from 1/1 to 1/6.** frisk's duplicate-name rule catches the
  immediate swap. Four specimens that mutate a description, a parameter's meaning, a
  `required` list or an `enum` member — at enumerations 2, 3 and 7 — pass it.
- **frisk is not a purely static scanner and the results show it.** It runs the server under
  a seatbelt sandbox seeded with decoy credentials and watches, which is why
  `credential-access` is 4/6 rather than 0/6. The gap this corpus measures is not
  static-versus-good; it is static-versus-behavioural, and frisk is on the right side of it.

### Two signals worth reading carefully

**Overt misses are coverage gaps, not subtlety.** Three classes caught **zero** of their
`overt` specimens while catching something `subtle`: hygiene 0/2 overt, impersonation 0/2
overt, scope-mismatch 0/1 overt. A miss on an overt specimen means no rule targets that
class at all, which suggests the scattered subtle catches are incidental to some other rule
rather than evidence of depth. A single per-class percentage cannot express that; this is
what the tier field was added for.

**The twin tiers are corroborated by the measurement, along a path that did not use it.**
Tiers were assigned by a reviewer judging only how tempting each false positive looked, who
never ran a scanner. Every false positive frisk produced landed in the top tier:

| Twin tier | Twins | frisk false positives |
|---|---|---|
| overt | 16 | 4 |
| moderate | 12 | 0 |
| subtle | 2 | 0 |

Two independent routes to the same ordering. This is an observation, not a requirement —
tiers are declared by authors and must never be tuned to what any scanner does, or the
corpus would be shaped around one tool, which is exactly what N1 and N2 exist to prevent.

### The registered misses (N2)

Specimen id first, so this table is machine-checkable. `scripts/check_known_misses.py`
counts these rows at release, and `test_registered_misses_were_actually_missed` asserts every
row names a specimen the committed result document records as missed — a row cannot drift
into naming something frisk now catches.

A curated selection, not the complete list: frisk misses 38 specimens in this
corpus, all enumerated per class in the result document. These are the ones that say
something a reader can act on.

| Specimen | Class | Tier | frisk verdict | What it would have to notice |
|---|---|---|---|---|
| `behaviour-exfil-prompt-argument-mosaic` | exfil-enumeration | subtle | clean | Reassemble a payload from twelve-character fragments scattered through three prompt templates' argument descriptions. No field holds a recognisable substring, so per-field entropy scoring cannot reach it in principle. |
| `behaviour-exfil-schema-key-names` | exfil-enumeration | moderate | clean | Read schema **key names** as content. Almost everything inspects values, and the value side of this catalog is unremarkable. |
| `behaviour-scanner-aware-sweep-order` | scanner-aware | moderate | clean | Notice the catalog depends on whether you listed resources before tools. The polarity is hostile to crawlers: the more thorough the sweep, the more reliably it lands on the clean catalog. |
| `behaviour-scanner-aware-clientinfo-shape` | scanner-aware | moderate | clean | Re-handshake as a client carrying display metadata in `clientInfo`. Tool name and tool-level description are byte-identical in both branches; the injection lives in a property only the agent's schema contains. |
| `behaviour-scanner-aware-default-client-identity` | scanner-aware | overt | clean | Send a `clientInfo.name` that is not a library default. A scanner keeping the SDK's default name is served the clean catalog and concludes correctly about it. |
| `behaviour-rugpull-enum-widening` | namesake-rugpull | subtle | clean | Enumerate seven times and diff an `enum` member list. Nothing else changes by a byte, including the parameter's own description. |
| `behaviour-credential-deferred-assembly` | credential-access | subtle | clean | Observe the second enumeration of a session, against paths assembled from character ordinals at call time so no path literal appears in the source. |
| `hygiene-digest-covers-wrapper` | hygiene | subtle | clean | Ask whether the thing verified is the thing that runs. Version, URL and sha256 are exact and the check is mandatory — it covers the bootstrapper, which then resolves the compiler from a mutable channel with no digest. |
| `impersonation-official-vendor-shim` | impersonation | overt | clean | Treat a claim of official vendor status, plus a warning that rival connectors silently discard writes, as a tool-selection attack rather than marketing copy. |
| `sensitive-params-pipeline-runner-snapshot` | sensitive-params | subtle | clean | Resolve `$ref` indirection. The top-level schema is four ordinary fields; the demand for unmasked CI variables and workspace file contents sits behind the pointer. |
| `injection-postmortem-house-style` | injection | subtle | clean | Read a `prompts/list` argument *default* as instruction, and notice it pre-decides a root cause while telling the model to drop findings implicating an automated agent. |
| `scope-mismatch-label-renderer` | scope-mismatch | moderate | clean | Recognise that a `template` field documented as resolving against an unrestricted server-side scope is arbitrary evaluation. No capability noun appears anywhere. |

---

**If frisk fixes one of these, strike the row and add new specimens.** Do not relax the
requirement. If the register ever drops below three, the corpus needs new specimens before
the next release.
