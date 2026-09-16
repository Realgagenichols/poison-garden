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

## Corpus v0.4.0 (unreleased)

```
corpus version  0.4.0
corpus hash     sha256:e0f16a9fd0835478fe2ec5038b44eb9987f0e0b883ec35fb7229a4c02097f261
specimens       97
scanner         mcp-frisk 0.2.0
measured        2026-09-14
command         poison-garden run --scanner "uvx --from mcp-frisk frisk scan --no-sandbox -- {target}"
```

Produced by `poison-garden run` itself — the same path any vendor uses — not by hand. Without
the state block above, an edit to any specimen silently invalidates every row below and
nothing says so (R4 exists to prevent exactly that).

**Per class.** An aggregate would hide the lopsided class, which is usually the interesting
one (R10). A specimen carrying two classes counts toward both. Intervals are Wilson 95%
(R18); tier counts are R20, reported as counts because a tier holds one or two specimens and
a percentage over two would be the same overclaim R18 exists to stop.

| Class | Caught | 95% CI | By tier | Missed |
|---|---|---|---|---|
| credential-access | 4/6 | 30–90% | moderate 2/3 · overt 1/1 · subtle 1/2 | 2 |
| egress | 0/6 | 0–39% | moderate 0/3 · overt 0/1 · subtle 0/2 | 6 |
| exfil-enumeration | 0/6 | 0–39% | moderate 0/4 · overt 0/1 · subtle 0/1 | 6 |
| hidden-content | 6/6 | 61–100% | moderate 3/3 · overt 2/2 · subtle 1/1 | — |
| hygiene | 1/6 | 3–56% | moderate 1/3 · overt 0/2 · subtle 0/1 | 5 |
| impersonation | 1/6 | 3–56% | moderate 0/3 · overt 0/2 · subtle 1/1 | 5 |
| injection | 4/7 | 25–84% | moderate 1/2 · overt 2/3 · subtle 1/2 | 3 |
| namesake-rugpull | 1/6 | 3–56% | moderate 1/4 · overt 0/1 · subtle 0/1 | 5 |
| scanner-aware | 0/6 | 0–39% | moderate 0/3 · overt 0/1 · subtle 0/2 | 6 |
| scope-mismatch | 3/6 | 19–81% | moderate 2/4 · overt 0/1 · subtle 1/1 | 3 |
| sensitive-params | 3/6 | 19–81% | moderate 1/3 · overt 2/2 · subtle 0/1 | 3 |

**False positives: 4 of 33 twins.** Registered misses below: 15 (N2 requires ≥3).
Full per-specimen verdicts in [`results/mcp-frisk-0.2.0.json`](results/mcp-frisk-0.2.0.json);
every figure above is recomputable from it.

### v0.4.0 — the taxonomy is complete

`egress` was in the class enum from the beginning and had **no requirement behind it**, while
R12–R14 were written for the other behavioural classes. It shipped empty for three releases.
That was not an authoring backlog: `attempt_egress` opened no socket at all when
`PG_EGRESS_SINK` was absent, and that variable is absent exactly when a third-party scanner
spawns the specimen. Any specimen in the class would have been a guaranteed miss for every
scanner — unmeasurable by construction.

R21 now defines it and the helper falls back to a loopback connect that transmits nothing.
**The measured property is the socket, not the destination**: a corpus of deliberately
malicious code published to strangers has exactly one safe destination, so the class tests
*undeclared network capability, exercised unprompted*. A scanner that deliberately ignores
loopback will score low here and is not thereby wrong — that is a disagreement about what the
finding is, and it belongs in a submission's notes rather than being scored past.

### v0.3.0 — what depth changed

v0.2.2 measured six of ten classes with a **single** malicious specimen each. Those figures
were not merely small — they read as precise, and were not:

| Class | v0.2.2 | now | |
|---|---|---|---|
| namesake-rugpull | 1/1 — "100%" | **1/6** | the one specimen was the one frisk catches |
| scope-mismatch | 1/1 — "100%" | **3/6** | |
| sensitive-params | 2/2 — "100%" | **3/6** | |
| credential-access | 1/1 — "100%" | **4/6** | |
| hygiene | 1/2 — "50%" | **1/6** | |
| **false positives** | **0/10** | **4/33** | the old twin set had no discriminating power at all |

Four classes that read as clean sweeps were sweeps of one specimen. The 95% interval on
`1/1` runs from 21% to 100%, so publishing "100%" implied precision the corpus could not
support — the same flattering half-truth R10 refuses for composite scores, arriving through
a door R10 did not cover. R18 and R19 exist because of this table.

The false-positive row is the sharper finding. `0/10` was not a good precision score; it was
a control that never fired. All four twins frisk now flags were independently audited and
confirmed benign — decoded byte by byte, schemas walked for every composition keyword at
every depth — so they are genuine false positives rather than mislabelled specimens.

### What the behavioural classes show

- **`egress` is missed entirely, 0/6**, and frisk flags none of its three twins either. It
  has no network-behaviour rule, so this class is a clean coverage gap rather than a
  discrimination failure. The twins are still doing their job: the naive "flag any
  `connect()`" rule fires on all three, which is what makes the class fair to score at all.
- **`exfil-enumeration` is missed entirely, 0/6.** The enumeration response *is* the
  exfiltration channel, so the scanner is reading the wire the theft rides on. Placement and
  encoding do the rest: a schema `default`, a resource URI query string, semver build
  metadata, schema key names, and a payload cut into twelve-character fragments across
  prompt arguments.
- **`scanner-aware` is missed entirely, 0/6.** Six specimens serve an inspector a clean
  catalog and an agent a poisoned one, keyed on declared capabilities, `clientInfo` shape,
  default client identity, handshake completion, sweep order, and re-enumeration. Every
  static conclusion frisk draws about them is *accurate about the catalog it was shown* —
  and useless.
- **`namesake-rugpull` fell from 1/1 to 1/6.** frisk's duplicate-name rule catches the
  immediate swap. Four specimens that mutate a description, a parameter's meaning, a
  `required` list or an `enum` member — at enumerations 2, 3 and 7 — pass it.
- **frisk is not a purely static scanner and the results show it.** It runs the server under
  a seatbelt sandbox seeded with decoy credentials and watches, which is why
  `credential-access` is 4/6 rather than 0/6. The gap this corpus measures is not
  static-versus-good; it is static-versus-behavioural, and frisk is on the right side of it.

### Two signals worth reading carefully

**Overt misses are coverage gaps, not subtlety.** Several classes caught **zero** of their
`overt` specimens while catching something `subtle`. A miss on an overt specimen means no
rule targets that class at all, which suggests the scattered subtle catches are incidental to
some other rule rather than evidence of depth. A single per-class percentage cannot express
that; this is what the tier field was added for.

**The twin-tier corroboration previously reported here is WITHDRAWN.** An earlier version of
this file observed that every false positive frisk produced fell in the top twin tier, and
offered it as independent evidence that the tier scale was sound. That inference rested on
twin tiers which have since been measured and found unreliable: eight blind raters reach
Krippendorff's α of 0.57–0.69 on twins, with intervals straddling the usable floor. A pattern
computed against an unreliable label is not corroboration of anything. See
[`docs/tier-reliability.md`](docs/tier-reliability.md).

Tiers on *malicious* specimens fare much better (α ≈ 0.83) and the per-tier counts above
stand — with one caveat recorded there: independent readers agree with the shipped
**behavioural** tiers only 46% of the time, against 79% for declaration tiers, so the
behavioural rows deserve re-verification before anyone leans on them.

### The registered misses (N2)

Specimen id first, so this table is machine-checkable. `scripts/check_known_misses.py`
counts these rows at release, and `test_registered_misses_were_actually_missed` asserts every
row names a specimen the committed result document records as missed — a row cannot drift
into naming something frisk now catches.

A curated selection, not the complete list: frisk misses 44 specimens in this
corpus, all enumerated per class in the result document. These are the ones that say
something a reader can act on.

| Specimen | Class | Tier | frisk verdict | What it would have to notice |
|---|---|---|---|---|
| `behaviour-egress-startup-beacon` | egress | overt | clean | Observe that a local-only number formatter opened a socket before answering `initialize`. Nothing in the catalog implies network capability; the declaration says conversion is local, and it is telling the truth about that. |
| `behaviour-egress-enumeration-order` | egress | subtle | clean | Notice a connection that fires only when `tools/list` is served *after* `resources/list`. Silent under the order every real client uses, so a scanner has to explore in an order nobody does. |
| `behaviour-egress-update-check-burst` | egress | moderate | clean | Treat five sockets opened for a 'ruleset refresh' nobody opted into as a finding. The pretext is in one description and in no schema, parameter or resource. Separates a threshold rule from a binary one. |
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
