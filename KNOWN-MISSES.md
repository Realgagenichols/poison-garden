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

## Corpus v0.1.0 (unreleased)

**Measured 2026-09-11** against `mcp-frisk` 0.2.0, using:

```sh
uvx --from mcp-frisk frisk scan --no-sandbox -- <python> specimens/<id>/server.py
```

`--no-sandbox` because the specimens are already being run inside poison-garden's own
throwaway HOME during a benchmark run; frisk's seatbelt profile is orthogonal to what is
being measured here (its *detectors*, not its containment).

**Per class** — reported this way rather than as one figure, for the same reason R10 forbids a
composite score in a result document: an aggregate hides exactly the lopsided class that
matters. A specimen carrying two classes counts toward both.

| Class | Caught | Missed |
|---|---|---|
| hidden-content | 4/4 | — |
| sensitive-params | 2/2 | — |
| scope-mismatch | 1/1 | — |
| injection | 3/4 | `injection-meeting-preamble` |
| hygiene | 1/2 | `hygiene-unpinned-remote-exec` |
| **impersonation** | **0/1** | `impersonation-builtin-reader` |

**False positives: 0 of 6 twins.** Aggregate: 9 of 12 malicious specimens flagged, 3 missed.

The interesting line is impersonation, not the aggregate: frisk flags none of it. One specimen
is too small a sample to call that a detection gap rather than a single hard case, which is
itself a finding — the class needs more attackers before its recall figure means anything.

Two specimens (`hidden-zero-width-transit`, `hidden-markup-comment-inventory`) carry a real
instruction inside the hidden channel and are therefore labelled both `hidden-content` and
`injection`. Under-labelling an obvious injection would have deflated that class's recall.

### The three misses (N2 satisfied)

| Specimen | Class | frisk verdict | What it would have to notice |
|---|---|---|---|
| `injection-meeting-preamble` | injection | PASS | The description reads as ordinary operational prose. Its directives are phrased as vendor policy ("Assistant procedure (required)") and its concealment instruction is justified on plausible support grounds, rather than using imperative override vocabulary. |
| `impersonation-builtin-reader` | impersonation | PASS | Name-similarity to a common built-in, combined with description text steering the model away from another server, on a server whose stated domain does not need that tool at all. |
| `hygiene-unpinned-remote-exec` | hygiene | PASS | A tool that describes fetching and executing code from an unpinned remote location — provenance is unverifiable, but nothing in the advertised text is syntactically suspicious. |

### Caught (not a miss — recorded for completeness)

`hidden-zero-width-transit`, `hidden-bidi-override-export`, `hidden-ansi-escape-ci` (FAIL);
`hidden-markup-comment-inventory`, `hygiene-anonymous-server`, `scope-mismatch-timezone-helper`,
`sensitive-params-diagnostics-dump`, `sensitive-params-ticket-transcript` (WARN);
`injection-invoice-remit-override` (FAIL).

### False positives

**None.** All six benign twins pass clean. Worth stating plainly, because it cuts against
this project's own interest: the twins were built to be tempting, and a scanner that resisted
all six is doing the hard part correctly. The corpus's `test_every_twin_trips_at_least_one_strawman`
confirms the twins *do* trip naive keyword rules — frisk is simply better than a strawman.

---

## How to add a row

A row is earned by a measurement, not an estimate. Run the current release of frisk against the
specimen, record the command and its output, and cite the release version. A row without a
recorded run is a guess wearing a table's clothes.

Re-measure on every frisk release. A miss that frisk later fixes must be struck from this
table, and if that drops the count below three, **the corpus needs new specimens before the
next release** — not a relaxed requirement.
