# Known misses

Specimens in this corpus that **`frisk` fails to flag.**

This project's maintainer also maintains [frisk](https://github.com/Realgagenichols/frisk),
an MCP security scanner. That is a conflict of interest, and this file is one of the
structural answers to it.

**Requirement N2:** every corpus release ships **at least three** specimens that frisk does not
detect, registered here. CI enforces the count. If frisk ever scored 100% against this corpus,
that would be a defect in the corpus — evidence it had been shaped around one scanner's
detectors — and not an achievement of that scanner.

The companion requirement is **N1**: specimens are not derived from frisk's detector fixtures.
A corpus authored from the same source as a scanner's rules cannot measure that scanner.

---

## Corpus v0.1.0 (unreleased)

| Specimen | Class | Why frisk misses it |
|---|---|---|
| _(populated during M1/M2 — a release cannot ship with fewer than three rows)_ | | |

---

## How to add a row

A row is earned by a measurement, not an estimate. Run the current release of frisk against the
specimen, record the command and its output, and cite the release version. A row without a
recorded run is a guess wearing a table's clothes.
