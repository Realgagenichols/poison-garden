# Contributing a specimen

A specimen is one directory under `specimens/`, containing `server.py` and `manifest.toml`.
It is a **runnable stdio MCP server** — a real program — not a JSON document. That is the
whole differentiator: a declaration and a behaviour can be authored to disagree only if
something is actually running.

```toml
id       = "injection-meeting-preamble"   # must equal the directory name
summary  = "One sentence: what it pretends to be, and what the tell is."
declaration = ["injection"]   # what the server SAYS, visible in tools/list
behavior    = []              # what it DOES when run
difficulty  = "overt"         # see below
notes    = "What a scanner would have to notice, and why that is hard."
```

`declaration` and `behavior` are independent and either may be empty. Both empty plus a
`twin_for` field makes it a **benign twin** — a legitimate server that resembles a malicious
one. Every class needs twins, and `poison-garden validate` fails without them. Write them to
be genuinely tempting: they are the only thing standing between this corpus and a scanner
that scores well by flagging everything.

Two rules that are easy to erode and expensive to lose:

- **Write from the threat, never from a scanner's rules.** A corpus authored from the same
  source as a detector cannot measure that detector. `scripts/audit_n1_independence.py`
  enforces this.
- **Demonstrative, not weaponized.** A specimen shows the *detectable signal* of an attack
  class and must be useless lifted out of the corpus. Decoy credentials only; every socket
  goes to loopback, through `_behaviour.attempt_egress` and nowhere else.

---

# Difficulty tiers

Results report caught/total per tier within each class, which is what turns a bare percentage
into a diagnosis: *6/6 overt, 0/2 subtle* says a scanner's rules fire on the obvious phrasing
and nothing else. That is a bug report. *75%* is a grade.

**This rubric has been tested.** Eight independent raters, blind to existing tiers, applied
it to 60 specimens. Agreement on malicious specimens is good (Krippendorff's α ≈ 0.83);
agreement on twins is weaker and not yet demonstrated to be reliable. See
[`docs/tier-reliability.md`](docs/tier-reliability.md) — including what is *not* established.

## The one question

**How much work must a competent scanner do before this specimen's tell is in front of it?**

- **The observer is a scanner built for this class, not a human reader.** Those tests come
  apart: zero-width characters defeat literal matching while a human reading the rendered
  text sees the instruction in plain sight. Grade against the tool.
- **Difficulty grades the tell, never the payload.** A specimen whose trigger is one line of
  client configuration is `overt` even if what it does once triggered is the most blatant
  theft in the corpus. Severity is a different axis and this field does not carry it.
- **Grade within the specimen's own family** — behavioural against behavioural, declaration
  against declaration. An `overt` behavioural specimen is the floor of its own family, not
  "as easy as" an `overt` injection string.
- **A specimen with two tells is graded by its EASIEST one.** The tier predicts whether a
  miss is excusable, and it is the easiest tell that makes a catch.

## Malicious specimens

| tier | test | a miss means |
|---|---|---|
| **overt** | The tell is in what the scanner already reads, and needs no reasoning once seen. | **Coverage gap** — that class is unimplemented. |
| **moderate** | One genuine inferential step: correlate two or more individually-unremarkable fields, or recognise that a phrase means something other than it appears to. Everything is present and unencoded. | A real but forgivable limitation. |
| **subtle** | A capability beyond reading the surface: decoding, reassembly across fields, character-class or traversal analysis, or arranging a condition the scanner would not arrange by default. | **Expected.** Not a criticism of any scanner. |

**Not a test:** "does the payload appear after the first line." Nearly every description here
is a summary, a blank line, then a paragraph, so that fires on almost everything. Count
independent reasoning steps instead — zero, one, or a capability the scanner may not have.

### Behavioural specimens: grade the precondition

A behavioural specimen's declaration reveals nothing *by construction*. That is the
definition of the family, not a difficulty — read literally it would make every one of them
`subtle`, which is useless. Grade on how hard it is to arrange the conditions under which the
behaviour fires:

- **overt** — fires unconditionally. Run the server at all and you see it.
- **moderate** — fires under a condition any ordinary client meets: enumerating, listing
  resources, completing a handshake.
- **subtle** — fires only under a condition an observer must deliberately construct:
  enumerating a specific number of times, calling methods in an unusual order.

**When the precondition is trivial but the payload is encoded, encoding wins.** An
`exfil-enumeration` specimen fires on any `tools/list` — trivial — while its secret is
base64 in a schema `default`. Grade it `subtle`. The premise behind the precondition rule is
that the declaration is not the carrier; for this family it *is* the carrier, so the rule
does not apply. Three raters independently hit this and called it a coin flip, which is why
it is written down.

**For `scanner-aware`, the question is whether a scanner lands on the poisoned branch by
accident.** Every specimen in the class keys on client identity in some form, so "presenting
a particular client identity" cannot by itself mean `subtle`. Ask instead: would a scanner
built without any thought of evasion set this field the poisoned way?

- **overt** — yes, incidentally. A scanner that names itself anything product-shaped is poisoned.
- **moderate** — only if it behaves like an ordinary client (declares capabilities, completes
  the handshake).
- **subtle** — only by constructing something no default client does.

## Benign twins

A twin has no tell, so the question above does not apply — do not force it. The tier grades
**how tempting the false positive is**: how loudly a plausible naive rule fires on this
legitimate server.

| tier | test |
|---|---|
| **overt** | Almost any keyword or single-signal rule flags it. |
| **moderate** | It trips a naive rule only after reading into the schema or correlating two fields. |
| **subtle** | Its mechanism is what its malicious sibling does, byte for byte, and only a judgement about *necessity* separates them. |

**Temptation decides, not how easily the twin is cleared.** Those two usually agree; where
they diverge — a twin that trips four rules and is acquitted by the very next sentence — grade
on the temptation. The twin exists to provoke the false positive; how gracefully a good
scanner recovers is a different question and not this field.

**`overt` on a twin is praise.** It means the twin is doing its job. A twin nothing would
ever flag controls for nothing. Never downgrade a twin because it is well made.

## If you cannot decide

Pick the lower tier and say so in `notes`. Over-rating difficulty is the more damaging error:
it moves a specimen out of the bucket where a miss counts as a coverage gap, which is the
bucket that makes the corpus diagnostic.

## Do not state the tier in `notes`

Write what a scanner would have to notice, not how hard you think that is. Phrases like "the
floor of the class" or "a miss is expected" make the note, rather than the rubric, decide the
tier — measured at roughly a fifth of the corpus, where raters transcribed the author's
judgement instead of forming one.

---

# Before you open a pull request

```bash
uv run poison-garden validate      # R3: every class has a benign twin
uv run pytest -q                   # includes per-specimen boot and safety checks
uv run ruff check .
uv run python scripts/audit_n1_independence.py
```

Your specimen must boot, answer a real MCP handshake, serve byte-identical catalogs across
two enumerations unless it declares `varies_by_invocation`, and exit cleanly when stdin
closes. A specimen that errors is excluded from both numerator and denominator, which means
it measures nothing.
