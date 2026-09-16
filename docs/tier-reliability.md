# Are the difficulty tiers reliable?

`difficulty` is declared by a specimen's author and published per class (R20). It is only
worth publishing if two competent people reading the same rubric assign the same tier. This
records an attempt to find out, including what it failed to establish.

## Why it was run

While re-tiering the benign twins, a cold reviewer and the specimen authors disagreed
completely: every twin the authors rated `subtle`, the reviewer rated `overt` — six of six, a
clean sign reversal rather than a spread. The shipped tiers were internally consistent only
because one judge assigned all of them. That is one observation, on one axis, with n=6, and
the project's own standard forbids publishing figures on that basis.

## Method

Pre-registered before any data was collected: hypotheses, sample, measure, and the thresholds
below were fixed in advance so the result could not be read to fit whatever came back.

- **60 specimens** — 30 malicious, 30 benign twins, seeded random draw from corpus 0.4.0
- **8 raters**, four per rubric version, independent, no shared context
- **Blind** — every `difficulty` line stripped; no access to the repository, `KNOWN-MISSES.md`,
  result documents, or git history
- **Randomised item order** per rater, so fatigue could not bias particular specimens
- **Krippendorff's α, ordinal metric** — ordinal because the tiers are ranked, and a nominal
  metric scores `overt`-vs-`subtle` the same as `overt`-vs-`moderate`, which would hide
  exactly the reversal under investigation. Reported with a bootstrap interval, because a
  corpus that refuses to publish recall without one (R18) cannot exempt its own statistics.

## What was established

**The tier is reliable for malicious specimens.** α ≈ 0.82–0.83 across both rubric versions
and all eight raters. Good agreement by any conventional reading.

**It is not demonstrably reliable for twins.** α = 0.57 under the original rubric and 0.69
under a rewrite, both with intervals straddling the 0.667 floor. The rewrite targeted the
twin guidance specifically and moved twin agreement by +0.125 while leaving malicious
agreement unchanged (+0.014) — the right shape for a targeted fix. But a paired bootstrap on
the *difference* gives [−0.084, +0.355]: consistent with a real improvement and equally
consistent with none. **At n=21 twins this study cannot tell.** Comparing the two point
estimates and declaring the floor cleared would be the overlapping-interval error.

**The rubric was the defect, not the raters' competence.** All four raters of the original
rubric independently reported the same four gaps, in the same order of severity:

1. It said nothing about benign twins, which are a third of the corpus — "the single largest
   source of noise" in three separate reports
2. `overt` was defined against a scanner and `subtle` against a human reader, so the two
   tests disagreed routinely
3. "a behaviour no declaration reveals" is literally true of *every* behavioural specimen,
   collapsing the whole family to `subtle`
4. Manifest `notes` were doing the grading the rubric should do

**The notes are load-bearing.** Where a note states or implies a tier, raters were unanimous
83% of the time; on clean specimens, 67%. Roughly a fifth of the corpus was graded by
transcription rather than judgement. This matters most for the case the field exists to
serve: a *new* specimen has no notes yet, so a new contributor gets only the rubric.

**The shipped tiers disagree with independent readers**, and the disagreement is not evenly
spread:

| family | raters matching shipped | unanimous 4/4 disagreements |
|---|---|---|
| declaration | 65% | 4/35 |
| behavioural | 49% | 10/25 |

Malicious specimens alone: 79% declaration versus 46% behavioural. A rater predicted this
clustering before seeing any of the data, from the mechanism — the behavioural tiers encode
what the author built the specimen to *test* (the strength of its discriminator), which is
often not a property of the artifact a reader can observe.

## What follows

- The rubric is rewritten and now lives in [`CONTRIBUTING.md`](../CONTRIBUTING.md), where a
  contributor will actually meet it. It previously existed only as a docstring in
  `poison_garden/corpus/models.py`, which no contributor reads — so every tier in the corpus
  was assigned by someone briefed in conversation, and the field had never been tested the
  way a contributor meets it.
- **Twin tiers remain unvalidated and are published nowhere.** `by_difficulty` is computed
  over malicious specimens only; no figure in any result document carries a twin's tier. The
  field stays in the manifest because the data is cheap to keep and expensive to recreate,
  but nothing may consume it until its reliability is established.
- **The behavioural malicious tiers need re-verification.** 46% agreement with independent
  readers is too low to leave unexamined, and the sample covered fewer than half of them.
- An earlier note in `KNOWN-MISSES.md` observed that every false positive a scanner produced
  fell in the top twin tier, and offered it as corroboration that the tier scale was sound.
  **That corroboration is withdrawn.** It rested on twin tiers this study finds unreliable.

## What this does not show

Eight raters are not eight human contributors. They may share priors a human pool would not,
or lack professional context a human pool would have. High agreement here is necessary but
not sufficient evidence that humans would agree; low agreement is strong evidence that they
would not. The malicious result should be read as "this rubric is probably usable", not "this
rubric is proven".

Two defects were predicted before the rewrite was tested and are still unfixed in the data,
though both are now addressed in the rubric text: multi-tell specimens had no rule for which
tell governs, and the twin definition conjoined two criteria without a tiebreak. A third was
introduced *by* the rewrite and caught by three raters independently — the instruction to
grade behavioural specimens by their precondition contradicts the encoding clause for the
`exfil-enumeration` family, whose declaration genuinely is the carrier.

Raw ratings, pre-registration, and analysis code were kept outside the repository; the
findings above are the durable part.
