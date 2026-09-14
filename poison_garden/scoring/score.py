"""Scoring — R9, R10.

Two rules here are the project's whole posture, and both are enforced rather than urged:

**Recall and false positives ship together, or neither ships (R9).** Any scanner can score
100% recall by flagging everything. The benign twins are what make that visible, so a
document containing recall without a false-positive rate would be a flattering half-truth
with our name on it.

**No composite score (R10).** An aggregate invites the rank-ordering this project
deliberately refuses, and it hides the lopsided class — which is usually the interesting
one. Per-class figures plus an FP rate, and nothing that could be quoted as "the
poison-garden score".
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from poison_garden.corpus.models import (
    MIN_SPECIMENS_FOR_A_CLAIM,
    Class,
    Corpus,
    Difficulty,
)
from poison_garden.runner.execute import SpecimenResult, Verdict


class ScoringRefused(Exception):
    """Refusing to emit a result that would misrepresent what was measured."""


def wilson_interval(caught: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion, Wilson score method.

    Wilson rather than the textbook normal approximation, because the normal one is
    degenerate exactly where this corpus lives: at 0/1 it produces the interval [0, 0],
    asserting certainty from a single observation.
    """
    if total == 0:
        return (0.0, 1.0)
    p = caught / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    low, high = max(0.0, centre - half), min(1.0, centre + half)

    # The endpoints are exact, and floating point does not reproduce them. At p=1 the
    # algebra collapses to (1 + z²/n)/(1 + z²/n) = 1, but evaluated numerically it lands on
    # 0.9999999999999999 — an upper bound BELOW the 100% printed next to it. Rounded to four
    # decimals the published pair read `"recall": 1.0` against `[0.61, 1.0]` and looked fine,
    # so this would have shipped as an invariant violation nobody could see in the artifact.
    # Pinning the exact values, rather than widening by an epsilon, because they are exact.
    if caught == 0:
        low = 0.0
    if caught == total:
        high = 1.0
    return (low, high)


@dataclass(frozen=True)
class ClassScore:
    """Recall for one attack class. A specimen counts toward every class it carries."""

    klass: Class
    caught: int
    total: int
    missed: tuple[str, ...]
    errored: tuple[str, ...]
    # R20: caught/total split by the tier the AUTHOR declared, as raw counts.
    #
    # Counts and never a rate, deliberately. Splitting five or six specimens three ways
    # leaves two per tier, and a percentage computed on two is the exact overclaim R18
    # exists to stop — printing "subtle: 0%" from one specimen would reintroduce it one
    # level down. The counts are still worth having: "6/6 overt, 0/2 subtle" is a bug
    # report a maintainer can act on, where a single class-level percentage is not.
    #
    # Kept WITHIN the class rather than rolled up across the corpus. A corpus-wide
    # "subtle: 4/19" would hide the lopsided class, which is the same defect R10 refuses
    # for composite scores — arriving through a different door.
    by_difficulty: tuple[tuple[Difficulty, int, int], ...] = ()

    @property
    def interval(self) -> tuple[float, float]:
        """What this figure actually supports, at 95%.

        Published alongside the point estimate because the point estimate alone overclaims.
        At 0/1 the honest reading is "somewhere between 0% and 79%", and rendering that as
        "0%" is the same flattering precision R10 refuses for composite scores — a number
        that looks like a measurement and is not one.
        """
        return wilson_interval(self.caught, self.total)

    @property
    def sufficient(self) -> bool:
        """Whether this class has enough specimens to say anything about a scanner."""
        return self.total >= MIN_SPECIMENS_FOR_A_CLAIM

    @property
    def recall(self) -> float | None:
        """None when nothing was scorable — NOT 0.0, and NOT 1.0.

        A class where every specimen errored has no recall. Reporting 0.0 would accuse the
        scanner of missing things it was never shown; reporting 1.0 would credit it for the
        same. Both are claims the run cannot support (P55).
        """
        if self.total == 0:
            return None
        return self.caught / self.total


@dataclass(frozen=True)
class Scores:
    per_class: tuple[ClassScore, ...]
    false_positives: tuple[str, ...]
    benign_total: int
    benign_errored: tuple[str, ...]
    errored: tuple[str, ...]

    @property
    def false_positive_rate(self) -> float | None:
        if self.benign_total == 0:
            return None
        return len(self.false_positives) / self.benign_total


def score_run(corpus: Corpus, results: list[SpecimenResult]) -> Scores:
    """Turn per-specimen verdicts into per-class recall and a false-positive rate."""
    # Duplicates are checked BEFORE building the map, because building it is what hides
    # them: a second result for the same specimen silently overwrites the first, and the
    # figures would then describe whichever one happened to come last.
    seen: dict[str, int] = {}
    for result in results:
        seen[result.specimen_id] = seen.get(result.specimen_id, 0) + 1
    duplicates = sorted(sid for sid, count in seen.items() if count > 1)
    if duplicates:
        raise ScoringRefused(
            f"more than one result for specimen(s) {duplicates}. Which verdict counts is "
            "undefined, so the figures would describe whichever arrived last."
        )

    by_id = {r.specimen_id: r for r in results}
    corpus_ids = {s.id for s in corpus.specimens}

    missing = sorted(corpus_ids - set(by_id))
    if missing:
        raise ScoringRefused(
            f"no result for specimen(s) {missing}. Scoring a partial run would "
            "silently shrink the denominator of every figure below."
        )

    # The guard used to look only one way. A result naming a specimen the corpus does not
    # contain means the run and the corpus disagree about what was measured — which is the
    # same class of defect as a missing one, and equally fatal to a published figure.
    extra = sorted(set(by_id) - corpus_ids)
    if extra:
        raise ScoringRefused(
            f"result(s) for specimen(s) not in this corpus: {extra}. The run and the "
            "corpus disagree about what was measured."
        )

    benign = corpus.benign
    scorable_benign = [s for s in benign if by_id[s.id].scored]

    if not scorable_benign:
        raise ScoringRefused(
            "refusing to emit a result with no scorable benign twins. Recall without a "
            "false-positive rate is a flattering half-measurement: any scanner reaches "
            "100% recall by flagging everything, and the twins are the only thing that "
            "makes that visible (R9)."
        )

    per_class: list[ClassScore] = []
    for klass in sorted(corpus.classes_present, key=lambda c: c.value):
        attackers = [s for s in corpus.malicious if klass in s.classes]
        # Numerator and denominator come from ONE set expression, in one place, so they
        # cannot come to describe different populations (cross-cutting P40).
        scorable = [s for s in attackers if by_id[s.id].scored]
        # Per-class credit. With SARIF, a flag counts for a class only if the scanner
        # actually identified THAT class — which matters for a dual-class specimen, where
        # one verdict would otherwise credit both classes for seeing one. Without SARIF
        # the verdict is the whole signal and a flag credits every class the specimen
        # carries, which is the honest reading of a coarser instrument.
        def _credited(specimen, _klass=klass) -> bool:
            """Did the scanner get credit for THIS class on THIS specimen?

            With SARIF, a flag counts for a class only if the scanner identified that
            class — which matters for a dual-class specimen, where one verdict would
            otherwise credit both classes for seeing one. Without SARIF the verdict is the
            whole signal, and a flag credits every class the specimen carries: the honest
            reading of a coarser instrument.
            """
            result = by_id[specimen.id]
            if result.verdict is not Verdict.FLAGGED:
                return False
            return result.attributed is None or _klass in result.attributed

        # `missed` is the complement of `caught` over the SAME set, by construction.
        # Computing it independently as "verdict is CLEAN" left a hole the moment SARIF
        # arrived: a specimen flagged but NOT attributed to this class was in neither list,
        # so caught + missed != total and the document's own consistency check would have
        # rejected it (P40 — numerator and denominator from one set expression, in one
        # place).
        caught = [s for s in scorable if _credited(s)]
        missed = [s for s in scorable if not _credited(s)]

        # R20. Built from the SAME `scorable`/`caught` lists as the headline figures, so
        # the tiers sum to the class total by construction rather than by coincidence — the
        # same reason `missed` is the complement of `caught` over one set expression (P40).
        # A tier computed from an independently-rebuilt population would drift the moment
        # the credit rule changed, and the sums would stop agreeing with nothing to say so.
        caught_ids = {s.id for s in caught}
        by_difficulty = tuple(
            (
                tier,
                sum(1 for s in scorable if s.difficulty is tier and s.id in caught_ids),
                sum(1 for s in scorable if s.difficulty is tier),
            )
            for tier in Difficulty
        )

        per_class.append(
            ClassScore(
                klass=klass,
                caught=len(caught),
                total=len(scorable),
                missed=tuple(sorted(s.id for s in missed)),
                errored=tuple(sorted(s.id for s in attackers if not by_id[s.id].scored)),
                by_difficulty=by_difficulty,
            )
        )

    return Scores(
        per_class=tuple(per_class),
        false_positives=tuple(
            sorted(s.id for s in scorable_benign if by_id[s.id].verdict is Verdict.FLAGGED)
        ),
        benign_total=len(scorable_benign),
        benign_errored=tuple(sorted(s.id for s in benign if not by_id[s.id].scored)),
        errored=tuple(sorted(r.specimen_id for r in results if not r.scored)),
    )
