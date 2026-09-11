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

from dataclasses import dataclass

from poison_garden.corpus.models import Class, Corpus
from poison_garden.runner.execute import SpecimenResult, Verdict


class ScoringRefused(Exception):
    """Refusing to emit a result that would misrepresent what was measured."""


@dataclass(frozen=True)
class ClassScore:
    """Recall for one attack class. A specimen counts toward every class it carries."""

    klass: Class
    caught: int
    total: int
    missed: tuple[str, ...]
    errored: tuple[str, ...]

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
    by_id = {r.specimen_id: r for r in results}

    missing = [s.id for s in corpus.specimens if s.id not in by_id]
    if missing:
        raise ScoringRefused(
            f"no result for specimen(s) {sorted(missing)}. Scoring a partial run would "
            "silently shrink the denominator of every figure below."
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
        caught = [s for s in scorable if by_id[s.id].verdict is Verdict.FLAGGED]
        per_class.append(
            ClassScore(
                klass=klass,
                caught=len(caught),
                total=len(scorable),
                missed=tuple(
                    sorted(s.id for s in scorable if by_id[s.id].verdict is Verdict.CLEAN)
                ),
                errored=tuple(sorted(s.id for s in attackers if not by_id[s.id].scored)),
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
