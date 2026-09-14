"""Corpus validation — R3 (every attack class has a benign twin).

The twin requirement is what stops a scanner scoring well by flagging everything. If a
class has no benign control, its false-positive rate is unmeasurable and the recall figure
for it means nothing.

This module reports what it MEASURED, not merely a verdict (cross-cutting P64): a corpus
with zero classes must not pass silently, because "nothing failed" and "nothing was
checked" are two different findings (P55).
"""

from __future__ import annotations

from dataclasses import dataclass

from poison_garden.corpus.models import MIN_SPECIMENS_FOR_A_CLAIM, Class, Corpus


@dataclass(frozen=True)
class ValidationReport:
    """The outcome of validating a corpus, including the size of what was inspected."""

    classes_measured: tuple[Class, ...]
    classes_without_twin: tuple[Class, ...]
    specimens_measured: int
    malicious_count: int
    benign_count: int
    orphan_twins: tuple[tuple[str, Class], ...] = ()
    # R19: classes carrying too few malicious specimens to support a published figure,
    # as (class, count) pairs.
    undersized_classes: tuple[tuple[Class, int], ...] = ()

    @property
    def ok(self) -> bool:
        """Undersized classes are deliberately NOT a failure.

        R19's contract is that a thin class is *reported as thin*, not that it is forbidden.
        Failing validation on it would mean a new attack class could never be added — its
        first specimen would break the build, so the corpus could only ever grow in blocks
        of five. Reporting it keeps the pressure visible without making breadth impossible.
        """
        return not self.classes_without_twin and not self.is_vacuous

    @property
    def is_vacuous(self) -> bool:
        """A corpus that exhibits no classes at all cannot validate anything."""
        return not self.classes_measured

    def summary(self) -> str:
        if self.is_vacuous:
            return (
                f"VACUOUS: {self.specimens_measured} specimen(s) inspected but zero attack "
                "classes present — there is nothing here to validate. A corpus that "
                "measures nothing must not report success."
            )
        head = (
            f"{len(self.classes_measured)} class(es) measured across "
            f"{self.specimens_measured} specimen(s) "
            f"({self.malicious_count} malicious, {self.benign_count} benign)"
        )
        if self.classes_without_twin:
            missing = ", ".join(sorted(c.value for c in self.classes_without_twin))
            return f"FAIL: {head}. No benign twin for: {missing}"
        out = f"OK: {head}. Every class has at least one benign twin."
        if self.undersized_classes:
            thin = ", ".join(f"{k.value} (n={n})" for k, n in self.undersized_classes)
            out += (
                f"\nNOTE: {len(self.undersized_classes)} class(es) below the "
                f"{MIN_SPECIMENS_FOR_A_CLAIM}-specimen threshold and reported as "
                f"insufficient rather than as a figure: {thin}"
            )
        if self.orphan_twins:
            orphans = ", ".join(f"{sid} -> {k.value}" for sid, k in self.orphan_twins)
            out += f"\nNOTE: twin(s) controlling for absent class(es): {orphans}"
        return out


def validate_corpus(corpus: Corpus) -> ValidationReport:
    """Check R3: every class exhibited by a malicious specimen has a benign twin."""
    present = corpus.classes_present
    with_twin = corpus.classes_with_twin

    missing = tuple(sorted(present - with_twin, key=lambda c: c.value))

    # A twin controlling for a class no specimen exhibits is not a failure, but it IS a
    # stale accepted-control that should not linger unnoticed (frisk's baseline lesson).
    orphans: list[tuple[str, Class]] = []
    for specimen in corpus.benign:
        for klass in sorted(specimen.twin_for - present, key=lambda c: c.value):
            orphans.append((specimen.id, klass))

    # R19. Counted over MALICIOUS specimens carrying the class, which is the denominator a
    # recall figure is computed against — counting every specimen would include the twins
    # and report a class as well-covered on the strength of its controls.
    undersized: list[tuple[Class, int]] = []
    for klass in sorted(present, key=lambda c: c.value):
        count = sum(1 for s in corpus.malicious if klass in s.classes)
        if count < MIN_SPECIMENS_FOR_A_CLAIM:
            undersized.append((klass, count))

    return ValidationReport(
        classes_measured=tuple(sorted(present, key=lambda c: c.value)),
        classes_without_twin=missing,
        specimens_measured=len(corpus),
        malicious_count=len(corpus.malicious),
        benign_count=len(corpus.benign),
        orphan_twins=tuple(orphans),
        undersized_classes=tuple(undersized),
    )
