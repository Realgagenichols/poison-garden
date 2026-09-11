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

from poison_garden.corpus.models import Class, Corpus


@dataclass(frozen=True)
class ValidationReport:
    """The outcome of validating a corpus, including the size of what was inspected."""

    classes_measured: tuple[Class, ...]
    classes_without_twin: tuple[Class, ...]
    specimens_measured: int
    malicious_count: int
    benign_count: int
    orphan_twins: tuple[tuple[str, Class], ...] = ()

    @property
    def ok(self) -> bool:
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

    return ValidationReport(
        classes_measured=tuple(sorted(present, key=lambda c: c.value)),
        classes_without_twin=missing,
        specimens_measured=len(corpus),
        malicious_count=len(corpus.malicious),
        benign_count=len(corpus.benign),
        orphan_twins=tuple(orphans),
    )
