"""Corpus data model.

The central idea of poison-garden lives in `Manifest`: a specimen's **declaration** classes
and its **behavior** classes are independent lists (R2). A specimen whose declaration is
empty and whose behavior is hostile is exactly the case static scanners cannot express, and
it is the reason a specimen is a running program rather than a JSON document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Class(StrEnum):
    """An attack family.

    Declaration classes describe what a specimen *says* (visible in `tools/list`).
    Behavior classes describe what it *does* when run. A manifest may use either list;
    the split is the whole point (R2).
    """

    # --- declaration classes (M1) -----------------------------------------------------
    INJECTION = "injection"
    HIDDEN_CONTENT = "hidden-content"
    SENSITIVE_PARAMS = "sensitive-params"
    SCOPE_MISMATCH = "scope-mismatch"
    IMPERSONATION = "impersonation"
    HYGIENE = "hygiene"

    # --- behavior classes (M3) --------------------------------------------------------
    CREDENTIAL_ACCESS = "credential-access"
    EGRESS = "egress"
    EXFIL_ENUMERATION = "exfil-enumeration"
    NAMESAKE_RUGPULL = "namesake-rugpull"
    SCANNER_AWARE = "scanner-aware"


DECLARATION_CLASSES: frozenset[Class] = frozenset(
    {
        Class.INJECTION,
        Class.HIDDEN_CONTENT,
        Class.SENSITIVE_PARAMS,
        Class.SCOPE_MISMATCH,
        Class.IMPERSONATION,
        Class.HYGIENE,
    }
)

BEHAVIOR_CLASSES: frozenset[Class] = frozenset(
    {
        Class.CREDENTIAL_ACCESS,
        Class.EGRESS,
        Class.EXFIL_ENUMERATION,
        Class.NAMESAKE_RUGPULL,
        Class.SCANNER_AWARE,
    }
)


class ManifestError(Exception):
    """A manifest is malformed. Carries the specimen path and the offending key."""


@dataclass(frozen=True)
class Manifest:
    """Ground truth for one specimen.

    `declaration` and `behavior` are independent and either MAY be empty (R2). Both empty
    means the specimen is benign — a twin used as a false-positive control (R3).
    """

    id: str
    summary: str
    declaration: tuple[Class, ...] = ()
    behavior: tuple[Class, ...] = ()
    twin_for: tuple[Class, ...] = ()
    entrypoint: str = "server.py"
    notes: str = ""

    @property
    def is_benign(self) -> bool:
        """True when the specimen exhibits no attack class at all.

        `twin_for` deliberately does NOT count: a twin is benign *by construction*. It
        names the class it is a false-positive control for, which is a different question
        from what it exhibits.
        """
        return not self.declaration and not self.behavior

    @property
    def classes(self) -> frozenset[Class]:
        """Every class this specimen exhibits, across both axes."""
        return frozenset(self.declaration) | frozenset(self.behavior)


@dataclass(frozen=True)
class Specimen:
    """A specimen on disk: its directory, its manifest, and its server entrypoint."""

    path: Path
    manifest: Manifest

    @property
    def id(self) -> str:
        return self.manifest.id

    @property
    def entrypoint_path(self) -> Path:
        return self.path / self.manifest.entrypoint

    @property
    def is_benign(self) -> bool:
        return self.manifest.is_benign

    @property
    def classes(self) -> frozenset[Class]:
        return self.manifest.classes

    @property
    def twin_for(self) -> frozenset[Class]:
        return frozenset(self.manifest.twin_for)


@dataclass(frozen=True)
class Corpus:
    """A loaded corpus: its specimens plus the version they were released under."""

    root: Path
    version: str
    specimens: tuple[Specimen, ...] = field(default=())

    def __len__(self) -> int:
        return len(self.specimens)

    @property
    def malicious(self) -> tuple[Specimen, ...]:
        return tuple(s for s in self.specimens if not s.is_benign)

    @property
    def benign(self) -> tuple[Specimen, ...]:
        return tuple(s for s in self.specimens if s.is_benign)

    @property
    def classes_present(self) -> frozenset[Class]:
        """Every class exhibited by at least one malicious specimen."""
        out: set[Class] = set()
        for specimen in self.malicious:
            out |= specimen.classes
        return frozenset(out)

    @property
    def classes_with_twin(self) -> frozenset[Class]:
        """Every class that at least one benign specimen acts as a control for."""
        out: set[Class] = set()
        for specimen in self.benign:
            out |= specimen.twin_for
        return frozenset(out)

    def twins_for(self, klass: Class) -> tuple[Specimen, ...]:
        return tuple(s for s in self.benign if klass in s.twin_for)

    def by_id(self, specimen_id: str) -> Specimen | None:
        for specimen in self.specimens:
            if specimen.id == specimen_id:
                return specimen
        return None
