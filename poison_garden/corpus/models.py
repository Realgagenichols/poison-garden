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

# Files and directories that are never part of a specimen's shipped identity.
IGNORED_FILE_NAMES: frozenset[str] = frozenset({".DS_Store"})
IGNORED_DIR_NAMES: frozenset[str] = frozenset({"__pycache__"})


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


# Below this many scorable specimens, a class's recall is not evidence about a scanner —
# it is evidence about one specimen. A population of one cannot separate "this tool has a
# gap here" from "this particular case is hard" (cross-cutting P48).
#
# Defined here, in the corpus layer, because it is a statement about whether the CORPUS is
# adequate, not about how a run is scored. Scoring and validation both import this one
# definition rather than each carrying a copy — a single threshold spelled in two places
# drifts, and the two surfaces would then disagree about which classes are quotable (P95).
MIN_SPECIMENS_FOR_A_CLAIM = 5


class Difficulty(StrEnum):
    """How hard a specimen is *meant* to be — R20.

    Declared by the author, never inferred from whether a scanner caught it. Inferring it
    would make the corpus grade itself on the curve of whoever ran it last, and a specimen
    would change tier every time a vendor shipped a release.

    The point is diagnostic, not decorative. "42% recall on injection" tells a maintainer
    nothing they can act on; "6/6 overt, 1/6 subtle" tells them their rules fire on the
    obvious phrasing and nothing else — which is a bug report, not a grade. It is also the
    honest way to read a low number: a scanner that catches every OVERT specimen and misses
    the subtle ones is in a different position from one that misses both, and a single
    percentage cannot tell those apart.

    **The assignment rubric lives in CONTRIBUTING.md, not here.** It used to live only in
    this docstring, which meant no contributor ever read it: every tier in the corpus was
    assigned by someone briefed in conversation instead, and the field had never been tested
    the way a contributor meets it. When it finally was, four independent raters each
    reported the same four gaps in it.

    **Reliability, measured rather than assumed** (docs/tier-reliability.md): eight blind
    raters over 60 specimens reach Krippendorff's α ≈ 0.83 on malicious specimens — good —
    and 0.57–0.69 on benign twins, straddling the usable floor. Twin tiers are therefore
    UNVALIDATED. Nothing consumes them: `by_difficulty` is computed over malicious specimens
    only, and no result document carries a twin's tier. Do not add a consumer until that
    number is established.
    """

    # The tell is on the surface: a scanner with a reasonable rule for this class should
    # find it. Misses here are gaps in coverage, not in subtlety.
    OVERT = "overt"
    # The tell is present and unambiguous but requires reading past the first line, or
    # correlating two fields that are individually unremarkable.
    MODERATE = "moderate"
    # The tell survives a careful reader only because it exploits something structural —
    # encoding, context, a behaviour no declaration reveals. Misses here are expected and
    # are not, on their own, a criticism of any scanner.
    SUBTLE = "subtle"


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

    # --- declared behaviour (M3) ------------------------------------------------------
    # How many enumerations poison-garden's own pre-flight consumes before the scanner
    # ever connects. A specimen whose behaviour depends on how many times it has run must
    # account for this, or the scanner sees a different invocation than the author meant —
    # which would make a rug-pull invisible, or fire it a beat early, as a function of OUR
    # implementation rather than the author's choice.
    preflight_enumerations: int = 1
    # What a scanner-aware specimen keys on. Recorded so the evasion is documented rather
    # than mysterious (R14), and so a reader can confirm it keys on something the SCANNER
    # controls rather than on poison-garden's own identity.
    discriminator: str = ""
    # Declares that two enumerations may legitimately differ. Without it, varying is a
    # defect: our pre-flight and the scanner's run are two invocations, and an undeclared
    # variation means the scanner measures something we never saw.
    varies_by_invocation: bool = False
    # The enumeration index, counting from 0, at which the catalog first differs from the
    # one served at enumeration 0.
    #
    # Exists because the test guarding `varies_by_invocation` asserted `catalogs[0] !=
    # catalogs[1]`, which quietly made "fires immediately" the only rug-pull the corpus
    # could express. That is the *easiest* rug-pull to catch: two-sample diffing finds it.
    # The interesting specimen is the one that waits, precisely because a scanner that
    # enumerates twice still sees nothing — and the guard forbade exactly that specimen.
    #
    # Declaring the index rather than loosening the assertion to "varies somewhere" keeps
    # the check strong in both directions: a specimen that claims 6 and fires at 1 fails,
    # and so does one that claims 6 and never fires (P76 — the expectation is listed
    # literally rather than inferred). The default of 1 is exactly the old assertion, so
    # every existing specimen keeps the guard it already had.
    varies_at_enumeration: int = 1

    # --- declared difficulty (R20) -----------------------------------------------------
    # Defaults to MODERATE rather than OVERT deliberately. An author who has not thought
    # about the tier should not have their specimen counted among the ones a scanner is
    # *expected* to catch — that would inflate the overt bucket, which is the bucket a miss
    # is read as a defect in.
    difficulty: Difficulty = Difficulty.MODERATE

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

    @property
    def difficulty(self) -> Difficulty:
        return self.manifest.difficulty

    def files(self) -> list[Path]:
        """Every file shipped as part of this specimen, sorted.

        **The single definition of "the files in this specimen."** Both the content hash
        and the S1/S2 safety scan consume this, so the set of bytes that gets hashed is by
        construction the same set that gets inspected for escapes. They used to be two
        definitions — the hash walked every file, while the safety scan globbed `*.py` —
        which left `manifest.toml` shipped, hashed, and never scanned, despite carrying
        author prose (`summary`, `notes`) where a hostname would plausibly land. A future
        `payload.json` would have been invisible the same way (cross-cutting P95).
        """
        return sorted(
            path
            for path in self.path.rglob("*")
            if path.is_file()
            and path.name not in IGNORED_FILE_NAMES
            and not any(part in IGNORED_DIR_NAMES for part in path.parts)
        )


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
