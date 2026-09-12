"""Validating a submitted result document — R15.

**Maintainers never recompute, adjust, or editorialise a submitted figure.** That is the
founding constraint expressed at the submission boundary: validation either accepts a
document as its author published it, or rejects it with a reason. There is deliberately no
code path that repairs one — a "helpful" fix-up would make the published figure ours rather
than the vendor's, which is the referee posture this project refuses.

So every check here answers one of two questions:

1. **Does this document describe a corpus we released?** A result citing an unknown corpus
   hash is not wrong, but it is not comparable either, and R4 exists to stop those being
   silently mixed.
2. **Does it agree with itself?** The stated per-class figures must be recomputable from the
   document's own verdict list. A vendor cannot be stopped from running a scanner badly, but
   a document whose summary contradicts its own evidence is not a measurement at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from poison_garden.scoring.document import (
    SCHEMA_VERSION,
    composite_fields_in,
    unexpected_fields_in,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RELEASES_FILE = REPO_ROOT / "CORPUS_RELEASES.json"

REQUIRED_TOP_LEVEL = ("schema", "corpus", "scanner", "verdicts", "per_class", "false_positives")


@dataclass
class ValidationResult:
    path: Path
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        head = f"{self.path.name}: {'OK' if self.ok else 'REJECTED'}"
        lines = [head]
        lines += [f"  error: {e}" for e in self.errors]
        lines += [f"  note:  {n}" for n in self.notes]
        return "\n".join(lines)


def known_releases() -> dict[str, str]:
    """version -> corpus hash, for every corpus this repo has released.

    A registry rather than "compare against the working tree": results accumulate across
    releases, so a document citing corpus 0.1.0 must stay valid after 0.2.0 ships. Checking
    against the current tree would silently invalidate every historical submission on the
    next corpus change, which is the opposite of what R4 is for.
    """
    if not RELEASES_FILE.is_file():
        return {}
    return json.loads(RELEASES_FILE.read_text(encoding="utf-8"))


def validate_document(path: str | Path, releases: dict[str, str] | None = None) -> ValidationResult:
    """Validate one submitted result document. Never modifies it."""
    target = Path(path)
    result = ValidationResult(path=target)
    releases = known_releases() if releases is None else releases

    try:
        payload: Any = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.errors.append(f"unreadable or not JSON ({type(exc).__name__})")
        return result

    if not isinstance(payload, dict):
        result.errors.append("top level is not an object")
        return result

    missing = [k for k in REQUIRED_TOP_LEVEL if k not in payload]
    if missing:
        result.errors.append(f"missing required key(s): {missing}")
        return result

    if payload.get("schema") != SCHEMA_VERSION:
        result.errors.append(
            f"schema is {payload.get('schema')!r}, expected {SCHEMA_VERSION!r}"
        )

    _check_corpus(payload, releases, result)
    _check_no_composite(payload, result)
    _check_figures_match_verdicts(payload, result)

    return result


def _check_corpus(payload: dict, releases: dict[str, str], result: ValidationResult) -> None:
    corpus = payload.get("corpus") or {}
    version, digest = corpus.get("version"), corpus.get("hash")

    if not isinstance(version, str) or not isinstance(digest, str):
        result.errors.append("corpus.version and corpus.hash must both be strings")
        return

    if not releases:
        result.notes.append("no corpus release registry present; hash not verified")
        return

    if version not in releases:
        result.errors.append(
            f"corpus version {version!r} is not a released corpus. Known: "
            f"{sorted(releases)}"
        )
        return

    if releases[version] != digest:
        result.errors.append(
            f"corpus hash does not match release {version}.\n"
            f"    submitted: {digest}\n"
            f"    released:  {releases[version]}\n"
            "    The document describes a corpus that is not the one it names, so its "
            "figures are not comparable with anything else citing that version."
        )


def _check_no_composite(payload: dict, result: ValidationResult) -> None:
    composite = composite_fields_in(payload)
    if composite:
        result.errors.append(f"contains composite-score field(s): {composite} (R10)")

    unknown = unexpected_fields_in(payload)
    if unknown:
        result.errors.append(
            f"contains field(s) outside the result schema: {unknown}. A headline number "
            "can be named anything, so the schema is asserted exactly rather than by "
            "keyword."
        )


def _check_figures_match_verdicts(payload: dict, result: ValidationResult) -> None:
    """The stated figures must be recomputable from the document's own verdict list.

    This is the check that makes self-reporting safe to publish. A vendor may run a scanner
    however they like; what they may not do is publish a summary their own evidence
    contradicts (P26 — two artifacts that must correspond need the correspondence asserted
    mechanically).
    """
    verdicts = payload.get("verdicts")
    per_class = payload.get("per_class")
    if not isinstance(verdicts, list) or not isinstance(per_class, list):
        result.errors.append("verdicts and per_class must both be lists")
        return

    by_specimen: dict[str, str] = {}
    for entry in verdicts:
        if not isinstance(entry, dict) or "specimen" not in entry or "verdict" not in entry:
            result.errors.append("a verdict entry lacks 'specimen' or 'verdict'")
            return
        if entry["specimen"] in by_specimen:
            result.errors.append(f"duplicate verdict for {entry['specimen']!r}")
            return
        by_specimen[entry["specimen"]] = entry["verdict"]

    for entry in per_class:
        klass = entry.get("class", "?")
        caught, total = entry.get("caught"), entry.get("total")
        missed = entry.get("missed") or []

        if not isinstance(caught, int) or not isinstance(total, int):
            result.errors.append(f"{klass}: caught and total must be integers")
            continue

        if caught > total:
            result.errors.append(f"{klass}: caught {caught} exceeds total {total}")

        # Every specimen the document says was missed must be recorded `clean` in its own
        # verdict list — the cheapest possible cross-check, and the one that catches a
        # figure typed by hand.
        for specimen in missed:
            actual = by_specimen.get(specimen)
            if actual is None:
                result.errors.append(f"{klass}: missed names {specimen!r}, which has no verdict")
            elif actual != "clean":
                result.errors.append(
                    f"{klass}: {specimen!r} is listed as missed but its verdict is "
                    f"{actual!r}"
                )

        if len(missed) + caught != total:
            result.errors.append(
                f"{klass}: caught({caught}) + missed({len(missed)}) != total({total})"
            )

    fp = payload.get("false_positives") or {}
    for specimen in fp.get("specimens") or []:
        if by_specimen.get(specimen) != "flagged":
            result.errors.append(
                f"false_positives names {specimen!r}, whose verdict is "
                f"{by_specimen.get(specimen)!r} rather than 'flagged'"
            )


def validate_directory(directory: str | Path) -> list[ValidationResult]:
    """Validate every result document in a directory, sorted by name."""
    root = Path(directory)
    return [validate_document(p) for p in sorted(root.glob("*.json"))]
