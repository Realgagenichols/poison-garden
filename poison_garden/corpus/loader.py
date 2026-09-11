"""Corpus discovery and loading.

Every failure is loud (cross-cutting P6). A specimen directory that cannot be loaded is an
error, never a skip: a silently-skipped specimen would shrink the denominator of every
score computed from the corpus, which is the quietest way for a benchmark to start lying.
"""

from __future__ import annotations

from pathlib import Path

from poison_garden.corpus.manifest import MANIFEST_NAME, parse_manifest
from poison_garden.corpus.models import Corpus, ManifestError, Specimen

CORPUS_VERSION_FILE = "CORPUS_VERSION"
DEFAULT_VERSION = "0.0.0-dev"

# Directories under the corpus root that are infrastructure, not specimens.
_NON_SPECIMEN_DIRS = frozenset({"__pycache__", ".git"})


class CorpusError(Exception):
    """The corpus as a whole is malformed."""


def load_corpus(root: str | Path) -> Corpus:
    """Load every specimen under `root`.

    Raises CorpusError if the root is missing, or if any specimen directory lacks a
    manifest. Raises ManifestError (via parse_manifest) for a malformed manifest.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise CorpusError(f"{root_path}: corpus root is not a directory")

    specimens: list[Specimen] = []
    seen_ids: dict[str, Path] = {}

    for entry in _specimen_dirs(root_path):
        manifest_path = entry / MANIFEST_NAME
        if not manifest_path.is_file():
            raise CorpusError(
                f"{entry}: specimen directory has no {MANIFEST_NAME}. "
                "An unlabelled directory is an error, not something to skip — skipping "
                "would silently shrink the corpus every score is computed against."
            )

        manifest = parse_manifest(manifest_path)

        if manifest.id != entry.name:
            raise CorpusError(
                f"{entry}: manifest id '{manifest.id}' does not match its directory name "
                f"'{entry.name}'. They must agree so a specimen can be found by either."
            )

        if manifest.id in seen_ids:
            raise CorpusError(
                f"{entry}: duplicate specimen id '{manifest.id}', already defined at "
                f"{seen_ids[manifest.id]}"
            )
        seen_ids[manifest.id] = entry

        specimen = Specimen(path=entry, manifest=manifest)
        if not specimen.entrypoint_path.is_file():
            raise CorpusError(
                f"{entry}: entrypoint '{manifest.entrypoint}' not found. A specimen is a "
                "runnable program (R1); a manifest without a server is not a specimen."
            )

        specimens.append(specimen)

    return Corpus(
        root=root_path,
        version=_read_version(root_path),
        # Sorted by id so the corpus is order-independent regardless of how the
        # filesystem enumerates directories (feeds the stable hash, R4).
        specimens=tuple(sorted(specimens, key=lambda s: s.id)),
    )


def _specimen_dirs(root: Path) -> list[Path]:
    """Candidate specimen directories, sorted. Underscore-prefixed dirs are shared code."""
    return sorted(
        entry
        for entry in root.iterdir()
        if entry.is_dir()
        and entry.name not in _NON_SPECIMEN_DIRS
        and not entry.name.startswith("_")
        and not entry.name.startswith(".")
    )


def _read_version(root: Path) -> str:
    version_path = root / CORPUS_VERSION_FILE
    if not version_path.is_file():
        return DEFAULT_VERSION
    version = version_path.read_text(encoding="utf-8").strip()
    if not version:
        raise CorpusError(f"{version_path}: corpus version file is empty")
    return version


__all__ = ["CorpusError", "ManifestError", "load_corpus"]
