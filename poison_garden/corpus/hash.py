"""Corpus content hashing — R4.

Two runs are only comparable when they name the same corpus, so the hash must be a
function of the corpus bytes and nothing else: not the filesystem's iteration order, not
absolute paths, not mtimes.

Framing is explicit. Every record is length-prefixed before hashing so that a specimen
named `a` containing `b` cannot collide with one named `ab` containing nothing — the
classic framing ambiguity (cross-cutting P13: writer and reader share one framing
definition).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from poison_garden.corpus.models import Corpus, Specimen

HASH_ALGORITHM = "sha256"
_DIGEST_PREFIX = "sha256:"

# Files inside a specimen directory that are not part of its identity.
_IGNORED_NAMES = frozenset({".DS_Store"})
_IGNORED_DIRS = frozenset({"__pycache__"})


def corpus_hash(corpus: Corpus) -> str:
    """Stable content hash over every specimen in the corpus.

    Independent of directory iteration order: specimens are sorted by id and each
    specimen's files are sorted by their path relative to the specimen directory.
    """
    digest = hashlib.new(HASH_ALGORITHM)
    _feed(digest, b"poison-garden-corpus-v1")

    for specimen in sorted(corpus.specimens, key=lambda s: s.id):
        _feed(digest, specimen.id.encode("utf-8"))
        for rel_path, content in _specimen_files(specimen):
            _feed(digest, rel_path.encode("utf-8"))
            _feed(digest, content)

    return _DIGEST_PREFIX + digest.hexdigest()


def specimen_hash(specimen: Specimen) -> str:
    """Content hash for a single specimen, using the same framing as `corpus_hash`."""
    digest = hashlib.new(HASH_ALGORITHM)
    _feed(digest, b"poison-garden-specimen-v1")
    _feed(digest, specimen.id.encode("utf-8"))
    for rel_path, content in _specimen_files(specimen):
        _feed(digest, rel_path.encode("utf-8"))
        _feed(digest, content)
    return _DIGEST_PREFIX + digest.hexdigest()


def _feed(digest, chunk: bytes) -> None:
    """Length-prefix every record so concatenation cannot be ambiguous."""
    digest.update(str(len(chunk)).encode("ascii"))
    digest.update(b":")
    digest.update(chunk)


def _specimen_files(specimen: Specimen) -> list[tuple[str, bytes]]:
    """Every file in a specimen directory, sorted by relative POSIX path."""
    out: list[tuple[str, bytes]] = []
    for path in sorted(specimen.path.rglob("*")):
        if path.is_dir():
            continue
        if path.name in _IGNORED_NAMES:
            continue
        if any(part in _IGNORED_DIRS for part in path.parts):
            continue
        rel = path.relative_to(specimen.path).as_posix()
        out.append((rel, path.read_bytes()))
    return out


class CorpusMismatch(Exception):
    """Two result documents name different corpora and cannot be compared (R4)."""


def refuse_mismatch(hash_a: str, hash_b: str, *, label_a: str = "a", label_b: str = "b") -> None:
    """Refuse a comparison across two different corpora, naming BOTH hashes (R4).

    Wired into result-document comparison in M2. Kept here because the rule belongs to the
    corpus, not to the document format.
    """
    if hash_a != hash_b:
        raise CorpusMismatch(
            "refusing to compare results from different corpora: "
            f"{label_a}={hash_a} vs {label_b}={hash_b}. "
            "Scores are only comparable within one corpus version."
        )


def corpus_path_hash(root: str | Path) -> str:
    """Convenience: load and hash in one step (used by the CLI)."""
    from poison_garden.corpus.loader import load_corpus

    return corpus_hash(load_corpus(root))
