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
    """Stable content hash over everything that determines what the corpus SERVES.

    Independent of directory iteration order: specimens are sorted by id and each
    specimen's files are sorted by their path relative to the specimen directory.

    **Shared root files are hashed too, and that is not incidental.** `specimens/_base.py`
    is the harness every specimen imports to produce its `tools/list` response. Hashing
    only specimen directories left it out, so editing `_base.py` — even in a way that
    stopped every hidden-content specimen serving anything hidden — produced a
    byte-identical corpus hash. Two result documents would then cite the same hash while
    describing materially different corpora, which is exactly the comparison R4 exists to
    make safe.
    """
    digest = hashlib.new(HASH_ALGORITHM)
    _feed(digest, b"poison-garden-corpus-v2")

    # Shared harness and metadata first, under their own record tag so a file named
    # `_base.py` at the root can never collide with one inside a specimen.
    _feed(digest, b"shared")
    for rel_path, content in _shared_root_files(corpus.root):
        _feed(digest, rel_path.encode("utf-8"))
        _feed(digest, content)

    _feed(digest, b"specimens")
    for specimen in sorted(corpus.specimens, key=lambda s: s.id):
        _feed(digest, specimen.id.encode("utf-8"))
        for rel_path, content in _specimen_files(specimen):
            _feed(digest, rel_path.encode("utf-8"))
            _feed(digest, content)

    return _DIGEST_PREFIX + digest.hexdigest()


def _shared_root_files(root: Path) -> list[tuple[str, bytes]]:
    """Files at the corpus root that every specimen depends on.

    Everything directly under the root that is not a specimen directory: the `_`-prefixed
    harness modules the loader deliberately skips, plus `CORPUS_VERSION`.
    """
    out: list[tuple[str, bytes]] = []
    for path in sorted(root.iterdir()):
        if path.is_dir():
            # Underscore-prefixed dirs are shared code the loader skips; walk them.
            if path.name.startswith("_") and path.name not in _IGNORED_DIRS:
                for nested in sorted(path.rglob("*")):
                    if nested.is_file() and _is_hashable(nested):
                        out.append((nested.relative_to(root).as_posix(), nested.read_bytes()))
            continue
        if _is_hashable(path):
            out.append((path.name, path.read_bytes()))
    return out


def _is_hashable(path: Path) -> bool:
    if path.name in _IGNORED_NAMES:
        return False
    return not any(part in _IGNORED_DIRS for part in path.parts)


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
