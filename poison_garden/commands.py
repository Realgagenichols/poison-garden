"""CLI command implementations.

Exit codes are load-bearing and distinguishable (cross-cutting P55):

    0  the corpus is fine
    1  the corpus is invalid — a real, reportable finding ABOUT THE CORPUS
    2  poison-garden itself broke

Conflating 1 and 2 would let a crash read as "your corpus has a problem", which is the
milder result and the wrong one. R4's hash command has the same discipline.
"""

from __future__ import annotations

import sys

from poison_garden.cli import EXIT_CORPUS_INVALID, EXIT_OK, CorpusInvalid
from poison_garden.corpus.hash import corpus_hash
from poison_garden.corpus.loader import CorpusError, load_corpus
from poison_garden.corpus.models import ManifestError
from poison_garden.corpus.validate import validate_corpus


def cmd_validate(corpus_root: str) -> int:
    """Validate manifests and twin coverage (R3)."""
    try:
        corpus = load_corpus(corpus_root)
    except (CorpusError, ManifestError) as exc:
        raise CorpusInvalid(str(exc)) from exc

    report = validate_corpus(corpus)
    print(report.summary())

    if not report.ok:
        # A vacuous corpus and a twin-less corpus are both invalid, but for different
        # reasons — the summary already distinguishes them in words.
        return EXIT_CORPUS_INVALID
    return EXIT_OK


def cmd_hash(corpus_root: str) -> int:
    """Print the corpus version and content hash (R4)."""
    try:
        corpus = load_corpus(corpus_root)
    except (CorpusError, ManifestError) as exc:
        raise CorpusInvalid(str(exc)) from exc

    print(f"version  {corpus.version}")
    print(f"hash     {corpus_hash(corpus)}")
    print(f"specimens {len(corpus)}", file=sys.stderr)
    return EXIT_OK
