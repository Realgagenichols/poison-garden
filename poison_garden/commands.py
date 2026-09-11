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

from poison_garden.cli import (
    EXIT_CORPUS_INVALID,
    EXIT_OK,
    EXIT_TOOL_ERROR,
    CorpusInvalid,
)
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


def cmd_run(
    corpus_root: str,
    scanner: str,
    out: str,
    scanner_name: str | None = None,
    flag_on: str = "nonzero",
    timeout: float = 120.0,
) -> int:
    """Run the user's scanner over the corpus and write a result document (R5-R10)."""
    from poison_garden.runner.execute import ExitCodeMapping, run_corpus
    from poison_garden.runner.target import ScannerTemplateError, parse_scanner
    from poison_garden.scoring.document import build_document
    from poison_garden.scoring.score import ScoringRefused

    try:
        corpus = load_corpus(corpus_root)
    except (CorpusError, ManifestError) as exc:
        raise CorpusInvalid(str(exc)) from exc

    try:
        command = parse_scanner(scanner)
    except ScannerTemplateError as exc:
        print(f"scanner template: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    mapping = ExitCodeMapping(flag_on=flag_on)
    results = run_corpus(corpus, command, mapping=mapping, timeout=timeout)

    try:
        document = build_document(
            corpus,
            results,
            scanner_name=scanner_name or command.program,
            mapping=mapping,
        )
    except ScoringRefused as exc:
        print(f"refusing to emit a result: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    written = document.write(out)

    errors = document.payload["errors"]
    for entry in document.payload["per_class"]:
        recall = entry["recall"]
        shown = "n/a" if recall is None else f"{recall:.0%}"
        print(f"  {entry['class']:<18} {entry['caught']}/{entry['total']}  {shown}")
    fp = document.payload["false_positives"]
    rate = fp["rate"]
    print(
        f"  false positives    {len(fp['specimens'])}/{fp['benign_total']}  "
        + ("n/a" if rate is None else f"{rate:.0%}")
    )
    if errors:
        # Prominent, per R7: an errored specimen left both numerator and denominator, so
        # the figures above describe fewer specimens than the corpus contains.
        print(f"\n  {len(errors)} specimen(s) ERRORED and were excluded: {errors}")
    print(f"\nwrote {written}")
    return EXIT_OK
