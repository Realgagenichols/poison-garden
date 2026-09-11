"""CLI command implementations.

Exit codes are load-bearing and distinguishable (cross-cutting P55):

    0  the corpus is fine
    1  the corpus is invalid — a real, reportable finding ABOUT THE CORPUS
    2  poison-garden itself broke
    3  poison-garden refused to emit a result, correctly

Conflating 1 and 2 would let a crash read as "your corpus has a problem", which is the
milder result and the wrong one. 3 is separate for the mirror reason: a refusal is the tool
working as specified — R9 declining to publish recall with no false-positive control — and
reporting it as 2 tells CI the tool crashed when it did its job.
"""

from __future__ import annotations

import sys
from pathlib import Path

from poison_garden.cli import (
    EXIT_CORPUS_INVALID,
    EXIT_OK,
    EXIT_REFUSED,
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

    # Captured BEFORE the run: this is the corpus the figures describe.
    hash_before = corpus_hash(corpus)
    results = run_corpus(corpus, command, mapping=mapping, timeout=timeout)

    try:
        document = build_document(
            corpus,
            results,
            # basename only: `command.program` is the template's argv[0] verbatim, so a
            # scanner installed at ~/.local/bin/mcp-scan would publish the user's username
            # and home path in a document meant to be committed to a public repo (S3).
            scanner_name=scanner_name or Path(command.program).name,
            mapping=mapping,
            corpus_hash_before_run=hash_before,
        )
    except ScoringRefused as exc:
        # Exit 3, not 2: the tool did exactly what R9 requires. CI must be able to tell
        # this from a crash.
        print(f"refusing to emit a result: {exc}", file=sys.stderr)
        return EXIT_REFUSED

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
