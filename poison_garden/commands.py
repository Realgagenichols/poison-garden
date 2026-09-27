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


def parse_error_codes(raw: str) -> tuple[int, ...]:
    """Parse `--error-on`, failing at the boundary rather than on the first specimen (P6).

    `--flag-on banana` once spawned every specimen, scanned one, then died with a bare
    ValueError after the work was done. Same class of mistake, so the same treatment.
    """
    if not raw.strip():
        return ()
    codes: list[int] = []
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            codes.append(int(piece))
        except ValueError as exc:
            raise ValueError(
                f"--error-on takes comma-separated exit codes, got {piece!r}"
            ) from exc
    return tuple(codes)


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
    error_on: str = "",
    timeout: float = 120.0,
    sarif: bool = False,
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

    mapping = ExitCodeMapping(flag_on=flag_on, error_on=parse_error_codes(error_on))

    # Captured BEFORE the run: this is the corpus the figures describe.
    hash_before = corpus_hash(corpus)
    results = run_corpus(corpus, command, mapping=mapping, timeout=timeout, sarif=sarif)

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


def cmd_selftest(corpus_root: str, scanner: str, flag_on: str = "nonzero",
                 error_on: str = "", timeout: float = 120.0) -> int:
    """Check a scanner command is wired up, BEFORE spending a full run on it (R22).

    The gap this closes, found by putting the submission path in front of a reader who had
    not written it: the benign twins catch a scanner that flags *everything*, and nothing
    catches one that flags *nothing*. A wrapper whose exit codes are not plumbed through
    produces a schema-valid, CI-passing document reading 0 caught across every class and
    0 false positives — indistinguishable, in the artifact, from a scanner that genuinely
    detects nothing.

    So this is advisory and never a refusal on the full run. A scanner that truly detects
    nothing is entitled to publish that, and suppressing it would be the corpus editing
    someone's result. What this does is let the author tell the two apart in thirty seconds
    instead of after a 97-specimen run.

    It drives the smallest discriminating pair: specimens whose tell sits in plain ASCII in
    the served catalog, and benign twins. A correctly wired scanner distinguishes them. One
    that returns the same code for both is either unwired or has no rules at all, and the
    message says how to tell.
    """
    from poison_garden.corpus.loader import load_corpus
    from poison_garden.corpus.models import Class, Difficulty
    from poison_garden.runner.execute import ExitCodeMapping, Verdict, scan_one
    from poison_garden.runner.sandbox import sandbox
    from poison_garden.runner.target import ScannerTemplateError, parse_scanner

    try:
        command = parse_scanner(scanner)
    except ScannerTemplateError as exc:
        print(f"scanner template is unusable: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    corpus = load_corpus(corpus_root)
    mapping = ExitCodeMapping(flag_on=flag_on, error_on=parse_error_codes(error_on))

    # The easiest things in the corpus: overt, declaration-resident, plain ASCII. If a
    # scanner flags nothing here it will flag nothing anywhere.
    blatant = [
        s for s in corpus.malicious
        if s.difficulty is Difficulty.OVERT and s.manifest.declaration
        and not (s.classes & {Class.SCANNER_AWARE, Class.EGRESS})
    ][:3]
    twins = [s for s in corpus.benign][:2]
    if not blatant or not twins:
        print("corpus has no overt declaration specimens to probe with", file=sys.stderr)
        return EXIT_TOOL_ERROR

    print(f"probing {command.program} with {len(blatant)} blatant specimen(s) "
          f"and {len(twins)} benign twin(s)\n")
    results: dict[str, Verdict] = {}
    for specimen in blatant + twins:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp, sandbox(Path(tmp)) as (box, _sink):
            outcome = scan_one(specimen, command, box.env(), mapping, timeout=timeout)
        results[specimen.id] = outcome.verdict
        kind = "malicious" if specimen in blatant else "benign   "
        print(f"  {kind}  {str(outcome.verdict):<8} exit={outcome.exit_code}  {specimen.id}")

    flagged_bad = sum(results[s.id] is Verdict.FLAGGED for s in blatant)
    flagged_good = sum(results[s.id] is Verdict.FLAGGED for s in twins)
    errored = sum(v is Verdict.ERROR for v in results.values())

    print()
    if errored:
        print(f"{errored} specimen(s) errored. The scanner could not be asked about them, so "
              "a full run would exclude them from both numerator and denominator.",
              file=sys.stderr)
        return EXIT_TOOL_ERROR
    if flagged_bad == 0 and flagged_good == 0:
        print(
            "Your scanner flagged NOTHING, including specimens whose attack text is in "
            "plain ASCII in the served catalog.\n\n"
            "That is usually a wiring problem rather than a detection result. Check:\n"
            f"  - does `{command.program}` exit non-zero when it finds something?\n"
            "    (use --flag-on if it signals with a different code)\n"
            "  - does {target} reach it as a command to launch, not a path to read?\n"
            "    poison-garden substitutes an interpreter plus a script path as argv.\n\n"
            "A full run would still produce a valid document — it would simply read 0 "
            "everywhere, which is why this check exists.",
            file=sys.stderr,
        )
        return EXIT_TOOL_ERROR
    if flagged_bad == len(blatant) and flagged_good == len(twins):
        print("Your scanner flagged everything, including the benign twins. That scores "
              "full recall and a 100% false-positive rate. Check the exit-code mapping.",
              file=sys.stderr)
        return EXIT_TOOL_ERROR

    print(f"Looks wired: {flagged_bad}/{len(blatant)} blatant flagged, "
          f"{flagged_good}/{len(twins)} twins flagged.")
    print("Run the full corpus with `poison-garden run`.")
    return EXIT_OK


def cmd_validate_result(path: str) -> int:
    """Validate submitted result document(s). Never modifies them (R15)."""
    from poison_garden.leaderboard.validate import validate_directory, validate_document

    target = Path(path)
    if target.is_dir():
        results = validate_directory(target)
        if not results:
            print(f"no result documents in {target}", file=sys.stderr)
            return EXIT_OK
    elif target.is_file():
        results = [validate_document(target)]
    else:
        print(f"{target}: not found", file=sys.stderr)
        return EXIT_TOOL_ERROR

    for result in results:
        print(result.summary())

    rejected = [r for r in results if not r.ok]
    if rejected:
        print(
            f"\n{len(rejected)} of {len(results)} submission(s) rejected. "
            "Maintainers do not adjust a submitted figure — the author re-runs and "
            "resubmits.",
            file=sys.stderr,
        )
        return EXIT_CORPUS_INVALID
    print(f"\nall {len(results)} submission(s) valid")
    return EXIT_OK


def cmd_leaderboard(results_dir: str, out: str, check: bool = False) -> int:
    """Render the comparison page, or verify the committed one is current (R16)."""
    from poison_garden.leaderboard.render import is_stale, write

    if check:
        if is_stale(results_dir, out):
            print(
                f"{out} is stale or hand-edited. It is generated from {results_dir}/ and "
                "must never be written by hand — regenerate with `poison-garden "
                "leaderboard`.",
                file=sys.stderr,
            )
            return EXIT_CORPUS_INVALID
        print(f"{out} is current")
        return EXIT_OK

    written = write(results_dir, out)
    print(f"wrote {written}")
    return EXIT_OK
