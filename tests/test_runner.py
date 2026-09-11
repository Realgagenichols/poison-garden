"""Runner and scoring tests — R5–R10, S3.

Every guard here is falsified: the M1 review found three separate tests that could not fail,
two of them written specifically to prevent vacuity.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
from helpers import SPECIMENS

from poison_garden.corpus.hash import CorpusMismatch
from poison_garden.corpus.loader import load_corpus
from poison_garden.corpus.models import Class
from poison_garden.runner.execute import (
    ExitCodeMapping,
    SpecimenResult,
    Verdict,
    run_corpus,
)
from poison_garden.runner.target import (
    PLACEHOLDER,
    ScannerTemplateError,
    parse_scanner,
    target_argv,
)
from poison_garden.scoring.document import (
    FORBIDDEN_FIELDS,
    build_document,
    compare,
    composite_fields_in,
)
from poison_garden.scoring.score import (
    ClassScore,
    Scores,
    ScoringRefused,
    score_run,
)


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


def _stub_scanner(tmp_path: Path, body: str, name: str = "stub.py") -> Path:
    """A fake scanner: reads argv, exits with a code we control."""
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


# --- R5: target construction -------------------------------------------------------------


def test_template_expands_target_to_multiple_argv_elements(corpus):
    """R5 scenario: `{target}` is an interpreter AND a path, not one token."""
    command = parse_scanner("mcp-scan {target}")
    specimen = corpus.specimens[0]
    argv = command.argv_for(specimen)

    assert argv[0] == "mcp-scan"
    assert argv[1:] == target_argv(specimen)
    assert len(argv) == 3, "target must expand in place, not collapse into one token"


def test_template_without_placeholder_is_refused():
    """Running it would scan nothing, once per specimen, and report a full verdict set."""
    with pytest.raises(ScannerTemplateError) as exc:
        parse_scanner("mcp-scan --all")
    assert PLACEHOLDER in str(exc.value)


def test_empty_and_unbalanced_templates_are_refused():
    with pytest.raises(ScannerTemplateError):
        parse_scanner("")
    with pytest.raises(ScannerTemplateError):
        parse_scanner("scanner 'unbalanced {target}")


def test_paths_with_spaces_survive_substitution(tmp_corpus):
    """No shell means no re-parsing: a space in a path stays one argv element (P4)."""
    root = tmp_corpus(
        [
            {"id": "injection-poisoned", "declaration": ["injection"]},
            {"id": "injection-twin", "twin_for": ["injection"]},
        ],
        root_name="corpus with spaces",
    )
    specimen = load_corpus(root).specimens[0]
    argv = parse_scanner("scan {target}").argv_for(specimen)
    assert " " in argv[-1]
    assert len(argv) == 3, "a space must not split the path into extra argv elements"


def test_embedded_placeholder_keeps_every_target_element(corpus):
    argv = parse_scanner("scan --server={target}").argv_for(corpus.specimens[0])
    assert len(argv) == 2
    assert argv[1].startswith("--server=")
    assert argv[1].endswith(".py")


# --- R6: verdict from exit code ----------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [(0, Verdict.CLEAN), (1, Verdict.FLAGGED), (2, Verdict.FLAGGED), (-9, Verdict.ERROR)],
)
def test_exit_code_maps_to_verdict(code: int, expected: Verdict):
    assert ExitCodeMapping().verdict_for(code) is expected


def test_signal_death_is_error_not_flagged():
    """A killed scanner reached no conclusion; neither do we (R6/R7)."""
    assert ExitCodeMapping().verdict_for(-15) is Verdict.ERROR


def test_configurable_threshold():
    mapping = ExitCodeMapping(flag_on="2")
    assert mapping.verdict_for(1) is Verdict.CLEAN
    assert mapping.verdict_for(2) is Verdict.FLAGGED
    assert "2" in mapping.describe()


def test_mapping_description_is_recorded(corpus):
    results = [SpecimenResult(s.id, Verdict.CLEAN, 0) for s in corpus.specimens]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())
    assert "exit != 0" in doc.payload["scanner"]["exit_code_mapping"]


def test_verdict_actually_follows_the_scanner_exit_code(tmp_path, corpus):
    """FALSIFICATION (P31): flip the stub's exit code, the verdicts must flip."""
    flagger = _stub_scanner(tmp_path, "import sys; sys.exit(1)", "flag.py")
    cleaner = _stub_scanner(tmp_path, "import sys; sys.exit(0)", "clean.py")

    flagged = run_corpus(corpus, parse_scanner(f"{sys.executable} {flagger} {PLACEHOLDER}"))
    cleaned = run_corpus(corpus, parse_scanner(f"{sys.executable} {cleaner} {PLACEHOLDER}"))

    assert {r.verdict for r in flagged} == {Verdict.FLAGGED}
    assert {r.verdict for r in cleaned} == {Verdict.CLEAN}


# --- R7: error isolation ------------------------------------------------------------------


def test_broken_specimen_is_error_and_does_not_abort_the_run(tmp_corpus, tmp_path):
    """R7 scenario: it is reported as error, excluded, and the others still score."""
    root = tmp_corpus(
        [
            {"id": "good-poisoned", "declaration": ["injection"],
             "server_text": _echo_server()},
            {"id": "good-twin", "twin_for": ["injection"], "server_text": _echo_server()},
            {"id": "broken", "declaration": ["hygiene"],
             "server_text": "import sys; sys.exit(1)"},
            {"id": "broken-twin", "twin_for": ["hygiene"], "server_text": _echo_server()},
        ]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    results = run_corpus(corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    by_id = {r.specimen_id: r for r in results}
    assert by_id["broken"].verdict is Verdict.ERROR
    assert by_id["broken"].error_reason is not None
    assert by_id["good-poisoned"].verdict is Verdict.FLAGGED, "run must not abort"

    scores = score_run(corpus, results)
    hygiene = next(c for c in scores.per_class if c.klass is Class.HYGIENE)
    assert hygiene.total == 0, "errored specimen must leave the denominator"
    assert hygiene.recall is None, "no recall exists for a class with nothing scorable"
    assert "broken" in scores.errored

    # R7 says errors are reported PROMINENTLY. These are the fields that discharge that,
    # and all three could be hardwired empty with the whole suite green.
    assert hygiene.errored == ("broken",), "per-class errored list is not populated"
    assert scores.benign_errored == (), "benign_errored must reflect the actual run"


def test_missed_list_names_the_specimens_that_were_missed(corpus):
    """`missed` is how a document says which specimens a scanner failed to catch.

    It could be hardwired to `()` with every test green — a scanner could then publish
    recall 0.5 with `"missed": []` and this corpus's own suite would certify it.
    """
    target = next(s for s in corpus.malicious if len(s.classes) == 1)
    klass = next(iter(target.classes))

    results = [
        SpecimenResult(
            s.id,
            Verdict.CLEAN if (s.is_benign or s.id == target.id) else Verdict.FLAGGED,
            1,
        )
        for s in corpus.specimens
    ]
    scores = score_run(corpus, results)
    entry = next(c for c in scores.per_class if c.klass is klass)

    assert entry.missed == (target.id,), f"missed list did not name {target.id}"
    for other in scores.per_class:
        if other.klass is not klass:
            assert target.id not in other.missed


def test_benign_errored_is_populated_when_a_twin_breaks(tmp_corpus, tmp_path):
    root = tmp_corpus(
        [
            {"id": "p", "declaration": ["injection"], "server_text": _echo_server()},
            {"id": "t-ok", "twin_for": ["injection"], "server_text": _echo_server()},
            {"id": "t-broken", "twin_for": ["injection"],
             "server_text": "import sys; sys.exit(1)"},
        ]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(0)")
    results = run_corpus(corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))
    scores = score_run(corpus, results)

    assert scores.benign_errored == ("t-broken",)
    assert scores.benign_total == 1, "a broken twin must leave the FP denominator"


def test_error_and_clean_are_distinguishable(corpus):
    """P55: two empties are two findings."""
    results = [
        SpecimenResult("a", Verdict.CLEAN, 0),
        SpecimenResult("b", Verdict.ERROR, None, error_reason="specimen-no-catalog"),
    ]
    assert results[0].scored is True
    assert results[1].scored is False
    assert results[0].verdict != results[1].verdict


def test_all_errored_run_does_not_report_perfect_recall(tmp_corpus, tmp_path):
    """P58: 0/0 must be 'no measurement', never 100%."""
    root = tmp_corpus(
        [
            {"id": "broken-a", "declaration": ["injection"],
             "server_text": "import sys; sys.exit(1)"},
            {"id": "twin-a", "twin_for": ["injection"], "server_text": _echo_server()},
        ]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    results = run_corpus(corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    scores = score_run(corpus, results)
    injection = next(c for c in scores.per_class if c.klass is Class.INJECTION)
    assert injection.recall is None
    assert injection.recall != 1.0


def test_scoring_refuses_a_partial_run(corpus):
    with pytest.raises(ScoringRefused, match="no result for specimen"):
        score_run(corpus, [SpecimenResult(corpus.specimens[0].id, Verdict.CLEAN, 0)])


# --- R9 / R10: scoring --------------------------------------------------------------------


def test_scoring_refuses_recall_without_false_positives(tmp_corpus, tmp_path):
    """R9 scenario: a malicious-only run cannot produce a publishable document."""
    root = tmp_corpus(
        [{"id": "only-poisoned", "declaration": ["injection"], "server_text": _echo_server()}]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    results = run_corpus(corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    with pytest.raises(ScoringRefused, match="false-positive"):
        score_run(corpus, results)


def test_dual_class_specimen_counts_toward_both_classes(corpus):
    """A missed dual-class specimen must appear under EVERY class it carries.

    The previous version set every malicious specimen to FLAGGED, so `missed` was empty
    for every class and the assertion was `id not in ()` — true by construction, whatever
    `score_run` did. A mutation attributing a dual-class specimen to only its
    alphabetically-first class passed the whole suite.

    Flipping the dual-class specimen to CLEAN is what makes this discriminating: a scanner
    that misses it would otherwise publish a document naming it under `injection` while
    silently omitting it from `hidden-content`, where it would read as a clean catch.
    """
    dual = [s for s in corpus.malicious if len(s.classes) > 1]
    assert dual, "corpus has no dual-class specimen — this test cannot discriminate (P48)"
    target = dual[0]
    assert len(target.classes) >= 2

    results = [
        SpecimenResult(
            s.id,
            Verdict.CLEAN if (s.is_benign or s.id == target.id) else Verdict.FLAGGED,
            1,
        )
        for s in corpus.specimens
    ]
    scores = score_run(corpus, results)

    for klass in target.classes:
        entry = next(c for c in scores.per_class if c.klass is klass)
        # Set equality, not membership: `in` cannot see N-1 of the other entries change
        # (P105), and the defect being guarded is omission from ONE class.
        assert set(entry.missed) == {target.id}, (
            f"{klass.value}: expected {target.id} missed, got {entry.missed}"
        )
        attackers = [s for s in corpus.malicious if klass in s.classes]
        assert entry.total == len(attackers), (
            f"{klass.value}: dual-class specimen missing from the denominator"
        )


def test_document_refuses_to_emit_without_a_false_positive_rate(corpus):
    """C5 regression: the refusal belongs at the EMITTER, which is what R9 names.

    Passing a pre-computed `Scores` used to skip the check in `score_run` entirely,
    producing a schema-valid document with 100% recall on all six classes and
    `"rate": null` — the flattering half-truth R9 exists to forbid.
    """
    results = [
        SpecimenResult(
            s.id,
            Verdict.ERROR if s.is_benign else Verdict.FLAGGED,
            None if s.is_benign else 1,
        )
        for s in corpus.specimens
    ]

    # The bypass is passing a PRE-COMPUTED Scores, which skips score_run's own refusal.
    # Calling build_document without `scores=` would be caught by score_run instead, so
    # this test would pass with the emitter guard deleted — which is exactly what the
    # first version of it did (verified: guard removed, 358 still green).
    hand_built = Scores(
        per_class=tuple(
            ClassScore(
                klass=k,
                caught=len([s for s in corpus.malicious if k in s.classes]),
                total=len([s for s in corpus.malicious if k in s.classes]),
                missed=(),
                errored=(),
            )
            for k in sorted(corpus.classes_present, key=lambda c: c.value)
        ),
        false_positives=(),
        benign_total=0,  # every twin errored -> no control at all
        benign_errored=tuple(sorted(s.id for s in corpus.benign)),
        errored=tuple(sorted(s.id for s in corpus.benign)),
    )
    assert hand_built.false_positive_rate is None, "precondition: no FP rate to report"

    with pytest.raises(ScoringRefused, match="false-positive rate"):
        build_document(corpus, results, "cheat", ExitCodeMapping(), scores=hand_built)


def test_flag_on_is_validated_at_construction(corpus):
    """W1: `int(flag_on)` used to run mid-scan, after every specimen had been spawned."""
    with pytest.raises(ValueError, match="--flag-on"):
        ExitCodeMapping(flag_on="banana")
    ExitCodeMapping(flag_on="nonzero")
    ExitCodeMapping(flag_on="2")


def test_flipping_one_verdict_moves_exactly_one_class(corpus):
    """P47: prove recall is DERIVED by mutating the source verdict."""
    target = next(s for s in corpus.malicious if len(s.classes) == 1)
    klass = next(iter(target.classes))

    def scores_with(verdict_for_target: Verdict):
        results = [
            SpecimenResult(
                s.id,
                verdict_for_target if s.id == target.id
                else (Verdict.CLEAN if s.is_benign else Verdict.FLAGGED),
                1,
            )
            for s in corpus.specimens
        ]
        return {c.klass: c.caught for c in score_run(corpus, results).per_class}

    before = scores_with(Verdict.FLAGGED)
    after = scores_with(Verdict.CLEAN)
    changed = {k for k in before if before[k] != after[k]}
    assert changed == {klass}, f"expected only {klass.value} to move, got {changed}"


def test_forbidden_field_list_is_pinned():
    """The R10 guard iterated this set, so emptying it made the guard pass for free.

    Measured: with `FORBIDDEN_FIELDS = frozenset()` and a `"score"` injected into the
    payload, all 351 tests passed and every published document would have carried a
    headline number. Pinning the set exactly means removing an entry is a deliberate edit
    to this line, not a silent nullification (P104 — put the vacuity guard inside the
    assertion it protects).
    """
    assert sorted(FORBIDDEN_FIELDS) == [
        "grade",
        "overall",
        "rank",
        "rating",
        "score",
        "total_score",
    ]


def test_document_has_no_composite_score(corpus):
    """R10 scenario."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())
    assert composite_fields_in(doc.payload) == []


def test_the_composite_check_actually_fires(corpus):
    """POSITIVE CONTROL: inject a headline number, the check must catch it."""
    results = [SpecimenResult(s.id, Verdict.CLEAN, 0) for s in corpus.specimens]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    for injected in ("score", "overall_recall", "final_grade", "rank"):
        poisoned = dict(doc.payload)
        poisoned[injected] = 0.93
        assert composite_fields_in(poisoned) == [injected], (
            f"a field named {injected!r} would ship undetected"
        )


def test_composite_check_reaches_nested_fields(corpus):
    """A headline number hidden one level down must still be caught."""
    results = [SpecimenResult(s.id, Verdict.CLEAN, 0) for s in corpus.specimens]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())
    poisoned = dict(doc.payload)
    poisoned["corpus"] = {**poisoned["corpus"], "score": 1.0}
    assert composite_fields_in(poisoned) == ["corpus.score"]


def test_document_figures_are_recomputable_from_its_own_verdicts(corpus):
    """P26: two artifacts that must correspond need the correspondence asserted."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    verdicts = {v["specimen"]: v["verdict"] for v in doc.payload["verdicts"]}
    for entry in doc.payload["per_class"]:
        klass = Class(entry["class"])
        attackers = [s.id for s in corpus.malicious if klass in s.classes]
        recomputed = sum(1 for sid in attackers if verdicts[sid] == "flagged")
        assert recomputed == entry["caught"], f"{entry['class']}: stated figure disagrees"


# --- R4: comparison across corpora ---------------------------------------------------------


def test_comparing_different_corpora_is_refused(corpus):
    """R4 scenario, completed — M1 built the guard, this is its consumer."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    a = build_document(corpus, results, "stub", ExitCodeMapping())
    b = build_document(corpus, results, "stub", ExitCodeMapping())
    b.payload["corpus"]["hash"] = "sha256:" + "0" * 64

    with pytest.raises(CorpusMismatch) as exc:
        compare(a, b, label_a="ours", label_b="theirs")
    assert a.corpus_hash in str(exc.value)
    assert "0" * 64 in str(exc.value)


def test_comparing_the_same_corpus_is_allowed(corpus):
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    a = build_document(corpus, results, "stub", ExitCodeMapping())
    compare(a, a)  # must not raise


# --- S3: the document must carry no secrets -------------------------------------------------


def test_document_carries_no_canary_token_or_env_value(corpus, tmp_path):
    """S3, asserted against a REAL run's canaries rather than a literal.

    The specimens are pointed at a scanner that dumps everything it can see; if any of that
    reached the document, this reddens.
    """
    spy = _stub_scanner(
        tmp_path,
        """
        import json, os, sys
        print(json.dumps({"argv": sys.argv, "env": dict(os.environ)}))
        sys.exit(1)
        """,
        "spy.py",
    )
    results = run_corpus(corpus, parse_scanner(f"{sys.executable} {spy} {PLACEHOLDER}"))
    doc = build_document(corpus, results, "spy", ExitCodeMapping())
    rendered = doc.to_json()

    assert "PG-DECOY-" not in rendered, "a decoy canary reached the result document (S3)"
    assert "BEGIN OPENSSH" not in rendered
    assert str(Path.home()) not in rendered, "the real home path reached the document"
    assert str(spy) not in rendered, "the scanner command line reached the document"


def test_scanner_identity_is_recorded_not_the_command_line(corpus):
    """A template can contain an API token, and this document is meant to be published."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "mcp-scan", ExitCodeMapping())
    assert doc.payload["scanner"]["name"] == "mcp-scan"
    assert "token" not in doc.to_json().lower()


def _echo_server() -> str:
    """A minimal working specimen server, independent of the shared harness."""
    return textwrap.dedent(
        '''
        import json, sys
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if msg.get("id") is None:
                continue
            if msg.get("method") == "initialize":
                r = {"protocolVersion": "2025-06-18", "capabilities": {},
                     "serverInfo": {"name": "stub", "version": "1.0"}}
            elif msg.get("method") == "tools/list":
                r = {"tools": [{"name": "noop", "description": "Does nothing.",
                                "inputSchema": {"type": "object", "properties": {}}}]}
            else:
                r = {}
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": r}) + "\\n")
            sys.stdout.flush()
        '''
    )
