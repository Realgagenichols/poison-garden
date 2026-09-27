"""Runner and scoring tests — R5–R10, S3.

Every guard here is falsified: the M1 review found three separate tests that could not fail,
two of them written specifically to prevent vacuity.
"""

from __future__ import annotations

import json
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
    unexpected_fields_in,
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


def test_error_and_clean_are_distinguishable():
    """P55: two empties are two findings.

    The `!=` assertion this used to carry compared two enum literals written three lines
    above — guaranteed by construction, and an instance of the rule that a test supplying
    the value under test cannot observe anything about it. What actually matters is that
    `scored` separates them, since that is the predicate scoring keys on.
    """
    clean = SpecimenResult("a", Verdict.CLEAN, 0)
    errored = SpecimenResult("b", Verdict.ERROR, None, error_reason="specimen-no-catalog")

    assert clean.scored is True
    assert errored.scored is False
    # The distinction must survive the round-trip into the published document.
    assert str(clean.verdict) == "clean"
    assert str(errored.verdict) == "error"


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
        "aggregate",
        "composite",
        "grade",
        "index",
        "rating",
        "score",
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

    for injected in ("score", "class_scores", "final_grade", "composite", "spearman_index"):
        poisoned = dict(doc.payload)
        poisoned[injected] = 0.93
        assert composite_fields_in(poisoned) == [injected], (
            f"a field named {injected!r} would ship undetected"
        )
        # And the schema guard must catch it too, by a different mechanism.
        assert injected in unexpected_fields_in(poisoned)


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
    """A template can contain an API token, and this document is meant to be published.

    Asserts the SHAPE of what gets recorded: an identity and a mapping, nothing derived
    from the invocation. That is falsifiable — adding any key under `scanner` reddens it —
    and it is the property that actually holds the guarantee, because `build_document`
    never receives the command line in the first place.

    It previously asserted `"token" not in doc.to_json().lower()`, a keyword grep over the
    whole document. That broke the moment a specimen was named
    `behaviour-twin-session-token-descriptions`, and would break on any specimen whose
    subject matter is tokens — the same defect as a `\\bpath\\b` rule matching
    `from pathlib import Path`. It matched the topic, and the corpus legitimately contains
    the topic.

    The end-to-end version of this — a real run whose scanner path must not reach the
    document — is `test_document_carries_no_canary_token_or_env_value` above. Restating it
    here with a literal this test supplies itself would assert nothing: a value nothing ever
    writes is absent by construction.
    """
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "mcp-scan", ExitCodeMapping())

    assert doc.payload["scanner"]["name"] == "mcp-scan"
    assert set(doc.payload["scanner"]) == {"name", "exit_code_mapping"}, (
        "a new key appeared under `scanner`; anything derived from the command line is a "
        "publication risk (S3)"
    )


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


# --- W2: a served catalog is a served catalog, even from a long-lived specimen -----------


def _long_lived_specimen(tmp_path: Path) -> Path:
    """Answers both requests correctly, then keeps serving — M3's R13/R14 shape."""
    d = tmp_path / "longlived"
    d.mkdir(parents=True, exist_ok=True)
    (d / "server.py").write_text(
        _echo_server() + "\nimport time\ntime.sleep(300)\n", encoding="utf-8"
    )
    (d / "manifest.toml").write_text(
        'id = "longlived"\nsummary = "serves then stays alive"\ndeclaration = ["injection"]\n',
        encoding="utf-8",
    )
    return d


def test_preflight_accepts_a_specimen_that_serves_then_stays_alive(tmp_path: Path):
    """REGRESSION (W2): `subprocess.run(input=...)` reads stdout to EOF, so it waits for
    the process to EXIT, not for the catalog to arrive.

    A specimen that answers `initialize` and `tools/list` correctly and then keeps serving
    used to time out and be classified `error` — leaving both numerator and denominator
    despite having done nothing R7 describes. Latent while every shipped specimen exits on
    stdin close; not latent once M3 lands multi-enumeration servers.
    """
    from poison_garden.corpus.models import Manifest, Specimen
    from poison_garden.runner.execute import preflight

    d = _long_lived_specimen(tmp_path)
    specimen = Specimen(
        path=d, manifest=Manifest(id="longlived", summary="x", entrypoint="server.py")
    )
    assert preflight(specimen, {"PATH": "/usr/bin:/bin"}, timeout=5.0) is None


def test_preflight_still_rejects_a_specimen_that_serves_nothing(tmp_path: Path):
    """Control (P21): the W2 fix must not turn every timeout into a pass."""
    from poison_garden.corpus.models import Manifest, Specimen
    from poison_garden.runner.execute import preflight

    d = tmp_path / "silent"
    d.mkdir(parents=True, exist_ok=True)
    (d / "server.py").write_text("import time\ntime.sleep(300)\n", encoding="utf-8")
    specimen = Specimen(
        path=d, manifest=Manifest(id="silent", summary="x", entrypoint="server.py")
    )
    assert preflight(specimen, {"PATH": "/usr/bin:/bin"}, timeout=3.0) == (
        "specimen-handshake-timeout"
    )


# --- W3 / W4: cmd_run had no test of any kind -------------------------------------------


def test_cmd_run_writes_a_valid_document(tmp_path: Path, capsys):
    """W4: `grep cmd_run tests/` returned zero hits. The CLI path a vendor actually runs."""
    from poison_garden.commands import cmd_run

    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    out = tmp_path / "result.json"
    code = cmd_run(
        corpus_root=str(SPECIMENS),
        scanner=f"{sys.executable} {stub} {PLACEHOLDER}",
        out=str(out),
        scanner_name="unit-test",
    )
    capsys.readouterr()

    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["scanner"]["name"] == "unit-test"
    # Derived from the corpus, never a literal. Hardcoding 26 meant the assertion decayed
    # into a corpus-size check that had to be edited every time a specimen was added — and
    # it says nothing about the run, because a document missing half its verdicts with the
    # right total would pass. `score_run` already refuses a document whose verdicts and
    # corpus disagree; what belongs here is that every specimen got one (P86).
    expected_ids = {s.id for s in load_corpus(SPECIMENS).specimens}
    assert {v["specimen"] for v in payload["verdicts"]} == expected_ids
    assert payload["errors"] == []


def test_cmd_run_does_not_publish_the_scanner_path(tmp_path: Path, capsys):
    """REGRESSION (W3): scanner_name defaulted to argv[0] verbatim, absolute path included.

    A scanner at ~/.local/bin/mcp-scan would have published the username and home path into
    a document meant to be committed to a public repo. The existing S3 test could not catch
    this: it passes an explicit scanner_name, so the default branch was never exercised and
    its `str(spy) not in rendered` assertion was true by construction.
    """
    from poison_garden.commands import cmd_run

    bindir = tmp_path / "home-ish" / ".local" / "bin"
    bindir.mkdir(parents=True)
    # Genuinely executable, so argv[0] can BE the absolute path — which is the whole
    # point: a scanner installed at ~/.local/bin/<name> is the realistic case.
    stub = bindir / "my-scanner.py"
    stub.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n", encoding="utf-8")
    stub.chmod(0o755)
    out = tmp_path / "result.json"

    cmd_run(
        corpus_root=str(SPECIMENS),
        scanner=f"{stub} {PLACEHOLDER}",  # argv[0] is an ABSOLUTE path
        out=str(out),
    )
    capsys.readouterr()

    rendered = out.read_text(encoding="utf-8")
    payload = json.loads(rendered)
    assert payload["scanner"]["name"] == "my-scanner.py", "expected the basename only"
    assert str(bindir) not in rendered, "the scanner's directory reached the document"
    assert str(tmp_path) not in rendered


def test_cmd_run_rejects_a_template_without_a_placeholder(tmp_path: Path, capsys):
    from poison_garden.commands import cmd_run

    code = cmd_run(
        corpus_root=str(SPECIMENS),
        scanner="scanner --all",
        out=str(tmp_path / "never.json"),
    )
    assert code == 2
    assert "target" in capsys.readouterr().err
    assert not (tmp_path / "never.json").exists(), "no document on a refused template"


# --- W5: a refusal is not a crash, and R7's summary must actually name the specimen ------


def test_refusal_and_crash_and_usage_have_distinct_exit_codes(tmp_path: Path, capsys):
    """P55: three outcomes cannot share two integers.

    A refusal is poison-garden working exactly as R9 specifies. Reporting it as
    EXIT_TOOL_ERROR told CI the tool crashed when it had done its job, and left "your
    scanner errored every specimen" indistinguishable from "poison-garden fell over".
    """
    from poison_garden.cli import EXIT_REFUSED
    from poison_garden.commands import cmd_run

    # A scanner that is not executable -> every specimen errors -> nothing scorable.
    dud = tmp_path / "not-executable.py"
    dud.write_text("import sys; sys.exit(0)\n", encoding="utf-8")
    refused = cmd_run(
        corpus_root=str(SPECIMENS),
        scanner=f"{dud} {PLACEHOLDER}",
        out=str(tmp_path / "refused.json"),
    )
    err = capsys.readouterr().err
    assert refused == EXIT_REFUSED
    assert "refusing to emit" in err
    assert not (tmp_path / "refused.json").exists()

    usage = cmd_run(
        corpus_root=str(SPECIMENS),
        scanner="scanner --all",
        out=str(tmp_path / "usage.json"),
    )
    capsys.readouterr()
    assert usage == 2

    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    ok = cmd_run(
        corpus_root=str(SPECIMENS),
        scanner=f"{sys.executable} {stub} {PLACEHOLDER}",
        out=str(tmp_path / "ok.json"),
        scanner_name="stub",
    )
    capsys.readouterr()
    assert ok == 0
    assert len({ok, usage, refused}) == 3, "the three outcomes must be distinguishable"


def test_run_summary_names_errored_specimens(tmp_corpus, tmp_path, capsys):
    """R7's scenario ends '...and the run's summary names it.' That half was untested.

    Asserting the data structure is not asserting the summary: a reader of the console
    output is the one R7 is protecting.
    """
    from poison_garden.commands import cmd_run

    root = tmp_corpus(
        [
            {"id": "works", "declaration": ["injection"], "server_text": _echo_server()},
            {"id": "works-twin", "twin_for": ["injection"], "server_text": _echo_server()},
            {"id": "wont-start", "declaration": ["hygiene"],
             "server_text": "import sys; sys.exit(1)"},
            {"id": "hygiene-twin", "twin_for": ["hygiene"], "server_text": _echo_server()},
        ]
    )
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(1)")
    code = cmd_run(
        corpus_root=str(root),
        scanner=f"{sys.executable} {stub} {PLACEHOLDER}",
        out=str(tmp_path / "r.json"),
        scanner_name="stub",
    )
    out = capsys.readouterr().out

    assert code == 0
    assert "wont-start" in out, "the summary does not name the errored specimen (R7)"
    assert "ERRORED" in out


# --- W6: the scanner template may carry a token; it must not reach a repr or an error ----


def test_scanner_command_repr_does_not_carry_the_template():
    command = parse_scanner("scan --api-key=sk-live-SUPERSECRET {target}")
    assert "SUPERSECRET" not in repr(command)
    assert "sk-live" not in repr(command)


def test_template_error_does_not_echo_the_template():
    """The message reaches stderr and any CI log."""
    with pytest.raises(ScannerTemplateError) as exc:
        parse_scanner("scan --api-key=sk-live-SUPERSECRET --all")
    assert "SUPERSECRET" not in str(exc.value)
    assert "scan" in str(exc.value), "naming the program is enough to locate the mistake"


# --- W7: the completeness guard used to look only one way --------------------------------


def test_scoring_refuses_a_result_for_a_specimen_not_in_the_corpus(corpus):
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    results.append(SpecimenResult("a-specimen-that-does-not-exist", Verdict.FLAGGED, 1))
    with pytest.raises(ScoringRefused, match="not in this corpus"):
        score_run(corpus, results)


def test_scoring_refuses_duplicate_results(corpus):
    """Building the id map is what hides this: the second result overwrites the first."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    results.append(SpecimenResult(corpus.specimens[0].id, Verdict.CLEAN, 0))
    with pytest.raises(ScoringRefused, match="more than one result"):
        score_run(corpus, results)


# --- (a)2: the product path must hand specimens a REAL, listening sink -------------------


def test_run_corpus_gives_specimens_a_connectable_egress_sink(tmp_corpus, tmp_path):
    """REGRESSION: `run_corpus` hand-built a Sandbox with a literal `egress_port=0`.

    Port 0 is not a connectable address and nothing was listening, so `PG_EGRESS_SINK`
    pointed at `127.0.0.1:0` and any exfiltration attempt simply failed to connect.
    Invisible while every specimen is a pure declaration; wrong the moment M3's R11/R12
    specimens exist, because their behaviour would have had no collector on the one path a
    vendor actually runs.
    """
    reporter = tmp_path / "sink.txt"
    # The specimen reports the address it was handed AND whether it could actually reach
    # it. Liveness has to be proven from INSIDE the run: the sink is torn down when
    # run_corpus returns, so connecting afterwards proves nothing either way.
    server = textwrap.dedent(
        f'''
        import os, socket
        addr = os.environ.get("PG_EGRESS_SINK", "")
        host, _, port = addr.rpartition(":")
        try:
            with socket.create_connection((host, int(port)), timeout=2) as c:
                c.sendall(b"exfil")
            reached = "yes"
        except Exception as exc:
            reached = f"no:{{type(exc).__name__}}"
        open({str(reporter)!r}, "w").write(addr + " " + reached)
        '''
    ) + _echo_server()
    root = tmp_corpus(
        [
            {"id": "p", "declaration": ["injection"], "server_text": server},
            {"id": "t", "twin_for": ["injection"], "server_text": _echo_server()},
        ]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(0)")
    run_corpus(corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    addr, reached = reporter.read_text(encoding="utf-8").split(" ", 1)
    host, _, port = addr.rpartition(":")

    assert host == "127.0.0.1", f"sink host is {host!r}"
    assert int(port) > 0, f"sink port is {port!r} — port 0 is not connectable"
    assert reached == "yes", (
        f"specimen could not reach the sink it was handed ({reached}); the address is "
        "plausible-looking but nothing is listening"
    )


def test_preflight_timeout_has_a_floor_and_a_cap(tmp_corpus, tmp_path):
    """N-c: `--timeout 2` used to buy a 2s handshake budget; `--timeout 300` gave 20s."""
    from poison_garden.runner import execute as _execute

    seen: list[float] = []
    real = _execute.preflight

    def spy(specimen, env, timeout=20.0):
        seen.append(timeout)
        return real(specimen, env, timeout=timeout)

    root = tmp_corpus(
        [
            {"id": "p", "declaration": ["injection"], "server_text": _echo_server()},
            {"id": "t", "twin_for": ["injection"], "server_text": _echo_server()},
        ]
    )
    corpus = load_corpus(root)
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(0)")
    command = parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}")

    _execute.preflight = spy
    try:
        run_corpus(corpus, command, timeout=2.0)
        assert min(seen) >= 5.0, f"floor not applied: {seen}"
        seen.clear()
        run_corpus(corpus, command, timeout=300.0)
        assert max(seen) <= 60.0, f"cap not applied: {seen}"
    finally:
        _execute.preflight = real


# --- item 3: run-order independence (N3) -------------------------------------------------


def test_a_specimen_that_writes_cannot_affect_a_later_one(tmp_corpus, tmp_path):
    """N3: behaviour is a function of inputs and the runner-supplied environment.

    One shared $HOME across the corpus made it a function of run POSITION too. A specimen
    that writes — plausible for R13's rug-pull state — left the file for every later
    specimen. The failure mode is the worst kind to debug: passes in isolation, fails at
    position 14, corpus hash identical either way.
    """
    marker = "PG-LEAKED-STATE"
    writer = (
        textwrap.dedent(
            f'''
            import os, pathlib
            pathlib.Path(os.environ["HOME"], "left-behind").write_text({marker!r})
            '''
        )
        + _echo_server()
    )
    # Sorted by id, so `a-writer` runs before `b-reader`.
    reader_report = tmp_path / "reader.txt"
    reader = (
        textwrap.dedent(
            f'''
            import os, pathlib
            p = pathlib.Path(os.environ["HOME"], "left-behind")
            open({str(reader_report)!r}, "w").write(p.read_text() if p.exists() else "CLEAN")
            '''
        )
        + _echo_server()
    )

    root = tmp_corpus(
        [
            {"id": "a-writer", "declaration": ["injection"], "server_text": writer},
            {"id": "b-reader", "declaration": ["hygiene"], "server_text": reader},
            {"id": "c-twin", "twin_for": ["injection"], "server_text": _echo_server()},
            {"id": "d-twin", "twin_for": ["hygiene"], "server_text": _echo_server()},
        ]
    )
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(0)")
    run_corpus(load_corpus(root), parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    assert reader_report.read_text(encoding="utf-8") == "CLEAN", (
        "a later specimen saw state written by an earlier one — HOME is being shared"
    )


def test_each_specimen_gets_a_distinct_egress_sink(tmp_corpus, tmp_path):
    """A shared sink accumulates across the corpus, so an attempt cannot be attributed.

    Introduced by the fix that started the sink at all — worth a guard for that reason.
    """
    report = tmp_path / "ports.txt"
    reporter = (
        textwrap.dedent(
            f'''
            import os
            with open({str(report)!r}, "a") as fh:
                fh.write(os.environ.get("PG_EGRESS_SINK", "") + "\\n")
            '''
        )
        + _echo_server()
    )
    root = tmp_corpus(
        [
            {"id": "one", "declaration": ["injection"], "server_text": reporter},
            {"id": "two", "declaration": ["hygiene"], "server_text": reporter},
            {"id": "twin-a", "twin_for": ["injection"], "server_text": _echo_server()},
            {"id": "twin-b", "twin_for": ["hygiene"], "server_text": _echo_server()},
        ]
    )
    stub = _stub_scanner(tmp_path, "import sys; sys.exit(0)")
    run_corpus(load_corpus(root), parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"))

    ports = [line for line in report.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(ports) >= 2, f"expected a sink address per specimen, got {ports}"
    assert len(set(ports)) == len(ports), (
        f"specimens shared one sink, so egress cannot be attributed: {ports}"
    )


# --- item 5: the initialize exchange was never inspected ---------------------------------


def test_preflight_rejects_a_specimen_that_fails_initialize(tmp_path: Path):
    """A specimen that errors on initialize but answers tools/list was classified healthy.

    A formality in M1 — every specimen answers it identically — and exactly the exchange
    R14's scanner-aware specimen uses to discriminate. Such a specimen refusing our
    handshake while still serving a catalog would have been waved through with its evasion
    unmeasured.
    """
    from poison_garden.corpus.models import Manifest, Specimen
    from poison_garden.runner.execute import preflight

    d = tmp_path / "bad-init"
    d.mkdir(parents=True)
    (d / "server.py").write_text(
        textwrap.dedent(
            '''
            import json, sys
            for line in sys.stdin:
                line = line.strip()
                if not line: continue
                m = json.loads(line)
                if m.get("id") is None: continue
                if m.get("method") == "initialize":
                    out = {"jsonrpc":"2.0","id":m["id"],
                           "error":{"code":-32600,"message":"no"}}
                else:
                    out = {"jsonrpc":"2.0","id":m["id"],
                           "result":{"tools":[{"name":"t","description":"d",
                                     "inputSchema":{"type":"object","properties":{}}}]}}
                sys.stdout.write(json.dumps(out)+"\\n"); sys.stdout.flush()
            '''
        ),
        encoding="utf-8",
    )
    specimen = Specimen(
        path=d, manifest=Manifest(id="bad-init", summary="x", entrypoint="server.py")
    )
    assert preflight(specimen, {"PATH": "/usr/bin:/bin"}, timeout=10.0) == (
        "specimen-initialize-failed"
    )


def test_preflight_exposes_the_initialize_response(tmp_path: Path):
    """R14's test needs the handshake result, not only the catalog."""
    from poison_garden.runner.execute import handshake_responses

    stdout = (
        '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"x","version":"1"}}}\n'
        '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n'
    )
    responses = handshake_responses(stdout)
    assert responses is not None
    assert responses[1]["result"]["serverInfo"]["name"] == "x"
    assert "tools" in responses[2]["result"]


# --- item 6: the published hash must describe the corpus AS MEASURED ---------------------


def test_document_refuses_when_the_corpus_changed_during_the_run(corpus, tmp_path):
    """R4: two honest runs over one corpus must not cite different hashes.

    A specimen that writes into its own directory — R13's state, an R12 decoy that
    regenerates — changed the hash computed after the run. `compare()` would then refuse
    two legitimate documents with nothing saying why.
    """
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    stale = "sha256:" + "1" * 64
    with pytest.raises(ScoringRefused, match="changed during the run"):
        build_document(
            corpus, results, "stub", ExitCodeMapping(), corpus_hash_before_run=stale
        )


def test_document_records_the_hash_captured_before_the_run(corpus):
    from poison_garden.corpus.hash import corpus_hash as _hash

    before = _hash(corpus)
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(
        corpus, results, "stub", ExitCodeMapping(), corpus_hash_before_run=before
    )
    assert doc.payload["corpus"]["hash"] == before


# --- the composite guard, after two independent reviews converged on "tighten" ----------


def test_non_string_keys_do_not_crash_the_guards():
    """Both reviewers caught this and I had not: `key.lower()` raises on a non-string key.

    Plausible rather than exotic here, because per-class results are keyed by class.
    """
    payload = {1: {"score": 0.5}, "ok": [{2: "x"}]}
    assert composite_fields_in(payload) == ["1.score"]
    unexpected_fields_in(payload)  # must not raise


def test_guard_catches_mid_compound_names():
    """The prefix/suffix form missed these; token matching is why they are caught now."""
    for name in ("spearman_rank_index", "weighted_composite_value", "class_scores"):
        assert composite_fields_in({name: 1}) == [name], f"{name} slipped the token match"


def test_guard_does_not_reject_a_field_the_spec_requires():
    """`overall` was dropped deliberately.

    R9 requires a document-level false-positive rate. Banning the word `overall` would
    have made the guard reject `overall_false_positive_rate` — the guard contradicting the
    requirement it exists to serve.
    """
    for legitimate in (
        "overall_false_positive_rate",
        "rank_correlation",
        "f1",
        "recall",
        "false_positive_rate",
    ):
        assert composite_fields_in({legitimate: 0.5}) == [], f"{legitimate} wrongly rejected"


def test_schema_guard_catches_what_no_wordlist_can(corpus):
    """The structural point: a composite score can be named with no banned word at all.

    `accuracy`, `detection_rate`, `success_rate` are aggregate figures whose names cannot be
    banned without banning legitimate per-class metrics. An exact key set catches them
    because poison-garden generates this document from a schema it controls.
    """
    results = [SpecimenResult(s.id, Verdict.CLEAN, 0) for s in corpus.specimens]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    assert unexpected_fields_in(doc.payload) == [], "the real document has an unknown field"

    for sneaky in ("accuracy", "detection_rate", "success_rate", "efficacy"):
        poisoned = {**doc.payload, sneaky: 0.91}
        assert composite_fields_in(poisoned) == [], (
            f"precondition: {sneaky} is invisible to the wordlist, which is the point"
        )
        assert unexpected_fields_in(poisoned) == [sneaky], (
            f"{sneaky} would ship undetected — the schema guard is the only thing that "
            "catches a headline number wearing an innocent name"
        )


def test_caught_and_missed_are_always_complementary(corpus):
    """REGRESSION: they were computed independently and SARIF opened a hole between them.

    A specimen flagged but not attributed to a class was in neither list, so
    caught + missed != total — and the document's own consistency check would then have
    rejected a document poison-garden itself produced.
    """
    from poison_garden.runner.sarif import parse_sarif

    results = []
    for index, specimen in enumerate(corpus.specimens):
        if specimen.is_benign:
            results.append(SpecimenResult(specimen.id, Verdict.CLEAN, 0))
            continue
        # Alternate: some flagged-and-attributed, some flagged-but-not, some clean.
        if index % 3 == 0:
            results.append(SpecimenResult(specimen.id, Verdict.CLEAN, 0))
        elif index % 3 == 1:
            results.append(SpecimenResult(specimen.id, Verdict.FLAGGED, 1))
        else:
            empty = parse_sarif(
                json.dumps({"version": "2.1.0", "runs": [{"results": []}]})
            )
            results.append(
                SpecimenResult(
                    specimen.id, Verdict.FLAGGED, 1, attributed=empty.classes
                )
            )

    scores = score_run(corpus, results)
    for entry in scores.per_class:
        assert entry.caught + len(entry.missed) == entry.total, (
            f"{entry.klass.value}: caught({entry.caught}) + missed({len(entry.missed)}) "
            f"!= total({entry.total})"
        )


# --- R24: "the scanner failed" must not score as "the scanner found nothing" -------------


def test_a_self_reported_failure_exit_code_becomes_error_not_clean():
    """REGRESSION, measured against a real tool.

    `velox-mcp-audit` exits 0 while printing "Do NOT trust this scan result" after a failed
    introspection. Under the default mapping that is a CLEAN verdict: a scanner that just
    said it could not do its job is recorded as having examined the specimen and found it
    innocent. That is a silent miss — the failure R7 exists to prevent — arriving through
    the exit code rather than through a broken specimen.
    """
    mapping = ExitCodeMapping(error_on=(2,))
    assert mapping.verdict_for(2) is Verdict.ERROR
    # Under the default it would have been a finding, which is the opposite mistake.
    assert ExitCodeMapping().verdict_for(2) is Verdict.FLAGGED


def test_error_on_is_checked_before_the_flag_threshold():
    """A code meaning failure must not also be read as a finding.

    Under `nonzero` — the default — every non-zero code is a finding, so ordering decides
    it. If the threshold were consulted first, `--error-on` would be silently inert exactly
    where it is needed.
    """
    mapping = ExitCodeMapping(flag_on="nonzero", error_on=(3,))
    assert mapping.verdict_for(3) is Verdict.ERROR, "flag threshold won over error_on"
    assert mapping.verdict_for(1) is Verdict.FLAGGED


def test_error_on_defaults_to_empty_so_nothing_changes_for_existing_users():
    """CONTROL (P49). Guessing a failure code would reclassify honest clean verdicts as
    errors, removing specimens from both numerator and denominator — the opposite error,
    and just as silent."""
    mapping = ExitCodeMapping()
    assert mapping.error_on == ()
    for code in (0, 1, 2, 7, 42):
        assert mapping.verdict_for(code) is not Verdict.ERROR


def test_the_mapping_description_records_error_codes():
    """R6: the document records how a number became a verdict. A reader cannot recompute
    a verdict they cannot see the rule for."""
    described = ExitCodeMapping(error_on=(2, 9)).describe()
    assert "2" in described and "9" in described
    assert "self-reported failure" in described
    # And the clause is ABSENT by default, or it would describe a rule nobody configured.
    # (The default legitimately ends "(signal) -> error", so check for the clause itself.)
    assert "self-reported failure" not in ExitCodeMapping().describe()


def test_error_on_is_parsed_at_the_boundary_not_on_the_first_specimen():
    """P6, and the same mistake `--flag-on banana` made: it spawned every specimen,
    scanned one, then died with a bare ValueError after the work was done."""
    from poison_garden.commands import parse_error_codes

    assert parse_error_codes("") == ()
    assert parse_error_codes(" 2 , 9 ") == (2, 9)
    with pytest.raises(ValueError, match="banana"):
        parse_error_codes("2,banana")
