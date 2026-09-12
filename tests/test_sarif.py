"""Optional SARIF attribution — R17.

The requirement's operative word is *optional*: the tests below are as concerned with SARIF
never making anything worse as with it making anything better. A precise number nobody
produces is worth less than a coarse one everybody does.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest
from helpers import SPECIMENS

from poison_garden.corpus.loader import load_corpus
from poison_garden.corpus.models import Class
from poison_garden.runner.execute import ExitCodeMapping, Verdict, run_corpus
from poison_garden.runner.sarif import SarifError, attribute, parse_sarif
from poison_garden.runner.target import PLACEHOLDER, parse_scanner
from poison_garden.scoring.score import score_run


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


def _sarif(rule_ids: list[str]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "stub"}},
                    "results": [
                        {"ruleId": r, "message": {"text": f"{r} detected"}} for r in rule_ids
                    ],
                }
            ],
        }
    )


def test_rule_ids_map_to_classes():
    findings = parse_sarif(_sarif(["prompt-injection", "zero-width-content"]))
    assert Class.INJECTION in findings.classes
    assert Class.HIDDEN_CONTENT in findings.classes
    assert findings.result_count == 2


def test_an_unmapped_rule_still_counts_as_a_finding():
    """Scoring a scanner by how well its vocabulary matches ours would be nonsense."""
    findings = parse_sarif(_sarif(["ACME-QX-0007"]))
    assert findings.classes == frozenset()
    assert findings.flagged is True
    assert findings.unmapped_rules == ("ACME-QX-0007",)


def test_empty_sarif_is_not_a_finding():
    findings = parse_sarif(_sarif([]))
    assert findings.flagged is False
    assert findings.result_count == 0


def test_malformed_sarif_raises():
    with pytest.raises(SarifError):
        parse_sarif("{not json")
    with pytest.raises(SarifError):
        parse_sarif(json.dumps({"version": "2.1.0"}))


def test_attribution_is_an_intersection_never_a_superset():
    """A scanner reporting every class it knows must not earn credit for absent ones.

    The SARIF analogue of flagging everything — and the benign twins cannot catch it,
    because a twin carries no classes to over-claim against.
    """
    findings = parse_sarif(_sarif(["injection", "hidden", "impersonation", "hygiene"]))
    earned = attribute(findings, frozenset({Class.INJECTION}))
    assert earned == frozenset({Class.INJECTION})


# --- R17's real requirement: it must never make anything worse ---------------------------


def _stub(tmp_path: Path, body: str, name="s.py") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_a_scanner_emitting_no_sarif_scores_exactly_as_before(corpus, tmp_path):
    """R17 scenario: absence of SARIF never blocks a run, and never changes a figure."""
    stub = _stub(tmp_path, "import sys; print('not sarif'); sys.exit(1)")
    command = parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}")

    without = score_run(corpus, run_corpus(corpus, command, sarif=False))
    with_flag = score_run(corpus, run_corpus(corpus, command, sarif=True))

    baseline = {c.klass: (c.caught, c.total) for c in without.per_class}
    enriched = {c.klass: (c.caught, c.total) for c in with_flag.per_class}
    assert baseline == enriched, "requesting SARIF changed a score for a scanner without it"


def test_unusable_sarif_keeps_the_exit_code_verdict(corpus, tmp_path):
    """A scanner must not score worse for emitting something we failed to read."""
    stub = _stub(tmp_path, "import sys; print('{oops'); sys.exit(1)")
    results = run_corpus(
        corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"), sarif=True
    )
    assert {r.verdict for r in results} == {Verdict.FLAGGED}
    assert all(r.attributed is None for r in results)
    assert any(r.sarif_note and "unusable-sarif" in r.sarif_note for r in results)


def test_sarif_separates_the_classes_of_a_dual_class_specimen(corpus, tmp_path):
    """What SARIF actually buys.

    A dual-class specimen is one verdict under exit codes, so a flag credits both classes
    even if the scanner only saw one. With SARIF the run can tell those apart.
    """
    dual = next(s for s in corpus.malicious if len(s.classes) > 1)
    assert Class.HIDDEN_CONTENT in dual.classes and Class.INJECTION in dual.classes

    # A scanner that reports ONLY hidden-content.
    stub = _stub(
        tmp_path,
        f"""
        import sys
        print({_sarif(["zero-width-content"])!r})
        sys.exit(1)
        """,
    )
    results = run_corpus(
        corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"), sarif=True
    )
    by_id = {r.specimen_id: r for r in results}
    assert by_id[dual.id].attributed == frozenset({Class.HIDDEN_CONTENT})

    scores = {c.klass: c for c in score_run(corpus, results).per_class}
    assert dual.id in scores[Class.INJECTION].missed, (
        "the scanner reported only hidden-content but was credited for injection"
    )
    assert dual.id not in scores[Class.HIDDEN_CONTENT].missed


def test_document_records_attribution_only_when_present(corpus, tmp_path):
    from poison_garden.scoring.document import build_document, unexpected_fields_in

    stub = _stub(tmp_path, "import sys; sys.exit(0)")
    results = run_corpus(
        corpus, parse_scanner(f"{sys.executable} {stub} {PLACEHOLDER}"), sarif=False
    )
    doc = build_document(corpus, results, "stub", ExitCodeMapping())
    assert all(v["attributed"] is None for v in doc.payload["verdicts"])
    assert unexpected_fields_in(doc.payload) == [], "attribution fields must be in the schema"
