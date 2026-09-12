"""Submission validation and comparison rendering — R15, R16.

The submission boundary is where this project's founding constraint has to hold in code:
maintainers never recompute, adjust, or editorialise a submitted figure. So validation has
exactly two outcomes, accept or reject with a reason, and there is deliberately no code path
that repairs a document.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import SPECIMENS

from poison_garden.corpus.hash import corpus_hash
from poison_garden.corpus.loader import load_corpus
from poison_garden.leaderboard.render import GENERATED_MARKER, is_stale, render
from poison_garden.leaderboard.validate import validate_directory, validate_document
from poison_garden.runner.execute import ExitCodeMapping, SpecimenResult, Verdict
from poison_garden.scoring.document import build_document

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


@pytest.fixture
def valid_document(corpus, tmp_path) -> Path:
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "unit-scanner", ExitCodeMapping())
    path = tmp_path / "unit-scanner.json"
    doc.write(path)
    return path


@pytest.fixture
def releases(corpus) -> dict[str, str]:
    return {corpus.version: corpus_hash(corpus)}


# --- R15: validation accepts or rejects, and never repairs --------------------------------


def test_a_genuine_document_validates(valid_document, releases):
    result = validate_document(valid_document, releases=releases)
    assert result.ok, result.summary()


def test_validation_never_modifies_the_document(valid_document, releases):
    """The founding constraint at the submission boundary.

    A 'helpful' fix-up would make the published figure ours rather than the vendor's,
    which is the referee posture this project refuses.
    """
    before = valid_document.read_bytes()
    validate_document(valid_document, releases=releases)
    assert valid_document.read_bytes() == before


def test_unknown_corpus_version_is_rejected(valid_document):
    result = validate_document(valid_document, releases={"9.9.9": "sha256:" + "0" * 64})
    assert not result.ok
    assert any("not a released corpus" in e for e in result.errors)


def test_corpus_hash_mismatch_is_rejected(valid_document, corpus):
    """A document describing a corpus that is not the one it names (R4)."""
    result = validate_document(
        valid_document, releases={corpus.version: "sha256:" + "1" * 64}
    )
    assert not result.ok
    assert any("does not match release" in e for e in result.errors)


def test_figures_that_disagree_with_own_verdicts_are_rejected(valid_document, releases):
    """R15's core check: a summary its own evidence contradicts is not a measurement."""
    payload = json.loads(valid_document.read_text(encoding="utf-8"))
    payload["per_class"][0]["caught"] += 5
    valid_document.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_document(valid_document, releases=releases)
    assert not result.ok
    assert any("exceeds total" in e or "!= total" in e for e in result.errors)


def test_a_missed_specimen_must_be_clean_in_its_own_verdicts(valid_document, releases):
    """The cheapest cross-check, and the one that catches a figure typed by hand."""
    payload = json.loads(valid_document.read_text(encoding="utf-8"))
    entry = next(e for e in payload["per_class"] if e["total"] > 0)
    flagged = next(
        v["specimen"] for v in payload["verdicts"] if v["verdict"] == "flagged"
    )
    entry["missed"] = [flagged]
    entry["caught"] = entry["total"] - 1
    valid_document.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_document(valid_document, releases=releases)
    assert not result.ok
    assert any("listed as missed but its verdict is" in e for e in result.errors)


def test_a_composite_score_is_rejected(valid_document, releases):
    payload = json.loads(valid_document.read_text(encoding="utf-8"))
    payload["score"] = 0.93
    valid_document.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_document(valid_document, releases=releases)
    assert not result.ok
    assert any("composite" in e or "outside the result schema" in e for e in result.errors)


def test_a_headline_number_under_an_innocent_name_is_rejected(valid_document, releases):
    """`accuracy` is invisible to a wordlist; the schema check is what catches it."""
    payload = json.loads(valid_document.read_text(encoding="utf-8"))
    payload["accuracy"] = 0.91
    valid_document.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_document(valid_document, releases=releases)
    assert not result.ok
    assert any("outside the result schema" in e for e in result.errors)


def test_duplicate_verdicts_are_rejected(valid_document, releases):
    payload = json.loads(valid_document.read_text(encoding="utf-8"))
    payload["verdicts"].append(dict(payload["verdicts"][0]))
    valid_document.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_document(valid_document, releases=releases)
    assert not result.ok
    assert any("duplicate verdict" in e for e in result.errors)


def test_unreadable_or_non_json_is_rejected(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    assert not validate_document(bad, releases={}).ok


def test_the_shipped_results_directory_validates():
    """The self-report we publish must pass the same gate a vendor's submission does."""
    results = validate_directory(REPO_ROOT / "results")
    assert results, "results/ contains no documents"
    for result in results:
        assert result.ok, result.summary()


# --- R16: the page is generated, never hand-edited ----------------------------------------


def test_rendered_page_carries_the_generated_marker():
    assert render(REPO_ROOT / "results").startswith(GENERATED_MARKER)


def test_committed_page_is_current():
    """A merged result whose page was never regenerated fails here rather than shipping."""
    assert not is_stale(REPO_ROOT / "results", REPO_ROOT / "COMPARISON.md"), (
        "COMPARISON.md is stale or hand-edited — regenerate with `poison-garden leaderboard`"
    )


def test_a_hand_edit_is_detected(tmp_path):
    page = tmp_path / "COMPARISON.md"
    page.write_text(render(REPO_ROOT / "results"), encoding="utf-8")
    assert not is_stale(REPO_ROOT / "results", page)

    page.write_text(page.read_text(encoding="utf-8") + "\n<!-- hand edit -->\n", encoding="utf-8")
    assert is_stale(REPO_ROOT / "results", page)


def test_the_page_is_not_ranked(tmp_path):
    """R16 + R10: sorting by performance would reintroduce through layout exactly what the
    document format refuses to contain.

    Two submissions where alphabetical and by-performance order disagree; the page must use
    alphabetical.
    """
    strong = {
        "schema": "poison-garden/result@1",
        "corpus": {"version": "0.2.0", "hash": "x", "specimen_count": 1},
        "scanner": {"name": "zzz-excellent", "exit_code_mapping": "m"},
        "verdicts": [],
        "per_class": [{"class": "injection", "caught": 9, "total": 9, "missed": []}],
        "false_positives": {"specimens": [], "benign_total": 5, "rate": 0.0},
    }
    weak = {**strong, "scanner": {"name": "aaa-poor", "exit_code_mapping": "m"},
            "per_class": [{"class": "injection", "caught": 0, "total": 9, "missed": []}]}
    (tmp_path / "a.json").write_text(json.dumps(weak), encoding="utf-8")
    (tmp_path / "z.json").write_text(json.dumps(strong), encoding="utf-8")

    page = render(tmp_path)
    assert "not a ranking" in page
    assert page.index("aaa-poor") < page.index("zzz-excellent"), (
        "rows are ordered by performance, which is a ranking by another name"
    )


def test_empty_results_directory_renders_an_honest_page(tmp_path):
    page = render(tmp_path)
    assert "No results submitted yet" in page
    assert GENERATED_MARKER in page
