"""Tests for the test factory itself.

A fixture that can be silently misused is a defect generator: every negative test built on
it is one typo away from passing for the wrong reason. These guards are cheap and they
protect the whole suite (cross-cutting P6, P51).
"""

from __future__ import annotations

import pytest

from poison_garden.corpus.loader import load_corpus

POISONED = {"id": "injection-poisoned", "declaration": ["injection"]}
TWIN = {"id": "injection-twin", "twin_for": ["injection"]}


def test_unknown_key_is_rejected(tmp_corpus):
    """The exact defect: `omit_manifests` (typo) used to build a VALID specimen."""
    with pytest.raises(ValueError) as exc:
        tmp_corpus([{"id": "x", "omit_manifests": True}])
    message = str(exc.value)
    assert "omit_manifests" in message
    assert "omit_manifest" in message, "the error should show the correct spelling nearby"


def test_typo_in_declaration_key_is_rejected(tmp_corpus):
    with pytest.raises(ValueError) as exc:
        tmp_corpus([{"id": "x", "declarations": ["injection"]}])
    assert "declarations" in str(exc.value)


def test_missing_id_is_rejected(tmp_corpus):
    with pytest.raises(ValueError, match="needs an 'id'"):
        tmp_corpus([{"declaration": ["injection"]}])


def test_conflicting_manifest_flags_are_rejected(tmp_corpus):
    with pytest.raises(ValueError, match="conflict"):
        tmp_corpus([{"id": "x", "manifest_text": "id = 'x'", "omit_manifest": True}])


def test_empty_corpus_is_refused_by_default(tmp_corpus):
    """P55: a test against an empty corpus cannot separate 'clean' from 'not checked'."""
    with pytest.raises(ValueError, match="empty corpus"):
        tmp_corpus([])


def test_empty_corpus_is_allowed_when_explicitly_requested(tmp_corpus):
    root = tmp_corpus([], allow_empty=True)
    assert root.is_dir()


def test_building_twice_into_one_root_name_is_refused(tmp_corpus):
    """Two builds used to merge, so a test comparing two corpora compared one to itself."""
    tmp_corpus([POISONED, TWIN])
    with pytest.raises(ValueError, match="already exists"):
        tmp_corpus([{"id": "other", "declaration": ["hygiene"]}])


def test_distinct_root_names_stay_separate(tmp_corpus):
    a = tmp_corpus([POISONED, TWIN], root_name="a")
    b = tmp_corpus([{"id": "hygiene-poisoned", "declaration": ["hygiene"]}], root_name="b")
    assert {s.id for s in load_corpus(a).specimens} == {"injection-poisoned", "injection-twin"}
    assert {s.id for s in load_corpus(b).specimens} == {"hygiene-poisoned"}


def test_summary_containing_a_quote_produces_valid_toml(tmp_corpus):
    """Naive interpolation made a VALID input look like a malformed-input test."""
    root = tmp_corpus([{**POISONED, "summary": 'he said "hi" and left'}, TWIN])
    corpus = load_corpus(root)
    assert corpus.by_id("injection-poisoned").manifest.summary == 'he said "hi" and left'


def test_summary_containing_a_backslash_produces_valid_toml(tmp_corpus):
    root = tmp_corpus([{**POISONED, "summary": r"path\to\thing"}, TWIN])
    assert load_corpus(root).by_id("injection-poisoned").manifest.summary == r"path\to\thing"


def test_real_corpus_root_fixture_refuses_an_empty_tree(real_corpus_root):
    """P16: the fixture validates its own setup rather than handing back an empty dir."""
    populated = [
        d for d in real_corpus_root.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
    ]
    assert populated
