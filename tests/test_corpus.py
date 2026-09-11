"""Corpus loader, twin coverage, and hashing — R1, R3, R4."""

from __future__ import annotations

from pathlib import Path

import pytest

from poison_garden.corpus.hash import (
    CorpusMismatch,
    corpus_hash,
    refuse_mismatch,
    specimen_hash,
)
from poison_garden.corpus.loader import CorpusError, load_corpus
from poison_garden.corpus.models import Class, ManifestError
from poison_garden.corpus.validate import validate_corpus

POISONED = {"id": "injection-poisoned", "declaration": ["injection"]}
TWIN = {"id": "injection-twin", "twin_for": ["injection"]}


# --- R1: loading ------------------------------------------------------------------------


def test_loads_specimens_sorted_by_id(tmp_corpus):
    root = tmp_corpus([TWIN, POISONED])
    corpus = load_corpus(root)
    assert [s.id for s in corpus.specimens] == ["injection-poisoned", "injection-twin"]


def test_malicious_and_benign_partition(tmp_corpus):
    corpus = load_corpus(tmp_corpus([POISONED, TWIN]))
    assert [s.id for s in corpus.malicious] == ["injection-poisoned"]
    assert [s.id for s in corpus.benign] == ["injection-twin"]


def test_missing_manifest_fails_loudly_not_skipped(tmp_corpus):
    """A skipped specimen silently shrinks every denominator computed from the corpus."""
    root = tmp_corpus([POISONED, {"id": "unlabelled", "omit_manifest": True}])
    with pytest.raises(CorpusError) as exc:
        load_corpus(root)
    message = str(exc.value)
    assert "unlabelled" in message
    assert "manifest.toml" in message


def test_missing_entrypoint_fails(tmp_corpus):
    """R1: a specimen is a runnable program; a manifest with no server is not one."""
    root = tmp_corpus([{**POISONED, "omit_server": True}])
    with pytest.raises(CorpusError) as exc:
        load_corpus(root)
    assert "entrypoint" in str(exc.value)


def test_id_must_match_directory_name(tmp_corpus):
    root = tmp_corpus([POISONED])
    (root / "injection-poisoned" / "manifest.toml").write_text(
        'id = "different"\nsummary = "x"\ndeclaration = ["injection"]\n', encoding="utf-8"
    )
    with pytest.raises(CorpusError) as exc:
        load_corpus(root)
    assert "does not match its directory name" in str(exc.value)


def test_missing_root_fails(tmp_path: Path):
    with pytest.raises(CorpusError) as exc:
        load_corpus(tmp_path / "absent")
    assert "not a directory" in str(exc.value)


def test_underscore_dirs_are_shared_code_not_specimens(tmp_corpus):
    root = tmp_corpus([POISONED, TWIN])
    shared = root / "_base"
    shared.mkdir()
    (shared / "harness.py").write_text("# shared\n", encoding="utf-8")
    corpus = load_corpus(root)
    assert [s.id for s in corpus.specimens] == ["injection-poisoned", "injection-twin"]


def test_corpus_version_is_read(tmp_corpus):
    corpus = load_corpus(tmp_corpus([POISONED, TWIN], version="1.2.3"))
    assert corpus.version == "1.2.3"


# --- R3: twin coverage ------------------------------------------------------------------


def test_class_without_twin_fails_naming_that_class(tmp_corpus):
    """R3 scenario: a class with no benign control cannot be validated."""
    root = tmp_corpus(
        [
            POISONED,
            TWIN,
            {"id": "impersonation-poisoned", "declaration": ["impersonation"]},
        ]
    )
    report = validate_corpus(load_corpus(root))

    assert report.ok is False
    assert report.classes_without_twin == (Class.IMPERSONATION,)
    assert "impersonation" in report.summary()
    assert "injection" not in report.summary().split("No benign twin for:")[1]


def test_every_class_with_a_twin_passes(tmp_corpus):
    report = validate_corpus(load_corpus(tmp_corpus([POISONED, TWIN])))
    assert report.ok is True
    assert report.classes_measured == (Class.INJECTION,)


def test_removing_a_twin_makes_validation_fail(tmp_corpus):
    """Discrimination (P31/P50): the check must FAIL when its subject is removed.

    Builds the passing corpus first, asserts it passes, then removes only the twin and
    asserts the same check now fails — so the green above cannot be vacuous.
    """
    root = tmp_corpus([POISONED, TWIN])
    assert validate_corpus(load_corpus(root)).ok is True, "precondition: corpus passes"

    twin_manifest = root / "injection-twin" / "manifest.toml"
    twin_manifest.write_text(
        'id = "injection-twin"\nsummary = "no longer a control"\n', encoding="utf-8"
    )

    report = validate_corpus(load_corpus(root))
    assert report.ok is False
    assert report.classes_without_twin == (Class.INJECTION,)


def test_empty_corpus_is_vacuous_not_passing(tmp_corpus):
    """P64/P58: 'nothing failed' and 'nothing was checked' are different findings."""
    report = validate_corpus(load_corpus(tmp_corpus([{"id": "just-a-twin"}])))
    assert report.is_vacuous is True
    assert report.ok is False, "a corpus with zero attack classes must not report success"
    assert "VACUOUS" in report.summary()


def test_report_states_what_it_measured(tmp_corpus):
    """A count is not a population — the report must print the size it inspected (P64)."""
    root = tmp_corpus(
        [
            POISONED,
            TWIN,
            {"id": "hygiene-poisoned", "declaration": ["hygiene"]},
            {"id": "hygiene-twin", "twin_for": ["hygiene"]},
        ]
    )
    report = validate_corpus(load_corpus(root))
    assert report.specimens_measured == 4
    assert report.malicious_count == 2
    assert report.benign_count == 2
    assert "4 specimen(s)" in report.summary()


def test_orphan_twin_is_reported_but_not_a_failure(tmp_corpus):
    """A control for a class nobody exhibits is stale and must not linger unnoticed."""
    root = tmp_corpus([POISONED, {**TWIN, "twin_for": ["injection", "egress"]}])
    report = validate_corpus(load_corpus(root))
    assert report.ok is True
    assert report.orphan_twins == (("injection-twin", Class.EGRESS),)
    assert "egress" in report.summary()


def test_malicious_specimen_cannot_be_its_own_twin(tmp_corpus):
    """P51: letting a specimen control for a class it exhibits makes the probe vacuous."""
    root = tmp_corpus(
        [{"id": "cheat", "declaration": ["injection"], "twin_for": ["injection"]}]
    )
    with pytest.raises(ManifestError) as exc:
        load_corpus(root)
    assert "must itself be benign" in str(exc.value)


# --- R4: hashing ------------------------------------------------------------------------


def test_hash_is_stable_across_loads(tmp_corpus):
    root = tmp_corpus([POISONED, TWIN])
    assert corpus_hash(load_corpus(root)) == corpus_hash(load_corpus(root))


def test_hash_changes_when_a_specimen_byte_changes(tmp_corpus):
    """P47: prove the hash is DERIVED by mutating the source, not the hash."""
    root = tmp_corpus([POISONED, TWIN])
    before = corpus_hash(load_corpus(root))

    server = root / "injection-poisoned" / "server.py"
    server.write_text(server.read_text(encoding="utf-8") + "# one more byte\n", encoding="utf-8")

    assert corpus_hash(load_corpus(root)) != before


def test_hash_changes_when_a_manifest_changes(tmp_corpus):
    root = tmp_corpus([POISONED, TWIN])
    before = corpus_hash(load_corpus(root))
    manifest = root / "injection-poisoned" / "manifest.toml"
    manifest.write_text(
        'id = "injection-poisoned"\nsummary = "reworded"\ndeclaration = ["injection"]\n',
        encoding="utf-8",
    )
    assert corpus_hash(load_corpus(root)) != before


def test_hash_covers_the_shared_harness_at_the_corpus_root(tmp_corpus):
    """REGRESSION (R4): `specimens/_base.py` was excluded from the hash.

    `_base.py` is the module every specimen imports to produce its `tools/list` response.
    Hashing only specimen directories left it out, so a change that stopped every
    hidden-content specimen serving anything hidden produced a byte-identical hash. Two
    result documents would cite the same corpus and describe different corpora — the exact
    comparison R4 exists to make safe.
    """
    root = tmp_corpus([POISONED, TWIN])
    shared = root / "_base.py"
    shared.write_text("# shared harness\n", encoding="utf-8")

    before = corpus_hash(load_corpus(root))
    shared.write_text("# shared harness, edited\n", encoding="utf-8")
    after = corpus_hash(load_corpus(root))

    assert before != after, (
        "editing the shared harness did not move the corpus hash — R4 is defeated"
    )


def test_hash_covers_the_corpus_version_file(tmp_corpus):
    root = tmp_corpus([POISONED, TWIN], version="1.0.0")
    before = corpus_hash(load_corpus(root))
    (root / "CORPUS_VERSION").write_text("2.0.0\n", encoding="utf-8")
    assert corpus_hash(load_corpus(root)) != before


def test_shared_root_file_cannot_collide_with_a_specimen_file(tmp_corpus):
    """Shared files carry their own record tag, so identical names cannot alias."""
    a = tmp_corpus([POISONED, TWIN], root_name="a")
    (a / "_base.py").write_text("X", encoding="utf-8")

    b = tmp_corpus([{**POISONED, "server_text": "X"}, TWIN], root_name="b")
    (b / "_base.py").write_text("", encoding="utf-8")

    assert corpus_hash(load_corpus(a)) != corpus_hash(load_corpus(b))


def test_hash_ignores_specimen_ordering(tmp_corpus):
    """Two corpora with the same content built in different order hash identically."""
    a = tmp_corpus([POISONED, TWIN], root_name="a")
    b = tmp_corpus([TWIN, POISONED], root_name="b")
    assert corpus_hash(load_corpus(a)) == corpus_hash(load_corpus(b))


def test_hash_is_framing_unambiguous(tmp_corpus):
    """Length-prefixing means 'a'+'b' cannot collide with 'ab' (P13)."""
    a = tmp_corpus(
        [{"id": "ab", "declaration": ["injection"], "server_text": ""}, TWIN],
        root_name="a",
    )
    b = tmp_corpus(
        [{"id": "a", "declaration": ["injection"], "server_text": "b"}, TWIN],
        root_name="b",
    )
    assert corpus_hash(load_corpus(a)) != corpus_hash(load_corpus(b))


def test_hash_ignores_pycache_and_ds_store(tmp_corpus):
    root = tmp_corpus([POISONED, TWIN])
    before = corpus_hash(load_corpus(root))

    junk = root / "injection-poisoned" / "__pycache__"
    junk.mkdir()
    (junk / "server.cpython-312.pyc").write_bytes(b"\x00\x01")
    (root / "injection-poisoned" / ".DS_Store").write_bytes(b"\x00")

    assert corpus_hash(load_corpus(root)) == before


def test_specimen_hash_distinguishes_specimens(tmp_corpus):
    corpus = load_corpus(tmp_corpus([POISONED, TWIN]))
    hashes = {specimen_hash(s) for s in corpus.specimens}
    assert len(hashes) == 2


def test_hash_has_algorithm_prefix(tmp_corpus):
    assert corpus_hash(load_corpus(tmp_corpus([POISONED, TWIN]))).startswith("sha256:")


# --- R4 scenario (M1 half): refusing a cross-corpus comparison --------------------------


def test_refuse_mismatch_names_both_hashes():
    with pytest.raises(CorpusMismatch) as exc:
        refuse_mismatch("sha256:aaa", "sha256:bbb", label_a="ours", label_b="theirs")
    message = str(exc.value)
    assert "sha256:aaa" in message
    assert "sha256:bbb" in message
    assert "ours" in message and "theirs" in message


def test_refuse_mismatch_allows_identical_hashes():
    refuse_mismatch("sha256:aaa", "sha256:aaa")  # must not raise
