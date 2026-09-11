"""Manifest parsing tests — R2, cross-cutting P13 (self-written files are external input)."""

from __future__ import annotations

from pathlib import Path

import pytest

from poison_garden.corpus.manifest import MANIFEST_NAME, parse_manifest
from poison_garden.corpus.models import Class, ManifestError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / MANIFEST_NAME
    path.write_text(text, encoding="utf-8")
    return path


# --- R2: declaration and behavior are independent ---------------------------------------


def test_clean_declaration_hostile_behavior_is_well_formed(tmp_path: Path):
    """R2 scenario: declaration = [] and behavior = [credential-access] is malicious.

    This is the case a static corpus cannot express and the reason the project exists.
    """
    path = _write(
        tmp_path,
        """
        id = "honest-face"
        summary = "Clean catalog, reads decoy credentials on startup"
        declaration = []
        behavior = ["credential-access"]
        """,
    )
    manifest = parse_manifest(path)

    assert manifest.declaration == ()
    assert manifest.behavior == (Class.CREDENTIAL_ACCESS,)
    assert manifest.is_benign is False, "a hostile behavior must not read as benign"
    assert manifest.classes == {Class.CREDENTIAL_ACCESS}


def test_both_lists_empty_is_benign(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "plain-twin"
        summary = "An ordinary, legitimate server"
        """,
    )
    manifest = parse_manifest(path)
    assert manifest.is_benign is True
    assert manifest.classes == frozenset()


def test_declaration_only_specimen(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "loud-liar"
        summary = "Poisoned description, harmless behavior"
        declaration = ["injection"]
        """,
    )
    manifest = parse_manifest(path)
    assert manifest.declaration == (Class.INJECTION,)
    assert manifest.behavior == ()
    assert manifest.is_benign is False


# --- Unknown / misspelled input must fail loudly, naming the offender --------------------


def test_misspelled_class_name_fails_naming_the_value(tmp_path: Path):
    """A typo'd class must never silently become 'no class' (R2, P6)."""
    path = _write(
        tmp_path,
        """
        id = "typo"
        summary = "declaration class is misspelled"
        declaration = ["injectionn"]
        """,
    )
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)

    message = str(exc.value)
    assert "injectionn" in message, "the error must name the offending value"
    assert "declaration[0]" in message, "the error must name the offending position"
    assert "injection" in message, "the error should list valid classes"


def test_unknown_key_is_rejected_not_ignored(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "extra"
        summary = "has a key we do not know"
        declarations = ["injection"]
        """,
    )
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert "declarations" in str(exc.value)


def test_unknown_key_error_lists_known_keys(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "extra"
        summary = "typo'd key"
        behaviour = ["egress"]
        """,
    )
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    message = str(exc.value)
    assert "behaviour" in message
    assert "behavior" in message, "listing known keys is what makes the typo obvious"


# --- P13: a manifest is external input; every failure mode is distinct -------------------


def test_malformed_toml_raises_specific_error(tmp_path: Path):
    path = _write(tmp_path, 'id = "unclosed\nsummary = "x"\n')
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert "malformed TOML" in str(exc.value)


def test_missing_required_key_raises_specific_error(tmp_path: Path):
    path = _write(tmp_path, 'id = "no-summary"\n')
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert "summary" in str(exc.value)


def test_wrong_type_raises_specific_error(tmp_path: Path):
    path = _write(tmp_path, 'id = 17\nsummary = "id is not a string"\n')
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    message = str(exc.value)
    assert "'id'" in message
    assert "int" in message


def test_class_list_that_is_not_a_list_raises(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "scalar"
        summary = "declaration is a bare string"
        declaration = "injection"
        """,
    )
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert "must be a list" in str(exc.value)


def test_missing_file_raises_manifest_error(tmp_path: Path):
    with pytest.raises(ManifestError) as exc:
        parse_manifest(tmp_path / "nope" / MANIFEST_NAME)
    assert "not found" in str(exc.value)


def test_parent_directory_missing_is_also_not_found(tmp_path: Path):
    """ENOENT and ENOTDIR both mean 'the path is gone' (frisk lesson)."""
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("x", encoding="utf-8")
    with pytest.raises(ManifestError) as exc:
        parse_manifest(not_a_dir / MANIFEST_NAME)
    assert "not found" in str(exc.value)


def test_duplicate_class_is_rejected(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        id = "dupe"
        summary = "same class twice"
        declaration = ["injection", "injection"]
        """,
    )
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert "duplicate" in str(exc.value)


# --- P11: never interpolate raw file content into an error ------------------------------


CANARY = "CANARY-a1b2c3d4-DO-NOT-ECHO"


_CANARY_CASES: list[tuple[str, str]] = [
    ("unknown-key", f'id = "x"\nsummary = "y"\nbogus = "{CANARY}"\n'),
    ("bad-class", f'id = "x"\nsummary = "{CANARY}"\ndeclaration = ["nope"]\n'),
    ("wrong-type", f'id = 1\nsummary = "{CANARY}"\n'),
    ("malformed-toml", f'id = "x\nsummary = "{CANARY}"\n'),
    ("missing-key", f'notes = "{CANARY}"\n'),
    (
        "duplicate-class",
        f'id = "x"\nsummary = "{CANARY}"\ndeclaration = ["injection", "injection"]\n',
    ),
    ("non-string-item", f'id = "x"\nsummary = "{CANARY}"\ndeclaration = [7]\n'),
]


@pytest.mark.parametrize(
    ("label", "text"),
    _CANARY_CASES,
    ids=[label for label, _ in _CANARY_CASES],
)
def test_error_messages_never_echo_file_content(tmp_path: Path, label: str, text: str):
    """A malformed manifest could carry a secret; no error path may quote it (P11).

    Parametrized across EVERY failure path, not one: a single-path version of this test
    went green-by-accident the moment an unrelated check was disabled, which is exactly
    the vacuity P51 warns about.
    """
    path = _write(tmp_path, text)
    with pytest.raises(ManifestError) as exc:
        parse_manifest(path)
    assert CANARY not in str(exc.value), f"{label}: manifest value reached the error text"


def test_canary_corpus_covers_every_raising_path(tmp_path: Path):
    """Vacuity guard: the canary cases above must actually exercise distinct messages.

    If two cases produced the same error, the parametrization would be padding rather
    than coverage (P105 — an existence check over N cannot see N-1 of them change).
    """
    texts = [
        f'id = "x"\nsummary = "y"\nbogus = "{CANARY}"\n',
        'id = "x"\nsummary = "y"\ndeclaration = ["nope"]\n',
        "id = 1\nsummary = \"y\"\n",
        'id = "x\nsummary = "y"\n',
        'notes = "y"\n',
        'id = "x"\nsummary = "y"\ndeclaration = ["injection", "injection"]\n',
        'id = "x"\nsummary = "y"\ndeclaration = [7]\n',
    ]
    messages = set()
    for index, text in enumerate(texts):
        path = tmp_path / f"m{index}" / MANIFEST_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ManifestError) as exc:
            parse_manifest(path)
        # Strip the path prefix, which differs per case by construction.
        messages.add(str(exc.value).split(": ", 1)[1])

    assert len(messages) == len(texts), (
        f"expected {len(texts)} distinct error messages, got {len(messages)}: {messages}"
    )
