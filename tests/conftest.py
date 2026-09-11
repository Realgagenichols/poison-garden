"""Shared test fixtures.

The `tmp_corpus` factory builds specimen directories on disk in a tmp_path, so corpus
tests never read or mutate the real `specimens/` tree. Tests that need the *real* corpus
say so explicitly via `real_corpus_root`.

**The factory validates its own input.** An unknown key used to be silently ignored, which
made it a defect generator: a test written to assert "a missing manifest is rejected" would,
on a typo of `omit_manifest`, quietly build a perfectly valid specimen and pass for the
wrong reason. A fixture that cannot be misused into vacuity is worth more than the three
lines it costs (cross-cutting P6 — validate at the boundary).
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every key `_build` understands. Anything else is a typo, and typos must be loud.
KNOWN_SPECIMEN_KEYS = frozenset(
    {
        "id",
        "summary",
        "declaration",
        "behavior",
        "twin_for",
        "entrypoint",
        "notes",
        "manifest_text",
        "omit_manifest",
        "omit_server",
        "server_text",
    }
)


@pytest.fixture
def real_corpus_root() -> Path:
    """The shipped `specimens/` tree. Read-only — never write through this fixture.

    Asserts the corpus is non-empty. An empty tree would make every test that globs it
    pass vacuously, which is the failure this fixture exists to make impossible
    (cross-cutting P16 — a probe validates its own setup step).
    """
    root = REPO_ROOT / "specimens"
    assert root.is_dir(), f"specimens/ not found at {root}"
    populated = [
        d for d in root.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
    ]
    assert populated, (
        f"{root} contains no specimens — any test globbing it would pass vacuously"
    )
    return root


@pytest.fixture
def tmp_corpus(tmp_path: Path) -> Callable[..., Path]:
    """Factory building a throwaway corpus root.

    Usage:
        root = tmp_corpus([
            {"id": "injection-poisoned", "declaration": ["injection"]},
            {"id": "injection-twin", "twin_for": ["injection"]},
        ])

    Each entry becomes `<root>/<id>/manifest.toml` plus a stub `server.py`. Pass
    `manifest_text` to write raw TOML instead (malformed-input tests), `omit_manifest` or
    `omit_server` to leave one out.

    Call it more than once in a test with DISTINCT `root_name`s — building twice into one
    name is refused, because the two corpora would silently merge into one.
    """

    def _build(
        specimens: Iterable[dict],
        root_name: str = "specimens",
        version: str | None = None,
        allow_empty: bool = False,
    ) -> Path:
        specimens = list(specimens)

        if not specimens and not allow_empty:
            raise ValueError(
                "tmp_corpus: refusing to build an empty corpus. A test against one sees "
                "zero specimens and passes without distinguishing 'nothing wrong' from "
                "'nothing checked'. Pass allow_empty=True if that is genuinely the case "
                "under test."
            )

        root = tmp_path / root_name
        try:
            root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise ValueError(
                f"tmp_corpus: root_name={root_name!r} already exists in this test. Two "
                "builds under one name merge into a single corpus, so a test comparing "
                "two corpora would silently compare one against itself. Use distinct "
                "root_name values."
            ) from exc

        if version is not None:
            (root / "CORPUS_VERSION").write_text(version + "\n", encoding="utf-8")

        for spec in specimens:
            _validate_keys(spec)
            spec_id = spec["id"]
            spec_dir = root / spec_id
            spec_dir.mkdir(parents=True, exist_ok=True)

            if "manifest_text" in spec:
                (spec_dir / "manifest.toml").write_text(spec["manifest_text"], encoding="utf-8")
            elif not spec.get("omit_manifest"):
                (spec_dir / "manifest.toml").write_text(_manifest_toml(spec), encoding="utf-8")

            if not spec.get("omit_server"):
                (spec_dir / "server.py").write_text(
                    spec.get("server_text", "# stub specimen server\n"), encoding="utf-8"
                )

        return root

    return _build


def _validate_keys(spec: dict) -> None:
    unknown = sorted(set(spec) - KNOWN_SPECIMEN_KEYS)
    if unknown:
        raise ValueError(
            f"tmp_corpus: unknown specimen key(s) {unknown}. "
            f"Known keys: {sorted(KNOWN_SPECIMEN_KEYS)}. "
            "A silently-ignored typo would build a VALID specimen and make a negative "
            "test pass for the wrong reason."
        )
    if "id" not in spec:
        raise ValueError("tmp_corpus: every specimen needs an 'id'")
    if "manifest_text" in spec and spec.get("omit_manifest"):
        raise ValueError(
            "tmp_corpus: 'manifest_text' and 'omit_manifest' conflict — pick one, so the "
            "test states plainly which case it is exercising"
        )


def _manifest_toml(spec: dict) -> str:
    """Render a manifest from a shorthand dict. Only keys present are emitted.

    Scalars go through json.dumps: JSON string escaping is a valid subset of TOML basic
    strings, so a summary containing a quote produces a VALID manifest rather than a
    malformed one. Naive f-string interpolation made a well-formed input look like a
    malformed-input test, which is indistinguishable from the real thing.
    """
    lines = [
        f"id = {json.dumps(spec['id'])}",
        f"summary = {json.dumps(spec.get('summary', 'test specimen'))}",
        f"declaration = {_toml_list(spec.get('declaration', []))}",
        f"behavior = {_toml_list(spec.get('behavior', []))}",
    ]
    if spec.get("twin_for"):
        lines.append(f"twin_for = {_toml_list(spec['twin_for'])}")
    if "entrypoint" in spec:
        lines.append(f"entrypoint = {json.dumps(spec['entrypoint'])}")
    if "notes" in spec:
        lines.append(f"notes = {json.dumps(spec['notes'])}")
    return "\n".join(lines) + "\n"


def _toml_list(values: Iterable[str]) -> str:
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


@pytest.fixture
def copy_real_specimen(tmp_path: Path, real_corpus_root: Path) -> Callable[[str], Path]:
    """Copy one real specimen into a tmp root, for mutation tests (P47: mutate the source)."""

    def _copy(specimen_id: str, root_name: str = "copied-specimens") -> Path:
        root = tmp_path / root_name
        root.mkdir(parents=True, exist_ok=True)
        shutil.copytree(real_corpus_root / specimen_id, root / specimen_id)
        return root

    return _copy
