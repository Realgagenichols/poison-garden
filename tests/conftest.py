"""Shared test fixtures.

The `tmp_corpus` factory builds specimen directories on disk in a tmp_path, so corpus
tests never read or mutate the real `specimens/` tree. Tests that need the *real* corpus
say so explicitly via `real_corpus_root`.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def real_corpus_root() -> Path:
    """The shipped `specimens/` tree. Read-only — never write through this fixture."""
    return REPO_ROOT / "specimens"


@pytest.fixture
def tmp_corpus(tmp_path: Path) -> Callable[..., Path]:
    """Factory building a throwaway corpus root.

    Usage:
        root = tmp_corpus([
            {"id": "injection-poisoned", "declaration": ["injection"]},
            {"id": "injection-benign"},
        ])

    Each entry becomes `<root>/<id>/manifest.toml` plus a stub `server.py`, so the
    directory is shaped exactly like a real specimen without carrying its behavior.
    Callers may pass `manifest_text` to write raw TOML instead (malformed-input tests).
    """

    def _build(
        specimens: Iterable[dict],
        root_name: str = "specimens",
        version: str | None = None,
    ) -> Path:
        root = tmp_path / root_name
        root.mkdir(parents=True, exist_ok=True)
        if version is not None:
            (root / "CORPUS_VERSION").write_text(version + "\n", encoding="utf-8")

        for spec in specimens:
            spec_id = spec["id"]
            spec_dir = root / spec_id
            spec_dir.mkdir(parents=True, exist_ok=True)

            if "manifest_text" in spec:
                (spec_dir / "manifest.toml").write_text(spec["manifest_text"], encoding="utf-8")
            elif spec.get("omit_manifest"):
                pass
            else:
                (spec_dir / "manifest.toml").write_text(
                    _manifest_toml(spec), encoding="utf-8"
                )

            if not spec.get("omit_server"):
                (spec_dir / "server.py").write_text(
                    spec.get("server_text", "# stub specimen server\n"), encoding="utf-8"
                )

        return root

    return _build


def _manifest_toml(spec: dict) -> str:
    """Render a manifest from a shorthand dict. Only keys present are emitted."""
    lines = [
        f'id = "{spec["id"]}"',
        f'summary = "{spec.get("summary", "test specimen")}"',
        f"declaration = {_toml_list(spec.get('declaration', []))}",
        f"behavior = {_toml_list(spec.get('behavior', []))}",
    ]
    if spec.get("twin_for"):
        lines.append(f"twin_for = {_toml_list(spec['twin_for'])}")
    if "entrypoint" in spec:
        lines.append(f'entrypoint = "{spec["entrypoint"]}"')
    return "\n".join(lines) + "\n"


def _toml_list(values: Iterable[str]) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


@pytest.fixture
def copy_real_specimen(tmp_path: Path, real_corpus_root: Path) -> Callable[[str], Path]:
    """Copy one real specimen into a tmp root, for mutation tests (P47: mutate the source)."""

    def _copy(specimen_id: str, root_name: str = "specimens") -> Path:
        root = tmp_path / root_name
        root.mkdir(parents=True, exist_ok=True)
        shutil.copytree(real_corpus_root / specimen_id, root / specimen_id)
        return root

    return _copy
