"""Manifest parsing.

A manifest is **external input**, even though we wrote it (cross-cutting P13). Every
failure mode gets a distinct, specific error naming the offending key — a typo'd class name
must never silently become "no class", because that would quietly turn a malicious specimen
into a benign one and corrupt every score computed from it.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from poison_garden.corpus.models import Class, Manifest, ManifestError

MANIFEST_NAME = "manifest.toml"

REQUIRED_KEYS = frozenset({"id", "summary"})
OPTIONAL_KEYS = frozenset({"declaration", "behavior", "entrypoint", "notes"})
KNOWN_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS


def parse_manifest(path: Path) -> Manifest:
    """Parse and validate one `manifest.toml`.

    Raises ManifestError on any defect, naming the file and the offending key.
    """
    try:
        raw_bytes = path.read_bytes()
    except (FileNotFoundError, NotADirectoryError) as exc:
        # Both errnos mean "the path is gone" — catching only ENOENT lets parent-directory
        # tampering masquerade as something milder (frisk lesson).
        raise ManifestError(f"{path}: manifest not found ({type(exc).__name__})") from exc

    try:
        data: dict[str, Any] = tomllib.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ManifestError(f"{path}: manifest is not valid UTF-8") from exc
    except tomllib.TOMLDecodeError as exc:
        # Report the parser's positional message but never interpolate raw file content
        # (cross-cutting P11 — exception reprs leak input values).
        raise ManifestError(f"{path}: malformed TOML ({type(exc).__name__})") from exc

    _reject_unknown_keys(path, data)
    _require_keys(path, data)

    return Manifest(
        id=_str_field(path, data, "id"),
        summary=_str_field(path, data, "summary"),
        declaration=_class_list(path, data, "declaration"),
        behavior=_class_list(path, data, "behavior"),
        entrypoint=_str_field(path, data, "entrypoint", default="server.py"),
        notes=_str_field(path, data, "notes", default=""),
    )


def _reject_unknown_keys(path: Path, data: dict[str, Any]) -> None:
    unknown = sorted(set(data) - KNOWN_KEYS)
    if unknown:
        raise ManifestError(
            f"{path}: unknown key(s) {unknown}. "
            f"Known keys are {sorted(KNOWN_KEYS)}. "
            "A typo'd key is rejected rather than ignored, so a mislabelled specimen "
            "cannot silently become benign."
        )


def _require_keys(path: Path, data: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_KEYS - set(data))
    if missing:
        raise ManifestError(f"{path}: missing required key(s) {missing}")


def _str_field(
    path: Path, data: dict[str, Any], key: str, default: str | None = None
) -> str:
    if key not in data:
        if default is None:
            raise ManifestError(f"{path}: missing required key '{key}'")
        return default
    value = data[key]
    if not isinstance(value, str):
        raise ManifestError(
            f"{path}: key '{key}' must be a string, got {type(value).__name__}"
        )
    if not value.strip() and default is None:
        raise ManifestError(f"{path}: key '{key}' must not be empty")
    return value


def _class_list(path: Path, data: dict[str, Any], key: str) -> tuple[Class, ...]:
    """Parse a class list. Absent is an empty list — that is legal and meaningful (R2)."""
    if key not in data:
        return ()

    value = data[key]
    if not isinstance(value, list):
        raise ManifestError(
            f"{path}: key '{key}' must be a list, got {type(value).__name__}"
        )

    out: list[Class] = []
    valid = sorted(c.value for c in Class)
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ManifestError(
                f"{path}: {key}[{index}] must be a string, got {type(item).__name__}"
            )
        try:
            out.append(Class(item))
        except ValueError as exc:
            raise ManifestError(
                f"{path}: {key}[{index}] is not a known class: '{item}'. "
                f"Valid classes are {valid}."
            ) from exc

    duplicates = sorted({c.value for c in out if out.count(c) > 1})
    if duplicates:
        raise ManifestError(f"{path}: key '{key}' contains duplicate class(es) {duplicates}")

    return tuple(out)
