"""Environment invariants — N4.

Task 1.1 ("confirm the mcp SDK imports and the pin is honoured") was verified once by hand,
which is the P50 shape exactly: a check whose green is guaranteed by nobody re-running it.
These assertions run every time instead.
"""

from __future__ import annotations

import importlib.metadata
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_python_is_at_least_the_declared_minimum(pyproject):
    requires = pyproject["project"]["requires-python"]
    assert requires.startswith(">=3.12")
    assert sys.version_info >= (3, 12), f"running on {sys.version_info}"


def test_python_version_pin_matches_requires_python(pyproject):
    """The pin, requires-python, and the classifiers must not drift apart."""
    pinned = (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip()
    assert pyproject["project"]["requires-python"].startswith(f">={pinned}")

    classifiers = pyproject["project"]["classifiers"]
    assert any(pinned in c for c in classifiers), (
        f"the pinned interpreter {pinned} has no matching classifier"
    )


def test_every_tested_python_has_a_classifier(pyproject):
    """CI matrixes 3.12 and 3.13; both must be declared or the metadata understates support."""
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    classifiers = " ".join(pyproject["project"]["classifiers"])
    for version in ("3.12", "3.13"):
        if f'"{version}"' in ci:
            assert version in classifiers, f"CI tests {version} but no classifier declares it"


def test_mcp_sdk_imports_and_pin_is_honoured():
    """The SDK is a dev dependency; specimens speak JSON-RPC by hand deliberately."""
    import mcp  # noqa: F401

    version = importlib.metadata.version("mcp")
    major, minor, *_ = (int(part) for part in version.split(".")[:2])
    assert (major, minor) == (1, 27), (
        f"mcp {version} is outside the tested band >=1.27.2,<1.28"
    )


def test_package_declares_no_runtime_dependencies(pyproject):
    """Guard against re-adding an unused hard dependency.

    `mcp` was a runtime dep while nothing in the package imported it, which constrains
    every consumer's resolver for a module that is never loaded. If the M2 runner genuinely
    needs it at runtime, move it back AND add the import that justifies it — then this
    assertion should be updated deliberately rather than deleted.
    """
    assert pyproject["project"]["dependencies"] == [], (
        "a runtime dependency was added; confirm the package actually imports it"
    )


def test_no_runtime_module_imports_an_undeclared_third_party_package():
    """Every import in poison_garden/ must be stdlib or first-party, given deps == []."""
    offenders: list[str] = []
    for path in (REPO_ROOT / "poison_garden").rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("import mcp", "from mcp")):
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno}")
    assert not offenders, (
        f"package imports `mcp` at {offenders} but declares no runtime dependencies"
    )
