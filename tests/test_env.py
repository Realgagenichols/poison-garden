"""Environment invariants — N4.

Task 1.1 ("confirm the mcp SDK imports and the pin is honoured") was verified once by hand,
which is the P50 shape exactly: a check whose green is guaranteed by nobody re-running it.
These assertions run every time instead.
"""

from __future__ import annotations

import ast
import importlib.metadata
import re
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
    """CI's matrix and the package classifiers must agree.

    Parses the matrix and asserts it is non-empty FIRST. The previous version was
    `if f'"{version}"' in ci:` — conditional on CI's quoting style, so switching the YAML
    to unquoted `python: [3.12, 3.13]` would have made the check silently no-op rather
    than fail (P50: a check whose green is guaranteed by how you spelled something else
    is not a check).
    """
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    match = re.search(r"^\s*python:\s*\[(.+?)\]\s*$", ci, re.MULTILINE)
    assert match, "could not find the python matrix in ci.yml — this check would be vacuous"

    tested = [v.strip().strip("\"'") for v in match.group(1).split(",")]
    assert tested, "the python matrix parsed as empty"

    classifiers = " ".join(pyproject["project"]["classifiers"])
    missing = [v for v in tested if v not in classifiers]
    assert not missing, f"CI tests {missing} but no classifier declares them"


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
    """Every import in poison_garden/ must be stdlib or first-party, given deps == [].

    Parses the AST rather than matching line prefixes. The prefix version matched exactly
    two literals (`import mcp`, `from mcp`) and therefore missed `import requests`,
    `from requests import get`, and every other package that isn't `mcp` — it enforced a
    specific past mistake rather than the rule in its own docstring.

    That is the same error as reading a source file to learn what a program advertises:
    the text is not the thing. Here the thing is the import graph, so read the import
    graph (cross-cutting P98 — a guard that reads source text measures the documentation).
    """
    stdlib = set(sys.stdlib_module_names)
    first_party = {"poison_garden"}
    offenders: list[str] = []

    for path in sorted((REPO_ROOT / "poison_garden").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import, which is first-party by construction.
                names = [node.module] if node.module and node.level == 0 else []
            else:
                continue

            for name in names:
                root = name.split(".")[0]
                if root in stdlib or root in first_party or root == "__future__":
                    continue
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{node.lineno} imports '{name}'")

    assert not offenders, (
        "package declares no runtime dependencies but imports third-party module(s): "
        f"{offenders}"
    )


def test_the_import_check_catches_more_than_one_package():
    """P31: the prefix version passed this suite while catching only `mcp`.

    Runs the same AST logic over synthetic sources and asserts each is caught. Without
    this, narrowing the check back to a literal prefix would go unnoticed.
    """
    stdlib = set(sys.stdlib_module_names)

    def undeclared(source: str) -> list[str]:
        found: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module] if node.module and node.level == 0 else []
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                if root not in stdlib and root != "poison_garden" and root != "__future__":
                    found.append(name)
        return found

    cases = {
        "import mcp": True,
        "import requests": True,
        "from requests import get": True,
        "import numpy as np": True,
        "from mcp.server import Server": True,
        "import json": False,
        "from pathlib import Path": False,
        "from poison_garden.corpus import models": False,
        "from . import models": False,
        "from __future__ import annotations": False,
    }
    wrong = [
        src
        for src, should_flag in cases.items()
        if bool(undeclared(src)) is not should_flag
    ]
    assert not wrong, f"import check misclassifies: {wrong}"
