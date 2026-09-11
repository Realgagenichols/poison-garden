"""Guards for requirements that were true by inspection and asserted nowhere — R8, S4, S5.

Both requirements here were *satisfied* and *unguarded*, which is a different thing. R8 held
because no networking import existed in the runner; S4 held because the README prose happened
to be right. Neither had a test, so both were one commit away from silently becoming false.

R8's guard gets sharper in M3, not softer: M3 legitimately introduces socket code into the
runner for the egress sink, at which point "the runner makes no network requests" stops being
obvious by inspection. Drawing the module boundary now — while it is still obvious — is the
point. `runner/sandbox.py` may bind a loopback listener; `runner/execute.py`, `runner/target.py`
and everything under `scoring/` may not touch the network at all.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

NETWORK_MODULES = frozenset(
    {"socket", "ssl", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib", "smtplib"}
)

# Modules that must never reach the network. sandbox.py is deliberately absent: it binds the
# loopback egress sink, which is how a specimen's exfiltration attempt is caught without a
# packet leaving the machine.
NO_NETWORK_MODULES = (
    "poison_garden/runner/execute.py",
    "poison_garden/runner/target.py",
    "poison_garden/scoring/score.py",
    "poison_garden/scoring/document.py",
    "poison_garden/commands.py",
    "poison_garden/cli.py",
)


def _imports_in(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module, node.lineno))
    return found


@pytest.mark.parametrize("relative", NO_NETWORK_MODULES)
def test_no_network_import_in_the_run_path(relative: str):
    """R8: a run makes no network requests of its own.

    True by construction today. Asserted so that adding `urllib` in a later milestone is a
    visible decision rather than an invisible one.
    """
    path = REPO_ROOT / relative
    assert path.is_file(), f"{relative} does not exist — this guard would be vacuous"

    offenders = [
        f"{relative}:{lineno} imports {name}"
        for name, lineno in _imports_in(path)
        if name.split(".")[0] in NETWORK_MODULES
    ]
    assert not offenders, f"network import in the run path (R8): {offenders}"


def test_the_network_guard_can_actually_fire():
    """P31: a guard over a population that happens to be clean proves nothing yet.

    Runs the same detection over synthetic sources and asserts each is caught, so the
    guard's discriminating power does not depend on the current code being clean.
    """
    cases = {
        "import socket": True,
        "import urllib.request": True,
        "from http.client import HTTPConnection": True,
        "import requests": True,
        "from httpx import Client": True,
        "import json": False,
        "from pathlib import Path": False,
        "import subprocess": False,
    }
    wrong = []
    for source, should_flag in cases.items():
        tree = ast.parse(source)
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module)
        flagged = any(n.split(".")[0] in NETWORK_MODULES for n in names)
        if flagged is not should_flag:
            wrong.append(source)
    assert not wrong, f"network guard misclassifies: {wrong}"


def test_sandbox_is_the_only_networking_module_and_is_loopback_only():
    """The one module allowed to touch the network must still be loopback-only.

    Stated as an assertion rather than a comment, because M3 adds egress-behaviour
    specimens and this is the line that keeps "the sink" from growing into "the network".
    """
    sandbox = REPO_ROOT / "poison_garden/runner/sandbox.py"
    names = [n for n, _ in _imports_in(sandbox)]
    assert "socket" in names, "sandbox.py is expected to own the loopback sink"

    source = sandbox.read_text(encoding="utf-8")
    assert 'host: str = "127.0.0.1"' in source, "the sink must default to loopback"
    for outbound in ("connect(", "urlopen", "gethostbyname", "0.0.0.0"):
        assert outbound not in source, f"sandbox.py performs outbound networking: {outbound}"


# --- S4 / S5: the README makes safety claims that nothing guarded ------------------------

README = REPO_ROOT / "README.md"

# Each phrase corresponds to a clause of S4/S5. Losing one is losing the requirement, and
# the last time this prose changed the commit message was "correct a README overstatement" —
# a change nothing would have caught going the other way.
REQUIRED_README_CLAUSES = (
    ("intentionally malicious", "S4: the repo must say what it contains"),
    ("The harness is not a sandbox", "S5: non-containment stated plainly"),
    ("naming convention, not", "S5: names the mechanism, not a reassurance"),
    ("do not run third-party or modified specimens", "S5: tells the reader what not to do"),
    ("decoy", "S4: specimens read decoys"),
    ("loopback", "S4: egress goes to a loopback sink"),
)


@pytest.mark.parametrize(
    ("phrase", "why"), REQUIRED_README_CLAUSES, ids=[c[0][:28] for c in REQUIRED_README_CLAUSES]
)
def test_readme_states_its_safety_claims(phrase: str, why: str):
    """S4/S5: their scenarios are entirely about README content, and nothing read it.

    `tests/test_sandbox.py` mentions the Safety section in a docstring while its body reads
    specimen sources — the same "measuring the file rather than the thing" gap recorded in
    lessons, from the other side.
    """
    assert README.is_file()
    text = README.read_text(encoding="utf-8").lower()
    assert phrase.lower() in text, f"README no longer states — {why}"


def test_readme_does_not_call_the_harness_a_sandbox_without_qualifying_it():
    """S5 forbids describing the harness as containment.

    The word may appear (it appears in 'The harness is not a sandbox'), so this checks that
    every occurrence sits within a negating clause rather than banning the word outright —
    a ban would be trivially satisfied by a synonym.
    """
    import re as _re

    text = README.read_text(encoding="utf-8")
    negated = ("not a sandbox", "is not a sandbox", "not a jail")
    for line in text.splitlines():
        # Strip inline code spans and fenced-block content first: `sandbox.py` is a
        # filename, not a claim about containment, and a guard that cannot tell prose from
        # a path reports the wrong thing (P86 — ask what the instrument touched).
        prose = _re.sub(r"`[^`]*`", "", line)
        if "sandbox" in prose.lower() and not any(n in prose.lower() for n in negated):
            pytest.fail(f"README describes a sandbox without qualification: {line.strip()!r}")


def test_the_sandbox_wording_guard_can_fire():
    """P31: the guard above passes on current prose; prove it would catch a regression."""
    import re as _re

    def offends(line: str) -> bool:
        prose = _re.sub(r"`[^`]*`", "", line)
        negated = ("not a sandbox", "is not a sandbox", "not a jail")
        return "sandbox" in prose.lower() and not any(n in prose.lower() for n in negated)

    assert offends("Every specimen runs safely inside our sandbox.") is True
    assert offends("The harness is not a sandbox.") is False
    assert offends("see `poison_garden/runner/sandbox.py` for details") is False


def test_readme_safety_section_exists_and_is_substantial():
    """Vacuity guard: the phrase assertions above pass against a one-line Safety section."""
    text = README.read_text(encoding="utf-8")
    assert "## Safety" in text
    section = text.split("## Safety", 1)[1].split("\n## ", 1)[0]
    assert len(section.strip().splitlines()) >= 10, (
        "the Safety section is too short to carry the claims S4/S5 require of it"
    )


def test_python_version_of_this_suite_matches_the_pin():
    """Cheap cross-check: these guards must run on the interpreter CI pins."""
    pinned = (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip()
    assert f"{sys.version_info.major}.{sys.version_info.minor}" == pinned
