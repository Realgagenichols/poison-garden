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


# Call names that would make the sink a client rather than a listener. Matched against the
# PARSED call graph, never against source text: the substring form asserted `"connect(" not
# in source` and broke on a docstring explaining that "a client's `connect()` returns once
# the connection is queued". That is the same defect as a `\bpath\b` rule matching
# `from pathlib import Path` — it matched the topic, and prose about networking is exactly
# what a module owning the sink should contain (P90 — a scripted check over code needs a
# parser, not a grep).
_OUTBOUND_CALLS = frozenset(
    {"connect", "connect_ex", "create_connection", "urlopen", "gethostbyname", "urlretrieve"}
)


def _called_names(path) -> set[str]:
    """Every function or method name actually invoked in a module."""
    import ast

    called: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            called.add(func.id)
        elif isinstance(func, ast.Attribute):
            called.add(func.attr)
    return called


def test_sandbox_is_the_only_networking_module_and_is_loopback_only():
    """The one module allowed to touch the network must still be loopback-only.

    Stated as an assertion rather than a comment, because the egress-behaviour specimens
    make this the line that keeps "the sink" from growing into "the network".
    """
    sandbox = REPO_ROOT / "poison_garden/runner/sandbox.py"
    names = [n for n, _ in _imports_in(sandbox)]
    assert "socket" in names, "sandbox.py is expected to own the loopback sink"

    source = sandbox.read_text(encoding="utf-8")
    assert 'host: str = "127.0.0.1"' in source, "the sink must default to loopback"
    assert "0.0.0.0" not in source, "the sink must not bind every interface"

    outbound = sorted(_called_names(sandbox) & _OUTBOUND_CALLS)
    assert not outbound, f"sandbox.py performs outbound networking: {outbound}"


def test_the_outbound_call_guard_catches_a_real_outbound_call(tmp_path):
    """P31/P50: the guard now parses rather than greps, so prove it still fires.

    Also proves it does NOT fire on prose — the exact regression that prompted the rewrite.
    """
    offender = tmp_path / "offender.py"
    offender.write_text("import socket\ns = socket.socket()\ns.connect(('10.0.0.1', 80))\n")
    assert _called_names(offender) & _OUTBOUND_CALLS == {"connect"}

    innocent = tmp_path / "innocent.py"
    innocent.write_text('"""A client\'s `connect()` returns once queued."""\nx = 1\n')
    assert not _called_names(innocent) & _OUTBOUND_CALLS, (
        "the guard fires on a docstring mentioning connect() — it is greping again"
    )


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
    (
        "no packet can",
        "S4: specimens now DO open sockets, so the banner must say why that is safe "
        "rather than claiming no network activity happens at all",
    ),
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


def test_readme_quoted_result_figures_match_the_committed_document():
    """The README says "Everything below is real output". This is what makes that true.

    A figure pasted into prose decays the moment the corpus changes, and it decays quietly
    and in whichever direction flatters. It already did once: the interval was published as
    `0.3902` against a document that says `0.3903`, because it was computed rather than
    copied — an error too small to notice by reading and exactly the kind R18 exists to stop
    being casual about.

    Parses the JSON block the README quotes and asserts every field matches the committed
    result document for that class (P68 — a published figure needs a mechanical relation to
    its source).
    """
    import json
    import re

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    blocks = [
        b for b in re.findall(r"```json\n(.*?)```", readme, re.S) if "recall_ci95" in b
    ]
    assert blocks, (
        "the README quotes no result JSON — if that section was removed, remove this test; "
        "if it was reformatted, this guard has stopped guarding anything (P58)"
    )

    documents = sorted((REPO_ROOT / "results").glob("*.json"))
    assert documents, "no committed result document to check the README against"
    payload = json.loads(documents[0].read_text(encoding="utf-8"))
    by_class = {e["class"]: e for e in payload["per_class"]}

    for block in blocks:
        quoted = json.loads(block)
        actual = by_class.get(quoted["class"])
        assert actual is not None, (
            f"the README quotes class {quoted['class']!r}, which the result document does "
            "not contain"
        )
        for field, value in quoted.items():
            assert actual[field] == value, (
                f"README quotes {quoted['class']}.{field} = {value!r}, but "
                f"{documents[0].name} says {actual[field]!r}. Copy the figure from the "
                "document; do not recompute it."
            )


def test_linked_documents_are_tracked_and_present():
    """Every repo-relative link in a shipped document must resolve AND be in git.

    This is the third instance of one defect. A blanket `*.lock` swallowed two specimens'
    data files, so two specimens crashed on import for everyone who cloned while passing
    locally. A blanket `docs/` then swallowed `docs/tier-reliability.md`, which README,
    CONTRIBUTING and SPEC all link to. Both times the file existed on the author's disk, so
    every check that reads the filesystem was satisfied — including the guard written after
    the first one, which only covers specimens.

    The question is not "does this file exist here" but "does the repository ship what it
    links to". Those differ exactly when a `.gitignore` pattern is broader than intended,
    which is the failure mode that keeps recurring.
    """
    import re
    import subprocess

    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout; tracked-ness is not a question that applies here")

    tracked = set(
        subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO_ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.split("\0")
    )
    assert tracked, "git ls-files returned nothing — this guard would pass vacuously (P58)"

    # Documents a reader actually receives. SPEC.md is deliberately excluded: it is local by
    # design, so its links are not promises to anyone.
    shipped = ["README.md", "CONTRIBUTING.md", "KNOWN-MISSES.md", "COMPARISON.md"]
    link = re.compile(r"\[[^\]]+\]\(([^)#]+)\)")

    broken: list[str] = []
    for name in shipped:
        doc = REPO_ROOT / name
        if not doc.is_file():
            continue
        for target in link.findall(doc.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            rel = (doc.parent / target).resolve()
            try:
                as_posix = str(rel.relative_to(REPO_ROOT))
            except ValueError:
                broken.append(f"{name} -> {target} (escapes the repository)")
                continue
            if not rel.exists():
                broken.append(f"{name} -> {target} (does not exist)")
            elif rel.is_file() and as_posix not in tracked:
                broken.append(f"{name} -> {target} (exists locally but is NOT in git)")

    assert not broken, (
        "shipped documents link to things the repository does not ship:\n  "
        + "\n  ".join(broken)
        + "\nCheck `.gitignore` — a blanket pattern is the usual cause."
    )
