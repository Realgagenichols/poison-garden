"""Console-script smoke tests (N4, cross-cutting P9).

`pythonpath` in pyproject saves pytest but NOT the installed console script — frisk shipped
a broken CLI entry point twice while its whole suite stayed green. These tests drive the
INSTALLED binary, not the imported module.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from poison_garden.cli import EXIT_TOOL_ERROR, build_parser

# The console script lives beside the interpreter running the tests. Resolving it this way
# (rather than via PATH) means an ABSENT script fails the test instead of skipping it —
# absence is precisely the P9 breakage this test exists to catch, and a skip would be the
# same silence (P55: a skip and a pass are two findings; one status distinguishes neither).
CONSOLE_SCRIPT = Path(sys.executable).parent / "poison-garden"


def test_parser_builds_and_lists_subcommands():
    parser = build_parser()
    help_text = parser.format_help()
    assert "validate" in help_text
    assert "hash" in help_text


def test_console_script_exists():
    """No skipif: a missing entry point is a failure, not a reason to stay quiet."""
    assert CONSOLE_SCRIPT.exists(), (
        f"console script not found at {CONSOLE_SCRIPT}. "
        "Run `uv sync` with UV_PROJECT_ENVIRONMENT set outside ~/Desktop "
        "(see tasks/lessons.md — hidden .pth files break the editable install)."
    )


def test_installed_console_script_runs_help(tmp_path: Path):
    """The INSTALLED entry point must work, not merely the importable module (P9).

    Runs from an unrelated cwd on purpose: a console script's `sys.path[0]` is its own
    directory, NOT the caller's cwd, so running from the repo root would mask a broken
    editable install by finding the package on the cwd path.
    """
    proc = subprocess.run(
        [str(CONSOLE_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    assert "poison-garden" in proc.stdout


def test_installed_console_script_can_import_its_own_package(tmp_path: Path):
    """Regression: a hidden `.pth` under ~/Desktop broke exactly this and nothing else.

    Asserts on the TOP-LEVEL package name specifically. A broader "no ModuleNotFoundError
    anywhere" check would also redden for a submodule that simply has not been written yet,
    which makes it a build-order alarm rather than a regression guard (P49 — assert the
    filter narrows, and to the right thing).
    """
    proc = subprocess.run(
        [str(CONSOLE_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=tmp_path,
    )
    assert "No module named 'poison_garden'" not in proc.stderr, (
        f"the console script cannot import its own package from cwd={tmp_path}; "
        "the editable install is broken (hidden .pth — see tasks/lessons.md)"
    )
    assert proc.returncode == 0, proc.stderr


def test_module_entry_point_runs_help():
    """Fallback path that works even before `uv tool install`."""
    proc = subprocess.run(
        [sys.executable, "-m", "poison_garden.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "validate" in proc.stdout


def test_no_subcommand_is_a_tool_error_not_success():
    """Bad usage must not exit 0. argparse uses 2, which is our EXIT_TOOL_ERROR."""
    proc = subprocess.run(
        [sys.executable, "-m", "poison_garden.cli"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == EXIT_TOOL_ERROR


# --- every subcommand's flags must reach its handler -------------------------------------


def test_every_run_flag_the_handler_reads_exists_on_the_parser():
    """REGRESSION: `--sarif` was wired into the dispatch but never added to the parser.

    `poison-garden run` crashed with AttributeError on EVERY invocation, and the suite did
    not notice because the `cmd_run` tests call the function directly and never go through
    argparse. Testing a handler is not testing the command — the wiring between them is its
    own surface, and this is the second time that seam has produced a defect.
    """
    import argparse
    import ast

    from poison_garden.cli import build_parser

    parser = build_parser()
    subparsers = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )

    source = ast.parse(Path(__file__).resolve().parent.parent.joinpath(
        "poison_garden", "cli.py"
    ).read_text(encoding="utf-8"))

    # Every `args.<name>` the dispatch reads must be a destination some parser defines.
    read_attrs: set[str] = set()
    for node in ast.walk(source):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "args"
        ):
            read_attrs.add(node.attr)

    defined: set[str] = {"command", "debug"}
    for sub in subparsers.choices.values():
        defined |= {a.dest for a in sub._actions}

    missing = sorted(read_attrs - defined)
    assert not missing, (
        f"main() reads args.{missing} but no parser defines it — the command will raise "
        "AttributeError on every invocation"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["validate", "--corpus", "specimens"],
        ["hash", "--corpus", "specimens"],
        ["validate-result", "results"],
        ["leaderboard", "--check"],
        ["run", "--scanner", "x {target}", "--out", "o.json"],
    ],
    ids=lambda a: a[0],
)
def test_every_subcommand_parses(argv):
    """Parsing is the cheapest possible smoke test and it would have caught the above."""
    from poison_garden.cli import build_parser

    parsed = build_parser().parse_args(argv)
    assert parsed.command == argv[0]
