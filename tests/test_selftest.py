"""`poison-garden selftest` — R22.

The gap this closes was found by putting the submission path in front of someone who had
not written it. The benign twins catch a scanner that flags EVERYTHING; nothing caught one
that flags NOTHING. A wrapper whose exit codes are not plumbed through produces a
schema-valid, CI-passing result document reading 0 caught across every class and 0 false
positives — and in the artifact that is indistinguishable from a scanner which genuinely
detects nothing.

`selftest` is advisory and deliberately not a refusal on the full run: a scanner that truly
detects nothing is entitled to publish that, and suppressing it would be the corpus editing
someone else's result.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from poison_garden.cli import EXIT_OK, EXIT_TOOL_ERROR

REPO_ROOT = Path(__file__).resolve().parent.parent
CONSOLE = Path(sys.executable).parent / "poison-garden"


def _scanner(tmp_path: Path, body: str, name: str) -> str:
    path = tmp_path / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return f"{sys.executable} {path} {{target}}"


def _selftest(scanner: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(CONSOLE), "selftest", "--scanner", scanner],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
    )


def test_an_unwired_scanner_is_caught(tmp_path: Path):
    """THE case. Exit 0 always — the shape a half-finished wrapper has."""
    proc = _selftest(_scanner(tmp_path, "import sys; sys.exit(0)\n", "unwired"))
    assert proc.returncode == EXIT_TOOL_ERROR
    combined = proc.stdout + proc.stderr
    assert "flagged NOTHING" in combined
    # The diagnostic must name what to check, not merely that something is wrong.
    assert "--flag-on" in combined
    assert "{target}" in combined


def test_a_scanner_that_flags_everything_is_caught(tmp_path: Path):
    """The mirror. Full recall and a 100% false-positive rate is also a wiring smell."""
    proc = _selftest(_scanner(tmp_path, "import sys; sys.exit(1)\n", "flagall"))
    assert proc.returncode == EXIT_TOOL_ERROR
    assert "flagged everything" in proc.stdout + proc.stderr


def test_a_correctly_wired_scanner_passes(tmp_path: Path):
    """CONTROL (P49). Without this, a selftest that failed everything would satisfy both
    tests above and be worse than useless — it would turn away every real vendor."""
    body = (
        "import sys\n"
        'target = " ".join(sys.argv[1:])\n'
        'sys.exit(0 if "twin" in target else 1)\n'
    )
    proc = _selftest(_scanner(tmp_path, body, "sane"))
    assert proc.returncode == EXIT_OK, proc.stdout + proc.stderr
    assert "Looks wired" in proc.stdout


def test_selftest_probes_both_malicious_and_benign(tmp_path: Path):
    """A probe set of only malicious specimens could not tell 'unwired' from 'flags all'."""
    body = (
        "import sys\n"
        'target = " ".join(sys.argv[1:])\n'
        'sys.exit(0 if "twin" in target else 1)\n'
    )
    proc = _selftest(_scanner(tmp_path, body, "sane2"))
    assert "malicious" in proc.stdout and "benign" in proc.stdout
    assert "blatant specimen" in proc.stdout and "benign twin" in proc.stdout


def test_a_broken_template_fails_before_any_specimen_runs(tmp_path: Path):
    """Fail fast at the boundary (P6): no {target} means the scanner never sees a specimen."""
    proc = subprocess.run(
        [str(CONSOLE), "selftest", "--scanner", "echo no-placeholder-here"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == EXIT_TOOL_ERROR
    assert "template" in (proc.stdout + proc.stderr).lower()


@pytest.mark.parametrize("flag", ["--corpus", "--scanner", "--flag-on", "--timeout"])
def test_every_documented_flag_exists_on_the_parser(flag: str):
    """REGRESSION: `--sarif` was once wired into dispatch and never added to the parser,
    so `run` raised AttributeError on every invocation while the suite stayed green."""
    from poison_garden.cli import build_parser

    help_text = build_parser().parse_args(["selftest", "--scanner", "x {target}"])
    assert hasattr(help_text, flag.lstrip("-").replace("-", "_"))
