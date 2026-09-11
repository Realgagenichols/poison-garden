"""CLI command tests — R3, R4, cross-cutting P6 and P55.

The exit codes carry meaning: 0 fine, 1 the corpus is invalid, 2 poison-garden broke. A
crash that exits 1 would masquerade as a corpus finding, which is the milder result and the
wrong one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from poison_garden.cli import EXIT_CORPUS_INVALID, EXIT_OK, EXIT_TOOL_ERROR, main

POISONED = {"id": "injection-poisoned", "declaration": ["injection"]}
TWIN = {"id": "injection-twin", "twin_for": ["injection"]}


# --- validate -----------------------------------------------------------------------------


def test_validate_ok_exits_zero(tmp_corpus, capsys):
    root = tmp_corpus([POISONED, TWIN])
    code = main(["validate", "--corpus", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "OK:" in out


def test_validate_missing_twin_exits_corpus_invalid(tmp_corpus, capsys):
    root = tmp_corpus([POISONED])
    code = main(["validate", "--corpus", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_CORPUS_INVALID
    assert "injection" in out


def test_validate_vacuous_corpus_does_not_report_success(tmp_corpus, capsys):
    root = tmp_corpus([{"id": "only-a-twin"}])
    code = main(["validate", "--corpus", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_CORPUS_INVALID
    assert "VACUOUS" in out


def test_validate_malformed_manifest_is_corpus_invalid_not_tool_error(tmp_corpus, capsys):
    """P55: a bad manifest is a finding about the corpus (1), not a crash (2)."""
    root = tmp_corpus([{"id": "broken", "manifest_text": 'id = "broken"\nbogus = 1\n'}])
    code = main(["validate", "--corpus", str(root)])
    err = capsys.readouterr().err
    assert code == EXIT_CORPUS_INVALID
    assert "corpus invalid" in err


def test_validate_missing_corpus_root_is_corpus_invalid(tmp_path: Path, capsys):
    code = main(["validate", "--corpus", str(tmp_path / "absent")])
    assert code == EXIT_CORPUS_INVALID
    assert "not a directory" in capsys.readouterr().err


# --- hash ---------------------------------------------------------------------------------


def test_hash_prints_version_and_digest(tmp_corpus, capsys):
    root = tmp_corpus([POISONED, TWIN], version="2.1.0")
    code = main(["hash", "--corpus", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "2.1.0" in out
    assert "sha256:" in out


def test_hash_is_stable_between_invocations(tmp_corpus, capsys):
    root = tmp_corpus([POISONED, TWIN])
    main(["hash", "--corpus", str(root)])
    first = capsys.readouterr().out
    main(["hash", "--corpus", str(root)])
    second = capsys.readouterr().out
    assert first == second


def test_hash_on_broken_corpus_is_corpus_invalid(tmp_corpus, capsys):
    root = tmp_corpus([{"id": "no-manifest", "omit_manifest": True}])
    code = main(["hash", "--corpus", str(root)])
    assert code == EXIT_CORPUS_INVALID


# --- P6 / P55: a crash must never read as the milder result --------------------------------


def test_unexpected_exception_exits_tool_error_not_corpus_invalid(tmp_corpus, monkeypatch, capsys):
    """An internal fault is exit 2. Exit 1 means 'your corpus is bad' and must not lie."""
    import poison_garden.commands as commands

    def _boom(_root):
        raise RuntimeError("simulated internal fault")

    monkeypatch.setattr(commands, "load_corpus", _boom)

    code = main(["validate", "--corpus", str(tmp_corpus([POISONED, TWIN]))])
    err = capsys.readouterr().err
    assert code == EXIT_TOOL_ERROR, "an internal crash must not exit 1"
    assert "RuntimeError" in err, "the error must name the exception type (P6)"


def test_tool_error_names_the_exception_type(tmp_corpus, monkeypatch, capsys):
    import poison_garden.commands as commands

    monkeypatch.setattr(
        commands, "load_corpus", lambda _root: (_ for _ in ()).throw(KeyError("inner"))
    )
    main(["validate", "--corpus", str(tmp_corpus([POISONED]))])
    assert "KeyError" in capsys.readouterr().err


# --- the three exit codes are genuinely distinct -------------------------------------------


def test_three_outcomes_produce_three_distinct_exit_codes(tmp_corpus, tmp_path: Path):
    """P55: two empties are two findings. Run the real binary for each outcome."""
    ok_root = tmp_corpus([POISONED, TWIN], root_name="ok")
    bad_root = tmp_corpus([POISONED], root_name="bad")

    def _run(args: list[str]) -> int:
        return subprocess.run(
            [sys.executable, "-m", "poison_garden.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=tmp_path,
        ).returncode

    ok = _run(["validate", "--corpus", str(ok_root)])
    invalid = _run(["validate", "--corpus", str(bad_root)])
    usage = _run([])  # no subcommand at all

    assert ok == EXIT_OK
    assert invalid == EXIT_CORPUS_INVALID
    assert usage == EXIT_TOOL_ERROR
    assert len({ok, invalid, usage}) == 3, "the three outcomes must be distinguishable"
