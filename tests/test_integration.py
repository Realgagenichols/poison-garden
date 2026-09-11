"""End-to-end tests against the REAL shipped corpus — R1–R4, S1, S2.

Everything else in the suite runs against synthetic corpora built in tmp_path. These tests
drive the actual `specimens/` tree, because a corpus that loads only in fixtures is not a
corpus (cross-cutting P53 — green tests are not a used application).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from poison_garden.cli import EXIT_OK, main
from poison_garden.corpus.hash import corpus_hash
from poison_garden.corpus.loader import load_corpus
from poison_garden.corpus.models import Class
from poison_garden.corpus.validate import validate_corpus

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIMENS = REPO_ROOT / "specimens"

# The six declaration classes M1 is required to cover. Listed LITERALLY rather than derived
# from the corpus under test: deriving them would rename the expectation along with the
# corpus, so removing a whole class would stay green (P76, and frisk's parametrize lesson).
M1_DECLARATION_CLASSES = (
    Class.INJECTION,
    Class.HIDDEN_CONTENT,
    Class.SENSITIVE_PARAMS,
    Class.SCOPE_MISMATCH,
    Class.IMPERSONATION,
    Class.HYGIENE,
)


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


# --- R1–R4: the real corpus loads, validates, and hashes --------------------------------


def test_real_corpus_loads(corpus):
    assert len(corpus) > 0, "the shipped corpus is empty"


def test_real_corpus_has_both_malicious_and_benign(corpus):
    """P48: a population of one cannot separate populations."""
    assert len(corpus.malicious) > 0, "no malicious specimens"
    assert len(corpus.benign) > 0, "no benign twins — false-positive rate is unmeasurable"


def test_real_corpus_covers_every_m1_declaration_class(corpus):
    present = corpus.classes_present
    missing = [c.value for c in M1_DECLARATION_CLASSES if c not in present]
    assert not missing, f"M1 requires these declaration classes and they are absent: {missing}"


def test_real_corpus_passes_twin_coverage(corpus):
    report = validate_corpus(corpus)
    assert report.ok, report.summary()
    assert not report.is_vacuous


def test_every_class_twin_is_actually_benign(corpus):
    for specimen in corpus.benign:
        assert specimen.is_benign
        assert specimen.twin_for, f"{specimen.id} is benign but controls for no class"


def test_real_corpus_hash_is_stable(corpus):
    assert corpus_hash(corpus) == corpus_hash(load_corpus(SPECIMENS))


def test_cli_validate_passes_on_the_real_corpus(capsys):
    assert main(["validate", "--corpus", str(SPECIMENS)]) == EXIT_OK
    assert "OK:" in capsys.readouterr().out


# --- R1: every shipped specimen is a runnable MCP server --------------------------------


def _handshake(script: Path, timeout: float = 20.0) -> list[dict]:
    """Drive a real MCP handshake against a specimen and return its parsed responses."""
    stdin_text = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "clientInfo": {"name": "poison-garden-tests", "version": "0"},
                    "capabilities": {},
                },
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
    )
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _shipped_specimen_ids() -> list[str]:
    if not SPECIMENS.is_dir():
        return []
    return sorted(
        d.name
        for d in SPECIMENS.iterdir()
        if d.is_dir() and not d.name.startswith(("_", "."))
    )


@pytest.mark.slow
@pytest.mark.parametrize("specimen_id", _shipped_specimen_ids())
def test_specimen_answers_a_real_handshake(specimen_id: str):
    """R1 scenario: definitions come from a running process, not a static file."""
    specimen = load_corpus(SPECIMENS).by_id(specimen_id)
    assert specimen is not None

    responses = _handshake(specimen.entrypoint_path)
    by_id = {r.get("id"): r for r in responses}

    assert 1 in by_id, f"{specimen_id}: no initialize response"
    assert "result" in by_id[1], f"{specimen_id}: initialize errored"
    assert "serverInfo" in by_id[1]["result"]

    assert 2 in by_id, f"{specimen_id}: no tools/list response"
    tools = by_id[2]["result"]["tools"]
    assert isinstance(tools, list) and tools, f"{specimen_id}: advertised no tools"
    for tool in tools:
        assert "name" in tool, f"{specimen_id}: a tool has no name"


def test_there_are_specimens_to_handshake():
    """Vacuity guard: an empty parametrize list makes the test above vanish silently (P58)."""
    assert _shipped_specimen_ids(), "no specimens found — the handshake test ran zero cases"
