"""End-to-end tests against the REAL shipped corpus — R1–R4, S1, S2.

Everything else in the suite runs against synthetic corpora built in tmp_path. These tests
drive the actual `specimens/` tree, because a corpus that loads only in fixtures is not a
corpus (cross-cutting P53 — green tests are not a used application).
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from helpers import (
    REPO_ROOT,
    SPECIMENS,
    catalog_for_client,
    enumerate_twice_in_one_session,
    handshake,
    shipped_specimen_ids,
)

from poison_garden.cli import EXIT_OK, main
from poison_garden.corpus.hash import corpus_hash
from poison_garden.corpus.loader import load_corpus
from poison_garden.corpus.models import Class
from poison_garden.corpus.validate import validate_corpus

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


@pytest.mark.slow
@pytest.mark.parametrize("specimen_id", shipped_specimen_ids())
def test_specimen_answers_a_real_handshake(specimen_id: str, corpus):
    """R1 scenario: definitions come from a running process, not a static file."""
    specimen = corpus.by_id(specimen_id)
    assert specimen is not None

    responses = handshake(specimen.entrypoint_path)
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
    assert shipped_specimen_ids(), "no specimens found — the handshake test ran zero cases"


# --- P76: expectations listed literally, never derived from the corpus under test --------

# Every specimen shipped in corpus v0.1.0, written out. Deriving this list from the corpus
# would rename the expectation along with the thing it checks, so deleting a specimen would
# stay green — the exact failure frisk hit with a parametrize over its own constant.
# Growth is fine (the assertion is a subset check); silent REMOVAL is the regression.
EXPECTED_SPECIMENS = frozenset(
    {
        # M3 behavioural families.
        "behaviour-credential-reader",
        "behaviour-twin-config-reader",
        "behaviour-exfil-in-description",
        "behaviour-twin-build-fingerprint",
        "behaviour-namesake-rugpull",
        "behaviour-twin-stable-namesakes",
        "behaviour-scanner-aware",
        "behaviour-twin-capability-negotiation",
        "hidden-ansi-escape-ci",
        "hidden-bidi-override-export",
        "hidden-content-twin-localization",
        "hidden-markup-comment-inventory",
        "hidden-zero-width-transit",
        "hygiene-anonymous-server",
        "hygiene-twin-pinned-installer",
        "hygiene-unpinned-remote-exec",
        "impersonation-builtin-reader",
        "impersonation-twin-wiki-search",
        "injection-invoice-remit-override",
        "injection-meeting-preamble",
        "injection-twin-invoice-import",
        "scope-mismatch-timezone-helper",
        "scope-mismatch-twin-runbook",
        "sensitive-params-diagnostics-dump",
        "sensitive-params-ticket-transcript",
        "sensitive-params-twin-ticket-router",
    }
)


def test_no_specimen_has_silently_disappeared():
    present = set(shipped_specimen_ids())
    missing = sorted(EXPECTED_SPECIMENS - present)
    assert not missing, (
        f"specimen(s) removed without updating EXPECTED_SPECIMENS: {missing}. "
        "If the removal was deliberate, delete the entry here in the same commit."
    )


def test_every_class_has_at_least_one_twin_and_one_attacker(corpus):
    """Counted per class rather than in aggregate — an aggregate hides a lopsided class."""
    for klass in M1_DECLARATION_CLASSES:
        attackers = [s for s in corpus.malicious if klass in s.classes]
        twins = corpus.twins_for(klass)
        assert attackers, f"{klass.value}: no malicious specimen"
        assert twins, f"{klass.value}: no benign twin"


# --- protocol hygiene: a specimen that corrupts stdout is a silent corpus shrink ---------


@pytest.mark.slow
@pytest.mark.parametrize("specimen_id", shipped_specimen_ids())
def test_specimen_writes_only_json_rpc_to_stdout(specimen_id: str, corpus):
    """Every stdout line must be a JSON-RPC object — nothing else, ever.

    A specimen that prints a banner, a warning, or a stray debug line corrupts the
    JSON-RPC stream. The scanner under test then errors instead of reporting, R7
    classifies the specimen as `error`, and it drops out of BOTH numerator and
    denominator. The corpus silently shrinks and every score computed from it shifts,
    with nothing anywhere saying so. That makes this a scoring-integrity check, not a
    style one.
    """
    specimen = corpus.by_id(specimen_id)
    proc = subprocess.run(
        [sys.executable, str(specimen.entrypoint_path)],
        input=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        + "\n",
        capture_output=True,
        text=True,
        timeout=20,
    )

    # Without this the whole test is vacuous: a specimen that crashes on import writes
    # nothing to stdout, the loop runs zero times, and a scoring-integrity check reports
    # green (P58). Verified: 0 lines -> 0 iterations -> pass.
    assert proc.stdout.strip(), (
        f"{specimen_id}: wrote nothing to stdout. stderr: {proc.stderr[:300]}"
    )

    for lineno, line in enumerate(proc.stdout.splitlines(), 1):
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{specimen_id}: stdout line {lineno} is not JSON — it would corrupt the "
                f"protocol stream and drop this specimen from scoring. Line: {line[:120]!r}"
            ) from exc
        assert message.get("jsonrpc") == "2.0", (
            f"{specimen_id}: stdout line {lineno} is JSON but not a JSON-RPC message"
        )


@pytest.mark.slow
@pytest.mark.parametrize("specimen_id", shipped_specimen_ids())
def test_specimen_exits_cleanly_when_stdin_closes(specimen_id: str, corpus):
    """A specimen that hangs after stdin closes stalls a whole benchmark run."""
    specimen = corpus.by_id(specimen_id)
    proc = subprocess.run(
        [sys.executable, str(specimen.entrypoint_path)],
        input="",
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, (
        f"{specimen_id}: exited {proc.returncode} on empty stdin. stderr: {proc.stderr[:200]}"
    )


# --- W8: the register must name a corpus state, not float free of one -------------------


def test_known_misses_names_the_current_corpus_version(corpus):
    """P68/P88: a published figure needs a mechanical relation to its source.

    The register's numbers describe one corpus state. If it cites a version the corpus no
    longer carries, the rows are stale rather than evidence, and nothing else would say so.
    """
    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text(encoding="utf-8")
    assert f"corpus version  {corpus.version}" in register, (
        f"KNOWN-MISSES does not record the current corpus version ({corpus.version})"
    )


def test_known_misses_names_the_current_corpus_hash(corpus):
    """A specimen edit moves the hash; the register must then be re-measured, not trusted."""
    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text(encoding="utf-8")
    current = corpus_hash(corpus)
    assert current in register, (
        f"KNOWN-MISSES records a corpus hash that is no longer current.\n"
        f"  current: {current}\n"
        "The corpus changed since the frisk measurement, so those rows describe a corpus "
        "that no longer exists. Re-run frisk and update the register — do not just edit "
        "the hash."
    )


def test_every_registered_miss_is_a_real_specimen(corpus):
    """A register naming absent specimens passes its own count while measuring nothing."""
    import re as _re

    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text(encoding="utf-8")
    rows = _re.findall(r"^\|\s*`([a-z0-9-]+)`\s*\|", register, _re.MULTILINE)
    assert rows, "KNOWN-MISSES registers no specimens"
    missing = [r for r in rows if corpus.by_id(r) is None]
    assert not missing, f"register names specimens absent from the corpus: {missing}"


# --- pre-flight is a SECOND invocation; anything impure happens twice, differently --------


@pytest.mark.slow
@pytest.mark.parametrize("specimen_id", shipped_specimen_ids())
def test_specimen_serves_an_identical_catalog_on_two_invocations(specimen_id: str, corpus):
    """N3, and the cheap guard against a whole family of M3 inversions.

    poison-garden pre-flights each specimen and then the scanner runs it again — a second
    invocation of the same program under a *different* environment, and only the second is
    the measurement. So anything a specimen does that is not a pure function of its inputs
    happens twice, differently, and the copy we can observe is the copy that does not count.

    Asserting the two catalogs are byte-identical turns "seems harmless" into a
    measurement. A specimen that legitimately varies — R13's rug-pull, R14's
    scanner-aware — must declare that in its manifest, at which point this test reads the
    declaration instead of demanding sameness. Until then, varying silently is a defect.

    Compares the two runs to EACH OTHER, never to a stored literal (P103).
    """
    specimen = corpus.by_id(specimen_id)
    assert specimen is not None

    def catalog() -> str:
        responses = handshake(specimen.entrypoint_path)
        return json.dumps([r for r in responses if r.get("id") == 2], sort_keys=True)

    first, second = catalog(), catalog()

    # NOTE: this applies to EVERY specimen, including declared variers, and the first
    # version of this test wrongly exempted them. `varies_by_invocation` does not mean
    # non-deterministic — it means the catalog depends on an input (position within a
    # session, or the client's declared identity) that two fresh processes given identical
    # input do not vary. Same inputs, same output, always; N3 is not in tension with R13 or
    # R14. The variation those classes implement is measured per class below, by varying
    # the input that actually drives it.
    assert first == second, (
        f"{specimen_id} served different catalogs on two invocations without declaring "
        "that it varies. Our pre-flight is one invocation and the scanner's run is "
        "another, so an undeclared variation means the scanner measures something we "
        "never saw."
    )


def test_every_declared_varier_actually_varies(corpus):
    """A declaration must be earned. Each varier is driven by the input its class names.

    Replaced `test_no_shipped_specimen_declares_a_behavior_class_yet`, which existed to
    fail loudly the moment M3 landed. It did, and this is what it demanded.
    """
    variers = [s for s in corpus.specimens if s.manifest.varies_by_invocation]
    assert variers, "no specimen declares varies_by_invocation — R13/R14 are unimplemented"

    for specimen in variers:
        assert specimen.manifest.behavior, (
            f"{specimen.id} claims to vary but declares no behaviour class"
        )
        classes = specimen.classes
        if Class.NAMESAKE_RUGPULL in classes:
            catalogs = enumerate_twice_in_one_session(specimen.entrypoint_path)
            assert catalogs[0] != catalogs[1], (
                f"{specimen.id}: two enumerations in ONE session produced the same "
                "catalog, so the rug-pull never happens"
            )
        elif Class.SCANNER_AWARE in classes:
            scanner_view = catalog_for_client(
                specimen.entrypoint_path, "mcp", capabilities={}
            )
            client_view = catalog_for_client(
                specimen.entrypoint_path,
                "claude-desktop",
                capabilities={"roots": {"listChanged": True}, "sampling": {}},
            )
            assert scanner_view != client_view, (
                f"{specimen.id}: a scanner and an ordinary client saw the same catalog, "
                "so the evasion does not occur"
            )


def test_no_pure_declaration_specimen_claims_to_vary(corpus):
    """Control: the exemption is available only to specimens whose class requires it."""
    for specimen in corpus.specimens:
        if specimen.manifest.varies_by_invocation:
            assert specimen.manifest.behavior, f"{specimen.id} varies without a behaviour class"
