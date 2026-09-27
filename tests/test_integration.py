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
    CLIENT_PROFILES,
    INSPECTOR_PROFILE,
    PROFILE_AXES,
    REPO_ROOT,
    SPECIMENS,
    catalog_for_profile,
    catalogs_across_profiles,
    enumerate_n_times_in_one_session,
    handshake,
    shipped_specimen_ids,
    variation_defects,
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
    """A register naming absent specimens passes its own count while measuring nothing.

    Uses the SAME `count_entries` the release gate uses, rather than a second regex. It had
    its own copy, and when the gate's regex was scoped to the register section this test
    kept the unscoped one — so the two disagreed about what "a registered miss" means and
    the test failed on rows the gate correctly ignored. One predicate, one spelling (P95);
    a check that parses the artifact differently from the gate it mirrors is not mirroring
    the gate.
    """
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from check_known_misses import count_entries

    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text(encoding="utf-8")
    rows = count_entries(register)
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
            # Driven to the enumeration the MANIFEST names, plus two, then checked in both
            # directions. Asserting only `catalogs[0] != catalogs[1]` made "fires
            # immediately" the sole expressible rug-pull — which is the one two-sample
            # diffing already catches, so the guard excluded exactly the specimens worth
            # having.
            fires_at = specimen.manifest.varies_at_enumeration
            catalogs = enumerate_n_times_in_one_session(
                specimen.entrypoint_path, fires_at + 2
            )
            defects = variation_defects(specimen.id, catalogs, fires_at)
            assert not defects, "\n".join(defects)
        elif Class.SCANNER_AWARE in classes:
            # Compared against EVERY agent profile, not one. The previous version drove a
            # single pair that varied `capabilities` and `clientInfo.name` only, so a
            # specimen keying on the shape of `clientInfo` — which R14 explicitly permits,
            # since it is something the client controls and reveals — served both probes
            # identically and was reported as not evading at all. A fixed pair silently
            # narrowed R14 to one axis, and the narrowing presented as a passing test.
            views = catalogs_across_profiles(specimen.entrypoint_path)
            inspector = views[INSPECTOR_PROFILE]
            agents = {k: v for k, v in views.items() if k != INSPECTOR_PROFILE}
            assert any(view != inspector for view in agents.values()), (
                f"{specimen.id}: an inspector and every agent profile "
                f"({sorted(agents)}) saw the same catalog, so the evasion never occurs. "
                f"Its declared discriminator is: {specimen.manifest.discriminator[:120]}"
            )

def test_no_pure_declaration_specimen_claims_to_vary(corpus):
    """Control: the exemption is available only to specimens whose class requires it."""
    for specimen in corpus.specimens:
        if specimen.manifest.varies_by_invocation:
            assert specimen.manifest.behavior, f"{specimen.id} varies without a behaviour class"


def test_some_rugpull_specimen_fires_late_enough_to_exercise_the_early_check(corpus):
    """Vacuity guard (P58/P64) for the half of `variation_defects` that can go unrun.

    Its "did not fire early" loop is `range(1, fires_at)` — empty when the threshold is 1.
    A corpus where every rug-pull fires immediately would exercise only the second half of
    the check, and the declaration would be buying nothing, silently.

    This also guards something about the CORPUS, not just the test: a corpus of only
    immediate rug-pulls measures the easy case. The late-firing specimen is the one a
    scanner sampling twice still misses, and it is the reason the threshold is declarable
    at all.
    """
    thresholds = {
        s.id: s.manifest.varies_at_enumeration
        for s in corpus.specimens
        if Class.NAMESAKE_RUGPULL in s.classes and s.manifest.varies_by_invocation
    }
    assert thresholds, "no rug-pull specimen declares varies_by_invocation"
    assert any(n > 1 for n in thresholds.values()), (
        "every rug-pull fires on the first re-enumeration, so the 'did not fire early' "
        f"check never runs on any specimen: {thresholds}. A corpus of only immediate "
        "rug-pulls measures the case two-sample diffing already catches."
    )


def test_the_early_fire_check_actually_catches_an_early_fire():
    """FALSIFICATION (P31/P50): a guard never shown to fire is decoration.

    Feeds `variation_defects` a specimen that claims to wait until enumeration 4 and in
    fact mutates at 1, and asserts it is caught. Without this, the loop could be reversed,
    off by one, or comparing the wrong index, and the suite would stay green.
    """
    catalogs = ["clean", "MUTATED", "MUTATED", "MUTATED", "MUTATED", "MUTATED"]
    defects = variation_defects("liar", catalogs, fires_at=4)
    assert defects, "a specimen mutating 3 enumerations early was not caught"
    assert "already changed at enumeration 1" in defects[0]


def test_the_never_fires_check_actually_catches_a_specimen_that_never_fires():
    """The other direction — the half the original assertion covered."""
    defects = variation_defects("inert", ["same"] * 6, fires_at=3)
    assert defects, "a specimen that never mutates was not caught"
    assert "never happens" in defects[0]


def test_a_correctly_timed_rugpull_produces_no_defects():
    """Control (P49): a checker that returns findings for everything would pass both above."""
    catalogs = ["clean", "clean", "clean", "MUTATED", "MUTATED"]
    assert variation_defects("honest", catalogs, fires_at=3) == []


def test_the_client_profiles_are_coherent_clients_not_a_bag_of_flags():
    """The inspector and every agent must differ on EVERY observable axis.

    This guard exists because the profiles grew by accretion: three times, a scanner-aware
    specimen keyed on a signal the driver did not vary, and the fix was to add that axis.
    That is the right fix each time — the specimens keyed on things real clients genuinely
    differ on — but the failure mode it invites is tuning one flag until a test goes green,
    which would leave a profile that is no longer any real client.

    Asserting difference on every axis keeps INSPECTOR a coherent portrait of something that
    connects, sweeps, lists once and leaves, and the agents a portrait of something driving
    a model. A specimen may then key on any of them and be measured.
    """
    inspector = CLIENT_PROFILES[INSPECTOR_PROFILE]
    agents = {k: v for k, v in CLIENT_PROFILES.items() if k != INSPECTOR_PROFILE}
    assert agents, "no agent profile to contrast the inspector against"

    for name, agent in agents.items():
        for axis in PROFILE_AXES:
            assert agent[axis] != inspector[axis], (
                f"profile '{name}' matches the inspector on '{axis}'. A specimen keying on "
                "that axis cannot be measured, and the test would report no evasion."
            )
        assert agent["params"]["capabilities"], f"'{name}' declares no capabilities"
        assert "title" in agent["params"]["clientInfo"], (
            f"'{name}' omits clientInfo.title — the field a client with a UI populates"
        )

    assert not inspector["params"]["capabilities"]
    assert "title" not in inspector["params"]["clientInfo"]


def test_registered_misses_were_actually_missed():
    """Every row in KNOWN-MISSES must name a specimen the result document records as missed.

    The register is the project's central honesty commitment (N2), and until now nothing
    connected it to the measurement it claims to summarise: the version and hash were
    checked, the rows were not. A row could name a specimen frisk catches — through a
    rewritten specimen, a fixed detector, or a copy-paste — and the count would still pass,
    which would turn "specimens frisk fails" into "specimens someone once wrote down"
    (P68 — a published figure needs a mechanical relation to its source).
    """
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from check_known_misses import count_entries

    registered = set(count_entries((REPO_ROOT / "KNOWN-MISSES.md").read_text("utf-8")))
    assert registered, "the register names no specimens"

    results = sorted((REPO_ROOT / "results").glob("*frisk*.json"))
    assert results, "no committed frisk result to check the register against"
    document = _json.loads(results[0].read_text("utf-8"))

    missed = {m for entry in document["per_class"] for m in entry["missed"]}
    assert missed, "the result document records no misses at all — N2 cannot be satisfied"

    caught_but_registered = sorted(registered - missed)
    assert not caught_but_registered, (
        f"KNOWN-MISSES registers {caught_but_registered}, which the committed result "
        "document does not list as missed. Either frisk now catches them — strike those "
        "rows and register new specimens — or the register was edited without re-running "
        "the measurement."
    )


def test_the_register_is_checked_against_the_documents_own_corpus():
    """The register and the result must describe the SAME corpus, or the check above is void.

    Comparing a register written for v0.3.0 against a result document measured on v0.2.2
    would compare two different populations and pass or fail for reasons unrelated to frisk
    (R4 — two documents are comparable only when they describe the same corpus).
    """
    import json as _json

    results = sorted((REPO_ROOT / "results").glob("*frisk*.json"))
    document = _json.loads(results[0].read_text("utf-8"))
    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text("utf-8")

    assert document["corpus"]["hash"] in register, (
        "the register does not cite the hash of the result document it is checked against"
    )
    assert corpus_hash(load_corpus(SPECIMENS)) == document["corpus"]["hash"], (
        "the corpus on disk is not the one the committed result document measured"
    )


def _tool_names_for_profile(entrypoint, profile: str) -> set[str]:
    import json as _json

    catalog = _json.loads(catalog_for_profile(entrypoint, profile) or "{}")
    return {t.get("name", "") for t in catalog.get("tools", [])}


def test_scanner_aware_evasion_never_runs_backwards(corpus):
    """An inspector must never be shown a tool some agent is not.

    R14's property is directional: clean definitions to an inspector, poisoned ones to a
    real agent. The varier test above only asserts the two views *differ*, and a specimen
    can satisfy that while evading in reverse — serving the inspector the dangerous catalog
    and a subset of real clients the clean one. That is not an evasion; it is an ordinary
    poisoned server with a narrow exemption, and it will be caught by any scanner.

    This is not hypothetical. A now-deleted specimen, `behaviour-scanner-aware-legacy-
    protocol-pin`, keyed on the caller declaring an older `protocolVersion`, on the premise
    that an enumerator is built once and never moves. frisk declares a current one, was
    served the poisoned catalog, and flagged it — making that specimen the class's only
    "catch" and inflating frisk's score on the strength of a specimen that was not working.
    A corpus crediting its own author's scanner for that is the precise failure N2 exists to
    prevent, so it gets a guard rather than a note. It was replaced by
    `behaviour-scanner-aware-default-client-identity`; this assertion is what would have
    caught it without needing a scanner run at all, since the corpus's own `inspector`
    profile declares a current protocol revision and `agent-older-protocol` does not.

    Subset rather than equality, because withholding a tool is only one shape of evasion:
    sanitising a description leaves the tool sets identical and is caught by the varier test.
    """
    aware = [s for s in corpus.malicious if Class.SCANNER_AWARE in s.classes]
    assert aware, "no scanner-aware specimens — R14 is unimplemented"

    backwards: list[str] = []
    for specimen in aware:
        inspector = _tool_names_for_profile(specimen.entrypoint_path, INSPECTOR_PROFILE)
        for profile in CLIENT_PROFILES:
            if profile == INSPECTOR_PROFILE:
                continue
            agent = _tool_names_for_profile(specimen.entrypoint_path, profile)
            extra = inspector - agent
            if extra:
                backwards.append(
                    f"{specimen.id}: the inspector is served {sorted(extra)}, which the "
                    f"'{profile}' client is not. The evasion runs backwards — a scanner "
                    "sees more surface than a real client, so it will simply catch this."
                )

    assert not backwards, "\n".join(backwards)


def test_the_n2_counter_ignores_tables_outside_the_register():
    """REGRESSION: `count_entries` was applied to the whole file, not the register section.

    Its docstring had always claimed "only rows inside the table count"; the regex never
    enforced it. Nothing noticed until a probe-coverage table was added whose rows also
    begin with a backticked lowercase-hyphen token, and the count silently went 15 → 20.

    The direction is what makes it serious. An inflated count is the direction that lets a
    too-easy corpus clear N2 — the release gate asserting the corpus still beats its own
    author's scanner. A deflated count fails loudly; an inflated one ships.
    """
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from check_known_misses import count_entries

    register = (REPO_ROOT / "KNOWN-MISSES.md").read_text(encoding="utf-8")
    real = count_entries(register)
    assert real, "the register counted nothing"

    # A table ABOVE the register section, shaped exactly like a register row.
    decoy = register.replace(
        "### The registered misses (N2)",
        "| `not-a-specimen-at-all` | x | y |\n\n### The registered misses (N2)",
        1,
    )
    assert count_entries(decoy) == real, (
        "a table outside the register section was counted as a registered miss; the "
        "counter is unscoped again"
    )

    # And it must still see rows that really are in the register.
    assert "### The registered misses (N2)" in register
    assert all("`" not in e and " " not in e for e in real)
