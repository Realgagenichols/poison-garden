"""Running a scanner over the corpus — R5, R6, R7, R8, S1.

Three outcomes per specimen, and they are three different findings (cross-cutting P55):

    flagged  the scanner said something is wrong
    clean    the scanner said nothing is wrong
    error    we could not ask the question

`error` is not a miss. A specimen that fails to start, fails its handshake, or whose scan
times out leaves BOTH the numerator and the denominator (R7). Counting it as a miss would
let a broken corpus quietly deflate every scanner's score; counting it as a catch would do
the opposite. Neither is a measurement.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from poison_garden.corpus.models import Class, Corpus, Specimen
from poison_garden.runner.sandbox import ENV_EGRESS_SINK, sandbox
from poison_garden.runner.sarif import SarifError, attribute, parse_sarif
from poison_garden.runner.target import ScannerCommand, target_argv

DEFAULT_TIMEOUT = 120.0


class Verdict(StrEnum):
    FLAGGED = "flagged"
    CLEAN = "clean"
    ERROR = "error"


@dataclass(frozen=True)
class SpecimenResult:
    """What happened when the scanner was pointed at one specimen."""

    specimen_id: str
    verdict: Verdict
    exit_code: int | None = None
    duration_s: float = 0.0
    # Why it errored, as a CATEGORY — never the scanner's output, which could contain a
    # decoy canary the specimen handed it (S3).
    error_reason: str | None = None
    # R17: classes the scanner identified, when it emitted usable SARIF. None means SARIF
    # was not requested or not usable — which is NOT a failure and never changes the
    # verdict, because the baseline must stay available to a scanner that emits nothing.
    attributed: frozenset[Class] | None = None
    sarif_note: str | None = None

    @property
    def scored(self) -> bool:
        return self.verdict is not Verdict.ERROR


@dataclass(frozen=True)
class ExitCodeMapping:
    """How an exit code became a verdict. Recorded in the document so a reader can check."""

    flag_on: str = "nonzero"

    def __post_init__(self) -> None:
        """Validate at the boundary, not on the first specimen (P6).

        `int(self.flag_on)` used to run inside `verdict_for`, so `--flag-on banana` spawned
        every specimen, scanned the first one, and then died with a bare ValueError after
        the work was already done.
        """
        if self.flag_on == "nonzero":
            return
        try:
            int(self.flag_on)
        except ValueError as exc:
            raise ValueError(
                f"--flag-on must be 'nonzero' or an integer exit code, got {self.flag_on!r}"
            ) from exc

    def verdict_for(self, exit_code: int) -> Verdict:
        # A negative returncode means killed by a signal: the scanner did not reach a
        # conclusion, so neither do we.
        if exit_code < 0:
            return Verdict.ERROR
        if self.flag_on == "nonzero":
            return Verdict.FLAGGED if exit_code != 0 else Verdict.CLEAN
        threshold = int(self.flag_on)
        return Verdict.FLAGGED if exit_code >= threshold else Verdict.CLEAN

    def describe(self) -> str:
        if self.flag_on == "nonzero":
            return "exit != 0 -> flagged; exit == 0 -> clean; exit < 0 (signal) -> error"
        return (
            f"exit >= {self.flag_on} -> flagged; below -> clean; exit < 0 (signal) -> error"
        )


def preflight(specimen: Specimen, env: dict[str, str], timeout: float = 20.0) -> str | None:
    """Confirm the specimen actually serves a catalog. Returns an error category or None.

    Run BEFORE the scanner. Without it, a broken specimen makes the scanner fail, and the
    scanner's failure is indistinguishable from a detection — a corpus defect silently
    becomes a verdict about someone else's tool.
    """
    request = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "pg"}},
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
    )
    try:
        proc = subprocess.run(
            target_argv(specimen),
            input=request,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        stdout = proc.stdout
    except subprocess.TimeoutExpired as exc:
        # `subprocess.run(input=...)` reads stdout to EOF, so it waits for the process to
        # EXIT, not for the catalog to arrive. A specimen that answers correctly and then
        # keeps serving — which is exactly the shape of M3's namesake-rug-pull (R13) and
        # scanner-aware (R14) specimens — timed out here and was classified `error`,
        # leaving both numerator and denominator despite having done nothing wrong.
        # R7 reserves `error` for a specimen that fails to start, fails its handshake, or
        # times out; a specimen that served its catalog did none of the three.
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if _catalog_in(stdout) is True:
            return None
        return "specimen-handshake-timeout"
    except OSError as exc:
        return f"specimen-spawn-failed:{type(exc).__name__}"

    served = _catalog_in(stdout)
    if served is True:
        return None
    if served is None:
        return "specimen-stdout-not-json"
    responses = handshake_responses(stdout) or {}
    if "result" not in responses.get(1, {}):
        return "specimen-initialize-failed"
    return "specimen-no-catalog"


def handshake_responses(stdout: str) -> dict[int, dict] | None:
    """Parse a specimen's stdout into {request id: message}, or None if it is not JSON-RPC.

    Returns the initialize response too, rather than discarding it. R14's scanner-aware
    specimen discriminates IN the initialize exchange — that is the message that stops
    being a formality — so a test asserting two client identities get different catalogs
    needs the handshake result, not only the catalog.
    """
    out: dict[int, dict] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            return None
        request_id = message.get("id")
        if isinstance(request_id, int):
            out[request_id] = message
    return out


def _catalog_in(stdout: str) -> bool | None:
    """True if BOTH the initialize and tools/list exchanges succeeded.

    The initialize response used to go uninspected, so a specimen that errored on
    initialize but answered `tools/list` was classified healthy. A formality in M1, where
    every specimen answers it identically — and exactly the exchange R14's specimen uses to
    discriminate, so a scanner-aware specimen refusing our handshake would have been waved
    through with its evasion unmeasured.
    """
    responses = handshake_responses(stdout)
    if responses is None:
        return None
    if "result" not in responses.get(1, {}):
        return False
    return "result" in responses.get(2, {})


def scanner_env(sandbox_env: dict[str, str]) -> dict[str, str]:
    """The user's own environment, plus the loopback sink address.

    **Additive, never a replacement.** Handing the scanner the specimen sandbox broke the
    first real acceptance run: a scanner invoked as `uvx --from mcp-frisk ...` is not
    findable on a PATH of `/usr/bin:/bin`, so every specimen errored and the run correctly
    refused to emit a document. So this copies `os.environ` and adds exactly one key.

    Why add it at all: the scanner spawns the specimen, so the specimen inherits whatever
    the scanner passes down. With `PG_EGRESS_SINK` present, an egress specimen reaches
    poison-garden's own loopback sink and the sink records what a real attacker would have
    taken — ground truth about our corpus, captured during the run that is actually scored.

    Best-effort by design. A scanner that scrubs its child's environment (frisk runs
    specimens under a seatbelt profile) simply will not forward it, and the specimen falls
    back to a loopback connect that sends nothing. Both paths open a socket, so the signal a
    scanner could detect is present either way; only our own visibility into the payload
    differs. The fallback is what makes the class measurable at all — this is the nicety.
    """
    out = dict(os.environ)
    sink = sandbox_env.get(ENV_EGRESS_SINK)
    if sink:
        out[ENV_EGRESS_SINK] = sink
    return out


def scan_one(
    specimen: Specimen,
    scanner: ScannerCommand,
    env: dict[str, str],
    mapping: ExitCodeMapping,
    timeout: float = DEFAULT_TIMEOUT,
    sarif: bool = False,
) -> SpecimenResult:
    """Point the scanner at one specimen and classify the outcome."""
    import time

    # Forward the caller's timeout. preflight defaulted to 20s regardless of --timeout, so
    # `--timeout 5` still spent 20s per unstartable specimen and `--timeout 300` gave a
    # slow-starting one only 20.
    # Floored at 5s: `--timeout 2` for a fast scanner would otherwise buy a 2-second
    # handshake budget, and a cold interpreter plus an import-heavy M3 specimen can miss
    # that. Capped at 60s so a generous scanner timeout does not multiply the wait on a
    # specimen that will never start.
    reason = preflight(specimen, env, timeout=max(5.0, min(timeout, 60.0)))
    if reason is not None:
        return SpecimenResult(specimen.id, Verdict.ERROR, error_reason=reason)

    argv = scanner.argv_for(specimen)
    started = time.monotonic()
    try:
        # shell=False and no pipeline: the exit status read here is the SCANNER's, which
        # is the entire verdict (P10). capture_output keeps the scanner's stdout out of
        # our own, where it could carry a decoy canary (S3).
        #
        # The scanner runs with the user's OWN environment, deliberately — see the note on
        # `run_corpus`. Handing it the specimen sandbox broke the first real acceptance
        # run: a scanner invoked as `uvx --from mcp-frisk ...` is not findable on a
        # PATH of `/usr/bin:/bin`, so all 18 specimens errored and the run correctly
        # refused to emit a document.
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=scanner_env(env),
        )
    except subprocess.TimeoutExpired:
        return SpecimenResult(
            specimen.id,
            Verdict.ERROR,
            duration_s=time.monotonic() - started,
            error_reason="scanner-timeout",
        )
    except OSError as exc:
        return SpecimenResult(
            specimen.id,
            Verdict.ERROR,
            duration_s=time.monotonic() - started,
            error_reason=f"scanner-spawn-failed:{type(exc).__name__}",
        )

    attributed: frozenset[Class] | None = None
    sarif_note: str | None = None
    if sarif:
        # Enrichment only. A scanner whose SARIF we cannot parse keeps its exit-code
        # verdict and gains a note — R17 says SARIF's absence never blocks a run, and a
        # scanner must not score worse for emitting something we failed to read.
        try:
            findings = parse_sarif(proc.stdout)
        except SarifError as exc:
            sarif_note = f"unusable-sarif:{exc.args[0][:60]}"
        else:
            attributed = attribute(findings, specimen.classes)
            if findings.unmapped_rules:
                sarif_note = f"unmapped-rules:{len(findings.unmapped_rules)}"

    return SpecimenResult(
        specimen_id=specimen.id,
        verdict=mapping.verdict_for(proc.returncode),
        exit_code=proc.returncode,
        duration_s=time.monotonic() - started,
        attributed=attributed,
        sarif_note=sarif_note,
    )


def run_corpus(
    corpus: Corpus,
    scanner: ScannerCommand,
    mapping: ExitCodeMapping | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    sarif: bool = False,
) -> list[SpecimenResult]:
    """Scan every specimen. One broken specimen never aborts the run (R7).

    **Who sandboxes what, precisely.** Our preflight — the handshake that decides whether a
    specimen is runnable at all — happens under the M1 sandbox, using `Sandbox.env()`
    itself rather than a second allowlist (P95). The SCANNER runs with the user's own
    environment, because it is their tool and it needs their PATH, and because the scanner
    is the thing that spawns the specimen during the actual scan.

    That last clause is the important one, and it is a limitation rather than an oversight:
    **during a real scan, poison-garden does not control the specimen's environment — the
    scanner does.** Our decoy home covers our preflight and nothing else. This is the same
    truth S5 states about the harness generally, and it is why the corpus is authored to be
    inert rather than relying on being contained. Documented in the README's Safety
    section; do not "fix" it by handing the scanner a scrubbed environment, which only
    breaks the scanner.
    """
    mapping = mapping or ExitCodeMapping()
    results: list[SpecimenResult] = []

    # A FRESH sandbox per specimen, not one shared across the corpus. Two reasons, both
    # invisible while every specimen is a pure declaration and both fatal after M3:
    #
    #   - N3 says behaviour is a function of inputs and the runner-supplied environment.
    #     A specimen that WRITES to the shared HOME — plausible for R13's rug-pull state —
    #     leaves it for every later specimen, making behaviour a function of run POSITION.
    #     That failure mode is the worst kind to debug: passes in isolation, fails at
    #     position 14, corpus hash identical either way.
    #   - The egress sink was shared too, so `connections` and `accepted` accumulated
    #     across the whole corpus and an attempt could not be attributed to the specimen
    #     that made it. That one was introduced by the fix that started the sink at all.
    for specimen in corpus.specimens:
        with tempfile.TemporaryDirectory(prefix="pg-run-") as td, sandbox(Path(td)) as (
            box,
            _sink,
        ):
            results.append(
                scan_one(specimen, scanner, box.env(), mapping, timeout, sarif=sarif)
            )

    return results
