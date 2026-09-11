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
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from poison_garden.corpus.models import Corpus, Specimen
from poison_garden.runner.sandbox import Sandbox, build_home
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
    except subprocess.TimeoutExpired:
        return "specimen-handshake-timeout"
    except OSError as exc:
        return f"specimen-spawn-failed:{type(exc).__name__}"

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            return "specimen-stdout-not-json"
        if message.get("id") == 2 and "result" in message:
            return None
    return "specimen-no-catalog"


def scan_one(
    specimen: Specimen,
    scanner: ScannerCommand,
    env: dict[str, str],
    mapping: ExitCodeMapping,
    timeout: float = DEFAULT_TIMEOUT,
) -> SpecimenResult:
    """Point the scanner at one specimen and classify the outcome."""
    import time

    reason = preflight(specimen, env)
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
            error_reason=f"scanner-spawn-failed:{type(exc).__name__}",
        )

    return SpecimenResult(
        specimen_id=specimen.id,
        verdict=mapping.verdict_for(proc.returncode),
        exit_code=proc.returncode,
        duration_s=time.monotonic() - started,
    )


def run_corpus(
    corpus: Corpus,
    scanner: ScannerCommand,
    mapping: ExitCodeMapping | None = None,
    timeout: float = DEFAULT_TIMEOUT,
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

    with tempfile.TemporaryDirectory(prefix="pg-run-") as td:
        root = Path(td)
        home, canaries = build_home(root)
        box = Sandbox(
            home=home,
            canaries=canaries,
            egress_host="127.0.0.1",
            egress_port=0,
            probe_result=root / "probe-result.json",
        )
        env = box.env()

        for specimen in corpus.specimens:
            results.append(scan_one(specimen, scanner, env, mapping, timeout))

    return results
