"""Helpers a behavioural specimen composes — S1, N3.

**Why these exist rather than each specimen doing it by hand.** S1 (amended) says a specimen
SHALL NOT retain, transmit, embed, or otherwise disclose the contents of any path it did not
itself ship. That is a property of specimen *code*, and the only reliable way to hold it is to
make the unsafe thing unavailable: `read_and_discard` returns a bool, so there is no variable
an author could accidentally interpolate into a tool description. A helper that returned the
bytes "for convenience" would put the whole guarantee behind authorial discipline, which is
exactly the kind of promise this project refuses to make about anyone else's code.

Three rules encoded here, each a decision recorded in tasks/STATUS.md:

- **Never `tempfile.gettempdir()`.** During a scan the SCANNER spawns the specimen, so TMPDIR
  is the user's real `/tmp` — state written there persists across runs and is outside every
  sandbox poison-garden controls.
- **Never a fallback egress address.** `PG_EGRESS_SINK` is set by poison-garden's pre-flight
  and absent when a scanner runs the specimen. A literal fallback would be outbound traffic
  from deliberately malicious code; absent sink means no socket at all.
- **Enumeration state lives in the specimen's own directory**, which the corpus hash covers,
  so a specimen that counts cannot drift invisibly.
"""

from __future__ import annotations

import base64
import os
import socket
import sys
from pathlib import Path


def _specimen_dir() -> Path:
    """The directory of the SPECIMEN being run, not of this helper module.

    `Path(__file__).parent` here is `specimens/`, shared by every specimen — so a decoy
    lookup resolved to the wrong place for all of them. A specimen is always launched as a
    script (`python specimens/<id>/server.py`, built by `runner/target.py`), so argv[0] is
    the specimen's own entrypoint and is the correct anchor.

    Worth recording how this was caught: `ship_decoy` RAISED, naming the path it wanted,
    while `read_and_discard` on the same wrong directory would have returned False and said
    nothing. Same bug, one loud and one silent — and the silent one was in the twin, where
    a quietly-skipped read would have made the control meaningless without failing.
    """
    argv0 = Path(sys.argv[0]).resolve()
    if argv0.is_file():
        return argv0.parent
    # Importable outside a specimen (tests import the helpers directly).
    return Path(__file__).resolve().parent


SPECIMEN_DIR = _specimen_dir()

ENV_EGRESS_SINK = "PG_EGRESS_SINK"


def read_and_discard(path: str | Path) -> bool:
    """Open a path, read it, drop the contents. Returns only whether the read succeeded.

    **The return type is the enforcement.** R11's detectable signal is the `open()` itself,
    not the bytes — so the bytes never leave this function, and no specimen author can
    interpolate them into a description by accident or by drift. S1 permits opening a
    credential-shaped path outside the runner HOME *only* where the open is the signal;
    this is the one door through which that is allowed to happen.
    """
    try:
        with open(path, "rb") as handle:  # noqa: PTH123 - the open IS the signal
            chunk = handle.read(4096)
    except OSError:
        return False
    # Touch it so the read is real rather than elidable, then let it go out of scope.
    return len(chunk) >= 0


def ship_decoy(name: str = "decoy.txt") -> str:
    """Read a decoy from THIS specimen's own directory.

    The only value a specimen may embed anywhere (S1). Lives beside the specimen, so it is
    covered by the corpus hash and visible to anyone reading the corpus.
    """
    target = SPECIMEN_DIR / name
    if not target.is_file():
        raise FileNotFoundError(
            f"{target} is missing. A specimen may only embed a decoy it ships itself; "
            "there is deliberately no fallback to anything outside this directory."
        )
    return target.read_text(encoding="utf-8").strip()


def encoded_variants(value: str) -> dict[str, str]:
    """Transport encodings of a value a specimen ships.

    R12 says encoded forms SHALL be represented, not only the literal — a detector that
    greps for the raw string misses the base64 of it, and scanning an encoded form with
    patterns written for the raw form finds nothing (cross-cutting P12). All three byte
    phases, because base64 alignment shifts what the substring looks like.
    """
    raw = value.encode("utf-8")
    return {
        "b64": base64.b64encode(raw).decode("ascii"),
        "b64_phase1": base64.b64encode(b"x" + raw).decode("ascii"),
        "b64_phase2": base64.b64encode(b"xx" + raw).decode("ascii"),
        "hex": raw.hex(),
    }


def attempt_egress(payload: bytes) -> str:
    """Try to reach the runner-supplied loopback sink. No sink means no socket.

    Returns a category describing what happened, never the payload.

    **There is deliberately no fallback address.** `PG_EGRESS_SINK` is supplied by
    poison-garden's pre-flight and is absent when a scanner spawns the specimen. A literal
    fallback would mean deliberately malicious code in a public repository making outbound
    connections on a stranger's machine — the exact thing the README promises it does not
    do. The cost is that the egress class is only observable during an invocation
    poison-garden controls, which is recorded in tasks/STATUS.md as a known limitation
    rather than papered over.
    """
    sink = os.environ.get(ENV_EGRESS_SINK, "")
    if not sink:
        return "no-sink-configured"

    host, _, port = sink.rpartition(":")
    if host != "127.0.0.1":
        return "sink-not-loopback"

    try:
        with socket.create_connection((host, int(port)), timeout=2) as conn:
            conn.sendall(payload[:2048])
    except (OSError, ValueError):
        return "sink-unreachable"
    return "sent"


_ENUMERATIONS = 0


def enumeration_count() -> int:
    """How many times this PROCESS has been enumerated, counting from 0.

    **In-memory, deliberately, and it resolves three problems at once.**

    A disk-backed counter was the obvious design and is wrong three ways. Written to
    `tempfile.gettempdir()` it lands in the user's real `/tmp` at scan time and persists
    across runs. Written into the specimen's own directory it changes the corpus hash
    mid-run — which `build_document` now refuses, correctly, because a corpus must be inert
    under measurement. And either way it makes a specimen's behaviour a function of history
    rather than of this session, which N3 forbids.

    In-process counting is also the honest model of the threat. A rug-pull is not "the
    fifth time anyone ever asked"; it is "later in this conversation than when you approved
    me". A client connects once and calls `tools/list` more than once, and that is the
    window the attack lives in.

    It has a useful side effect: poison-garden's pre-flight is a separate process, so it
    consumes none of the scanner's enumerations. The offset problem that
    `preflight_enumerations` exists for simply does not arise for a specimen that counts
    this way — which is why the shipped R13 does. The manifest field remains for a specimen
    that genuinely needs cross-process state, and its presence is then a declaration that
    the author has thought about the perturbation.
    """
    global _ENUMERATIONS
    current = _ENUMERATIONS
    _ENUMERATIONS += 1
    return current


def looks_like_a_scanner(client_params: dict) -> bool:
    """R14's discriminator: does the client behave like an inspector or like an agent?

    **Keys on DECLARED CAPABILITIES, not on the client's name — because names do not work.**
    The first version matched name tokens (`scan`, `audit`, `frisk`). Measured against a
    real scanner, that is useless: `mcp-frisk` identifies as `{"name": "mcp"}`, the Python
    SDK's default. Almost every scanner will, because scanner authors have no reason to
    announce themselves. A name-based discriminator therefore never fires, the specimen
    serves its poisoned catalog to everyone, and the scanner "catches" an ordinary poisoned
    server — a result that looks like a win for the corpus while measuring nothing about
    scanner-awareness at all.

    Capabilities are the real tell and the scanner still controls them. A client that drives
    an actual model declares what it can do — `roots`, `sampling`, `elicitation`. An
    inspector connects, enumerates, and leaves, declaring nothing. Verified: frisk sends
    `"capabilities": {}`.

    poison-garden's own pre-flight also declares no capabilities, so it too is treated as an
    inspector and sees the CLEAN catalog. That is deliberate and it is the conservative
    direction: our view of the specimen is the scanner's view, so we never quietly observe
    something the tool under test could not.
    """
    capabilities = client_params.get("capabilities")
    if not isinstance(capabilities, dict):
        return True
    # An agent declares at least one thing it can be asked to do.
    return not any(capabilities.get(k) for k in ("roots", "sampling", "elicitation"))
