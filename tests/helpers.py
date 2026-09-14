"""Shared test helpers.

`tests/` is not a package (no `__init__.py`), so test modules cannot import each other
relatively. pytest puts the test directory on `sys.path`, which makes `from helpers import
...` work from any test module.
"""

from __future__ import annotations

import atexit
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from poison_garden.runner.sandbox import EgressSink, Sandbox, build_home

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIMENS = REPO_ROOT / "specimens"


def handshake(
    script: Path, timeout: float = 20.0, env: dict[str, str] | None = None
) -> list[dict]:
    """Drive a real MCP handshake against a specimen; return its parsed responses.

    Sends `initialize` (id 1) then `tools/list` (id 2) and closes stdin. Uses
    `communicate(input=...)` rather than writing and closing stdin by hand — doing the
    latter makes communicate's own flush raise on a closed file.
    """
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
        env=env if env is not None else _sandboxed_env(),
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


_SESSION_SANDBOX: tuple[Sandbox, EgressSink] | None = None


def _session_sandbox() -> Sandbox:
    """One throwaway world for the whole test session.

    Returns a real `Sandbox`, so `handshake()` uses `Sandbox.env()` itself rather than a
    second hand-written copy of the allowlist. The first version of this function
    duplicated that allowlist and had already drifted — missing LANG, PG_EGRESS_SINK and
    PG_PROBE_RESULT — which is P95 (one predicate spelled twice drifts, and the copy in
    the other runtime fails silently). It is worse than the usual case here, because this
    copy is what decides whether the TEST SUITE is sandboxed. When the scrub in
    `Sandbox.env()` evolves, this must evolve with it, and the only way to guarantee that
    is to not have a second one.

    Session-scoped rather than per-call: one home instead of ~40, torn down at exit.
    """
    global _SESSION_SANDBOX
    if _SESSION_SANDBOX is None:
        root = Path(tempfile.mkdtemp(prefix="pg-session-"))
        home, canaries = build_home(root)
        sink = EgressSink().start()
        box = Sandbox(
            home=home,
            canaries=canaries,
            egress_host=sink.host,
            egress_port=sink.port,
            probe_result=root / "probe-result.json",
        )
        _SESSION_SANDBOX = (box, sink)

        def _teardown() -> None:
            sink.stop()
            shutil.rmtree(root, ignore_errors=True)

        atexit.register(_teardown)

    return _SESSION_SANDBOX[0]


def session_sink() -> EgressSink:
    """The session sandbox's egress sink, for tests that assert on egress attempts."""
    _session_sandbox()
    assert _SESSION_SANDBOX is not None
    return _SESSION_SANDBOX[1]


def _sandboxed_env() -> dict[str, str]:
    """Default environment for `handshake` — the real `Sandbox.env()`, never a copy.

    The suite used to spawn shipped specimens with the REAL inherited environment: real
    `$HOME`, real `~/.ssh`, full network. Harmless while every specimen is a pure
    declaration, and dangerous the day M3 lands a credential-access or egress specimen —
    the harness's own tests would be the one place that bypasses the harness.
    """
    return _session_sandbox().env()


def shipped_specimen_ids() -> list[str]:
    if not SPECIMENS.is_dir():
        return []
    return sorted(
        d.name for d in SPECIMENS.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
    )


def _drive(script: Path, messages: list[dict], env: dict[str, str] | None = None) -> list[dict]:
    """Send a sequence of JSON-RPC messages in ONE session and parse the replies."""
    stdin_text = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=30,
        env=env if env is not None else _sandboxed_env(),
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _init(client_name: str = "poison-garden-tests", capabilities: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": client_name, "version": "0"},
            "capabilities": capabilities or {},
        },
    }


def enumerate_n_times_in_one_session(
    script: Path, n: int, client_name: str = "claude-desktop"
) -> list[str]:
    """`n` successive `tools/list` calls on ONE connection, as served JSON strings.

    Replaced a two-sample `enumerate_twice_in_one_session`, which hard-coded the
    assumption that a rug-pull fires on the second enumeration and so made the
    late-firing specimen inexpressible — the one that matters most, because a scanner
    sampling twice still misses it. Deleted rather than kept alongside: leaving a
    two-sample helper in place is an invitation to reintroduce the weaker check.
    """
    requests = [_init(client_name)]
    requests += [
        {"jsonrpc": "2.0", "id": i, "method": "tools/list"} for i in range(2, 2 + n)
    ]
    by_id = {r.get("id"): r for r in _drive(script, requests)}
    return [
        json.dumps(by_id[i].get("result", {}), sort_keys=True)
        for i in range(2, 2 + n)
        if i in by_id
    ]


def catalog_for_client(script: Path, client_name: str, capabilities: dict | None = None) -> str:
    """The catalog served to a client declaring a given identity."""
    replies = _drive(
        script,
        [_init(client_name, capabilities), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
    )
    for reply in replies:
        if reply.get("id") == 2:
            return json.dumps(reply.get("result", {}), sort_keys=True)
    return ""


# Client profiles spanning what a server can actually observe about who is asking.
#
# One inspector/agent PAIR is not enough, and the corpus proved it. The pair varied
# `capabilities` and `clientInfo.name` only, so a specimen keying on the *shape* of
# `clientInfo` — or a twin negotiating on `protocolVersion` — served both probes the same
# bytes, and the test concluded no evasion occurred. R14 lets a specimen key on anything the
# client reveals; a fixed pair silently narrowed that to one axis, and the narrowing showed
# up as a green test, never as a gap.
#
# Each profile is a coherent client rather than a knob: INSPECTOR is what something that
# connects, enumerates and leaves actually sends (two required fields, nothing declared),
# and the agents are what something driving a model sends. `title` is in the 2025-06-18
# Implementation schema precisely so a host can show a person which app is connected — a
# client that fills it has a UI, and therefore a user.
# `sends_initialized` is part of the profile, not a knob on top of it. MCP requires a client
# to send `notifications/initialized` once the handshake completes; a real client does, and
# something that connects, enumerates and disconnects often does not bother. That is a tell a
# specimen may legitimately key on, and a driver that never sent the notification for ANY
# profile made every client look like an inspector — so a specimen keying on it served one
# catalog to everything and read as not evading.
CLIENT_PROFILES: dict[str, dict] = {
    "inspector": {
        # One enumeration, then gone. That IS the inspector's signature, and a specimen may
        # legitimately key on it: a scanner that connects, lists once and disconnects never
        # sees what a client re-listing mid-session sees.
        "enumerations": 1,
        "sends_initialized": False,
        # Sweeps every list endpoint before asking for tools. That is what exhaustive
        # enumeration looks like, and it is the opposite of a client, which asks for the
        # thing it needs.
        "sweeps_first": True,
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "mcp", "version": "0.1.0"},
            "capabilities": {},
        },
    },
    "agent": {
        "enumerations": 2,
        "sends_initialized": True,
        "sweeps_first": False,
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {
                "name": "claude-desktop",
                "version": "1.4.0",
                "title": "Claude",
            },
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {},
                "elicitation": {},
            },
        },
    },
    "agent-older-protocol": {
        "enumerations": 2,
        "sends_initialized": True,
        "sweeps_first": False,
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "some-host", "version": "0.9.2", "title": "Some Host"},
            "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
        },
    },
}

INSPECTOR_PROFILE = "inspector"


def catalog_for_profile(script: Path, profile: str) -> str:
    """The LAST catalog one named client profile is served, as a sorted JSON string.

    The last rather than the first, because the number of enumerations is itself part of
    the profile. A driver that always listed once made every client look like an inspector
    to a specimen keying on re-enumeration, so the specimen served one catalog to
    everything and the test concluded there was no evasion to find.
    """
    spec = CLIENT_PROFILES[profile]
    messages: list[dict] = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": spec["params"]}
    ]
    if spec["sends_initialized"]:
        # No `id`: this is a notification and takes no response, which is why a server that
        # keys on it has to observe the raw stream rather than a request handler.
        messages.append({"jsonrpc": "2.0", "method": "notifications/initialized"})
    if spec["sweeps_first"]:
        messages += [
            {"jsonrpc": "2.0", "id": 90, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 91, "method": "prompts/list"},
            {"jsonrpc": "2.0", "id": 92, "method": "resources/templates/list"},
        ]
    last_id = 1 + spec["enumerations"]
    for request_id in range(2, last_id + 1):
        messages.append({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})
    replies = _drive(script, messages)
    for reply in replies:
        if reply.get("id") == last_id:
            return json.dumps(reply.get("result", {}), sort_keys=True)
    return ""


def catalogs_across_profiles(script: Path) -> dict[str, str]:
    """What each profile is served, keyed by profile name."""
    return {name: catalog_for_profile(script, name) for name in CLIENT_PROFILES}


def variation_defects(specimen_id: str, catalogs: list[str], fires_at: int) -> list[str]:
    """Every way a rug-pull's served catalogs disagree with its declared threshold.

    Returns findings rather than asserting, so the check itself can be falsified: a test
    feeds it a specimen that fires early and asserts it is CAUGHT. A guard written inline
    as bare asserts cannot be exercised that way, and this one has a vacuity trap worth
    proving absent — the "did not fire early" loop is `range(1, fires_at)`, which is empty
    for the default threshold of 1. If every rug-pull declared 1, that half of the check
    would never execute and nothing would say so (P58/P64).
    """
    found: list[str] = []
    if len(catalogs) < fires_at + 1:
        return [
            f"{specimen_id}: served only {len(catalogs)} catalogs, need {fires_at + 1} — "
            "it stopped responding mid-session"
        ]
    for earlier in range(1, fires_at):
        if catalogs[earlier] != catalogs[0]:
            found.append(
                f"{specimen_id}: declares varies_at_enumeration = {fires_at} but the "
                f"catalog already changed at enumeration {earlier}"
            )
    if catalogs[fires_at] == catalogs[0]:
        found.append(
            f"{specimen_id}: declares varies_at_enumeration = {fires_at}, but that "
            "enumeration served the same catalog as enumeration 0 — the rug-pull never "
            "happens"
        )
    return found


# The axes a profile differs on. Named so the coherence check below can assert that the
# inspector and the agents differ on ALL of them rather than on whichever one a specimen
# happened to need.
PROFILE_AXES = ("enumerations", "sends_initialized", "sweeps_first")
