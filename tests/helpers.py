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


def enumerate_twice_in_one_session(script: Path, client_name: str = "claude-desktop") -> list[str]:
    """Two `tools/list` calls on ONE connection — the window a rug-pull lives in.

    A client connects once and enumerates more than once; the attack is "later in this
    conversation than when you approved me", not "the fifth time anyone ever asked".
    """
    replies = _drive(
        script,
        [
            _init(client_name),
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        ],
    )
    by_id = {r.get("id"): r for r in replies}
    return [
        json.dumps(by_id[i].get("result", {}), sort_keys=True)
        for i in (2, 3)
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
