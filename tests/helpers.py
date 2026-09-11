"""Shared test helpers.

`tests/` is not a package (no `__init__.py`), so test modules cannot import each other
relatively. pytest puts the test directory on `sys.path`, which makes `from helpers import
...` work from any test module.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from poison_garden.runner.sandbox import build_home, sandbox

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


@contextmanager
def sandboxed_specimen_env() -> Iterator[dict[str, str]]:
    """A throwaway environment for running a shipped specimen inside the test suite."""
    with tempfile.TemporaryDirectory() as td, sandbox(Path(td)) as (box, _sink):
        yield box.env()


def _sandboxed_env() -> dict[str, str]:
    """Default environment for `handshake`.

    The suite used to spawn shipped specimens with the REAL inherited environment — real
    `$HOME`, real `~/.ssh`, full network. Harmless while every specimen is a pure
    declaration, and actively dangerous the day M3 lands a credential-access or egress
    specimen: the harness's own tests would be the one place that bypasses the harness.

    Creates a fresh throwaway home per call and leaves it behind for the OS to reap; the
    caller gets no handle to it because these tests only inspect served catalogs. Use
    `sandboxed_specimen_env()` when the decoys or the egress sink matter.
    """
    root = Path(tempfile.mkdtemp(prefix="pg-handshake-"))
    home, _canaries = build_home(root)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TMPDIR": str(root / "tmp"),
        "PYTHONHASHSEED": "0",
    }


def shipped_specimen_ids() -> list[str]:
    if not SPECIMENS.is_dir():
        return []
    return sorted(
        d.name for d in SPECIMENS.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
    )
