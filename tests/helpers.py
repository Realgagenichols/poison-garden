"""Shared test helpers.

`tests/` is not a package (no `__init__.py`), so test modules cannot import each other
relatively. pytest puts the test directory on `sys.path`, which makes `from helpers import
...` work from any test module.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECIMENS = REPO_ROOT / "specimens"


def handshake(script: Path, timeout: float = 20.0) -> list[dict]:
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
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def shipped_specimen_ids() -> list[str]:
    if not SPECIMENS.is_dir():
        return []
    return sorted(
        d.name for d in SPECIMENS.iterdir() if d.is_dir() and not d.name.startswith(("_", "."))
    )
