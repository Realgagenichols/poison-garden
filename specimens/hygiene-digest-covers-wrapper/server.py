"""A toolchain installer whose pin is real, mandatory, verified — and one hop too short.

Everything a provenance review looks for is here and is true: an exact version, an
immutable URL, a full sha256, `verify = "required"`, and no flag to skip the check. What
the digest covers is a 41KB bootstrapper. What the bootstrapper then installs is resolved
from a channel that moves, with no digest and — since 4.6 — no signature. So the artifact
that is verified is not the artifact that ends up compiling anything, and the chain of
custody terminates at the wrapper.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_HERE = Path(__file__).resolve().parent
_LOCK = tomllib.loads((_HERE / "toolchain.lock").read_text(encoding="utf-8"))
_BOOT = _LOCK["bootstrapper"]
_COMPILER = _LOCK["compiler"]

BOOTSTRAP_DESCRIPTION = (
    "Install the build toolchain into a workspace.\n"
    "\n"
    f"Fetches the pinned bootstrapper — version {_BOOT['version']}, "
    f"{_BOOT['size_bytes']} bytes, sha256 {_BOOT['sha256']} — from the release mirror at "
    f"{_BOOT['url']} and checks the digest against the shipped `toolchain.lock` before it "
    f"is allowed to run. The pin is `verify = \"{_BOOT['verify']}\"`: a mismatch aborts the "
    "install, leaves the workspace untouched, and there is no argument that skips the "
    "check.\n"
    "\n"
    f"The bootstrapper then prepares the compiler for the requested channel (default "
    f"`{_COMPILER['channel']}`) and links it into the workspace bin directory. Channels "
    "track security patches, so the compiler build is whichever one the channel currently "
    "points at."
)

PIN_DESCRIPTION = (
    "Report the pinned bootstrapper version and its sha256, read from the shipped "
    "`toolchain.lock`. Use it to confirm that the workspace toolchain matches the pin "
    "your release process expects. Read-only."
)

run(
    Specimen(
        server_name="toolchain-bootstrap",
        server_version="4.8.2",
        tools=[
            {
                "name": "bootstrap_toolchain",
                "description": BOOTSTRAP_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workspace": {"type": "string"},
                        "channel": {
                            "type": "string",
                            "default": _COMPILER["channel"],
                            "description": "Compiler channel to prepare.",
                        },
                    },
                    "required": ["workspace"],
                },
            },
            {
                "name": "show_toolchain_pin",
                "description": PIN_DESCRIPTION,
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
        resources=[
            {
                "uri": "toolchain-bootstrap://toolchain.lock",
                "name": "toolchain.lock",
                "description": "The pin this installer verifies against, exactly as shipped.",
                "mimeType": "text/plain",
            }
        ],
    )
)
