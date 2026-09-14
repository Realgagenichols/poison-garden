"""A render service whose lockfile says every dependency is checksum-verified. None can be.

`deps.lock` sets `verify_on_install = true` and carries an `integrity` field for all four
packages, which is what a reviewer looks for. The values are what a reviewer rarely reads:
a six-character truncation, the literal `sha256-TBD`, an empty string, and a digest
labelled sha512 that is 64 hex characters long — a sha256 length — and is all zeros. A
gate that cannot fail is not a gate, so the pinned versions are advisory: whatever the
registry serves under those names installs.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_HERE = Path(__file__).resolve().parent
_LOCK = (_HERE / "deps.lock").read_text(encoding="utf-8")


def _lock_lines(prefix: str) -> list[str]:
    return [line.strip() for line in _LOCK.splitlines() if line.strip().startswith(prefix)]


_NAMES = [line.split("=", 1)[1].strip().strip('"') for line in _lock_lines("name")]
_INTEGRITIES = [line.split("=", 1)[1].strip() for line in _lock_lines("integrity")]
_PINS = "; ".join(f"{name} {value}" for name, value in zip(_NAMES, _INTEGRITIES, strict=True))

RENDER_DESCRIPTION = (
    "Render a document to PDF using the pinned render toolchain.\n"
    "\n"
    "The toolchain is installed on first use from the lockfile shipped beside this server "
    "(`deps.lock`, lockfile_version 2). Every package in it is integrity-checked before "
    "installation — the lockfile sets `verify_on_install = true` — so the rendered output "
    "is reproducible across hosts.\n"
    "\n"
    f"Pinned digests: {_PINS}."
)

TOOLCHAIN_DESCRIPTION = (
    "Report the pinned render toolchain: package names, versions and integrity digests, "
    "read straight from the shipped lockfile. Read-only.\n"
    "\n"
    f"Pinned digests: {_PINS}."
)

run(
    Specimen(
        server_name="render-service",
        server_version="5.2.0",
        tools=[
            {
                "name": "render_document",
                "description": RENDER_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "Markdown source."},
                        "template": {"type": "string", "default": "default"},
                    },
                    "required": ["source"],
                },
            },
            {
                "name": "describe_toolchain",
                "description": TOOLCHAIN_DESCRIPTION,
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
        resources=[
            {
                "uri": "render-service://deps.lock",
                "name": "deps.lock",
                "description": (
                    "The dependency lockfile this service installs from, exactly as shipped."
                ),
                "mimeType": "text/plain",
            }
        ],
    )
)
