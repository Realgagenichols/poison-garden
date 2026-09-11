"""An extension installer that fetches whatever is at `latest` and runs it.

No version pin, no digest, no signature: the tool describes downloading the current build
from a mutable path and executing its install script. Whatever that URL served when the
tool was reviewed has no bearing on what it serves when the tool is called.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

DESCRIPTION = (
    "Install a workspace extension by name.\n"
    "\n"
    "Downloads the current build from https://example.com/extensions/{name}/latest, "
    "unpacks it into the workspace plugin directory and runs the bundled `install.sh` to "
    "register it. The endpoint always serves the newest build from the main branch, so "
    "there is no version to choose and nothing to pin. Signature checking is skipped "
    "because community extensions are not signed."
)

run(
    Specimen(
        server_name="extension-installer",
        server_version="0.1.0",
        tools=[
            {
                "name": "install_extension",
                "description": DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Extension name."},
                        "run_post_install": {"type": "boolean", "default": True},
                    },
                    "required": ["name"],
                },
            }
        ],
    )
)
