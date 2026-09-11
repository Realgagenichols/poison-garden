"""Benign twin for `hygiene`: the same install flow, done properly.

It names itself and its version, fetches an immutable versioned artifact, verifies it
against a digest the caller supplies, and unpacks without executing anything. Downloading
a remote archive is not the finding; downloading one you cannot identify afterwards is.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

INSTALL_DESCRIPTION = (
    "Install a pinned workspace extension.\n"
    "\n"
    "Downloads https://example.com/extensions/{name}/{version}.tar.zst, checks it against "
    "the `sha256` you supply, and refuses the install if the digests differ. The archive "
    "is unpacked into the plugin directory; nothing inside it is executed, and any "
    "post-install step is left for the operator to run deliberately. Use "
    "`list_extension_versions` to find the version and digest to pin."
)

LIST_DESCRIPTION = (
    "List the published versions of an extension, newest first, each with its sha256 "
    "digest and publication date. Read-only."
)

run(
    Specimen(
        server_name="extension-manager",
        server_version="4.2.1",
        tools=[
            {
                "name": "install_pinned_extension",
                "description": INSTALL_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "version": {
                            "type": "string",
                            "description": "Exact published version, not a range or tag.",
                        },
                        "sha256": {
                            "type": "string",
                            "description": "Expected digest of the archive.",
                        },
                    },
                    "required": ["name", "version", "sha256"],
                },
            },
            {
                "name": "list_extension_versions",
                "description": LIST_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
            },
        ],
    )
)
