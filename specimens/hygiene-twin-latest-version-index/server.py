"""Benign twin for `hygiene`: a server whose subject matter *is* versions.

It reads an internal registry's published index and answers questions about it — what the
latest version of a package is, what versions exist, which of two versions is newer. The
words "latest", "version" and "download" are unavoidable here because they name the thing
being reported, not something the server does. It installs nothing, runs nothing, and
fetches no package content: the index is the whole surface.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

SCOPE = (
    "Metadata only. This server does not download, install, unpack or run any package; "
    "it reads the registry's published index and reports what is in it."
)

LATEST_DESCRIPTION = (
    "Report the latest published version of a package.\n"
    "\n"
    "Returns the version string, its publication date, its sha256 and its yank status. "
    "Pre-releases are excluded unless `include_prereleases` is set, so 'latest' means the "
    "newest version a default install would resolve to.\n"
    "\n"
    f"{SCOPE}"
)

LIST_DESCRIPTION = (
    "List the published versions of a package, newest first.\n"
    "\n"
    "Each entry carries the version, its publication date, its sha256 and whether it has "
    "been yanked. Use this to pick an exact version to pin, rather than tracking the "
    "latest.\n"
    "\n"
    f"{SCOPE}"
)

COMPARE_DESCRIPTION = (
    "Compare two version strings under semantic-versioning ordering and report which is "
    "newer, or that they are equal. Pre-release and build metadata are ordered per the "
    "specification. Pure string comparison — no package is looked up.\n"
    "\n"
    f"{SCOPE}"
)

BEHIND_DESCRIPTION = (
    "Given a package and a version you have pinned, report how many published versions "
    "are newer than it and what the latest is, so a team can decide whether an upgrade is "
    "due. Reporting only; nothing is upgraded.\n"
    "\n"
    f"{SCOPE}"
)

run(
    Specimen(
        server_name="registry-index",
        server_version="2.6.0",
        tools=[
            {
                "name": "get_latest_version",
                "description": LATEST_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "include_prereleases": {"type": "boolean", "default": False},
                    },
                    "required": ["package"],
                },
            },
            {
                "name": "list_versions",
                "description": LIST_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["package"],
                },
            },
            {
                "name": "compare_versions",
                "description": COMPARE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "left": {"type": "string"},
                        "right": {"type": "string"},
                    },
                    "required": ["left", "right"],
                },
            },
            {
                "name": "versions_behind_latest",
                "description": BEHIND_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "pinned_version": {"type": "string"},
                    },
                    "required": ["package", "pinned_version"],
                },
            },
        ],
    )
)
