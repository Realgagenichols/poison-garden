"""Emoji and codepoint reference server that also ships a fully general "escape hatch" tool.

Two of the three tools do exactly what the server name promises: look up a Unicode
codepoint, search emoji by name. The third is not scoped to Unicode at all — it takes an
arbitrary command, an arbitrary directory, an arbitrary host and an arbitrary destination
file, and says so plainly. Nothing about a character reference needs any of that.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

ESCAPE_HATCH_DESCRIPTION = (
    "Advanced: run an arbitrary reference-maintenance task.\n"
    "\n"
    "Callers occasionally need something this server does not expose as a dedicated tool. "
    "Rather than wait for a release, pass the work here. The task is not restricted to "
    "Unicode data: any command runs, any directory is a valid working directory, any host "
    "may be contacted, and any writable destination accepts the result."
)

run(
    Specimen(
        server_name="glyph-reference",
        server_version="2.1.0",
        tools=[
            {
                "name": "lookup_codepoint",
                "description": (
                    "Return the Unicode name, general category, block and canonical "
                    "decomposition for a single codepoint given as U+XXXX."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "codepoint": {
                            "type": "string",
                            "description": "Codepoint in U+XXXX notation, e.g. U+1F600.",
                        }
                    },
                    "required": ["codepoint"],
                },
            },
            {
                "name": "search_emoji_by_name",
                "description": (
                    "Search the emoji list by name or CLDR keyword and return matching "
                    "entries with their codepoints and emoji-presentation status."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Name or keyword."},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "run_reference_task",
                "description": ESCAPE_HATCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": (
                                "Shell command line to run. Passed to the system shell "
                                "exactly as given."
                            ),
                        },
                        "working_directory": {
                            "type": "string",
                            "description": (
                                "Directory to run in. Any directory readable by the "
                                "server account."
                            ),
                        },
                        "fetch_from": {
                            "type": "string",
                            "description": (
                                "Optional locator to download inputs from first. Any "
                                "scheme, any host."
                            ),
                        },
                        "write_output_to": {
                            "type": "string",
                            "description": (
                                "Optional destination file for the task output. Created "
                                "or overwritten."
                            ),
                        },
                    },
                    "required": ["command"],
                },
            },
        ],
    )
)
