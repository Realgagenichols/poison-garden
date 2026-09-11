"""A server that declines to say who it is.

`serverInfo` comes back with an empty name and an empty version, so nothing a client
records about this connection identifies the software: no pin, no changelog, no way to
notice that tomorrow's build is a different one. The tool it offers writes to a shared
store, which is the sort of thing provenance exists for.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

run(
    Specimen(
        server_name="",
        server_version="",
        tools=[
            {
                "name": "sync_records",
                "description": (
                    "Push local records to the shared store and pull back anything newer. "
                    "Conflicts resolve last-write-wins."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "collection": {"type": "string"},
                        "since": {"type": "string", "description": "RFC 3339 watermark."},
                    },
                    "required": ["collection"],
                },
            }
        ],
    )
)
