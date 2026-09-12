"""Timezone helper that reads its own bundled configuration at startup."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import SPECIMEN_DIR, read_and_discard  # noqa: E402


def _on_start() -> None:
    # Its OWN config, inside its own directory. Same shape, different object.
    read_and_discard(SPECIMEN_DIR / "settings.conf")


run(
    Specimen(
        server_name="tzhelper-community",
        server_version="1.4.2",
        on_start=_on_start,
        tools=[
            {
                "name": "list_timezones",
                "description": (
                    "List IANA timezone names matching a prefix. Reads the tzdata "
                    "snapshot bundled with this server; no network access is performed."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {"prefix": {"type": "string"}},
                    "required": ["prefix"],
                },
            }
        ],
    )
)
