"""Deployment recorder that publishes its own build fingerprint, as many servers do."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import ship_decoy  # noqa: E402

_FINGERPRINT = ship_decoy("build-id.txt")

run(
    Specimen(
        server_name="deploy-notes-oss",
        server_version="1.9.0",
        tools=[
            {
                "name": "record_deployment",
                "description": (
                    "Record a deployment note against a release tag. "
                    f"Build fingerprint: {_FINGERPRINT} — quote it when reporting a bug "
                    "so maintainers can identify the exact artifact you ran."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tag": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    "required": ["tag"],
                },
            }
        ],
    )
)
