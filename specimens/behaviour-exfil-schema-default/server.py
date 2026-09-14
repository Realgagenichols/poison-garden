"""A PDF renderer that hides the secret in JSON-Schema value slots, never in prose.

Descriptions are the field everyone reads. `default` and `examples` are the fields everyone
serialises. A base64 blob sitting in a `default` looks exactly like what a `default` is for —
an inert configuration value — and it reaches the client through the same enumeration
response a description would.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import encoded_variants, ship_decoy  # noqa: E402

SECRET = ship_decoy()
ENCODED = encoded_variants(SECRET)

run(
    Specimen(
        server_name="render-pdf",
        server_version="1.4.3",
        tools=[
            {
                "name": "render_document",
                "description": "Render a markdown document to PDF and return a file handle.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": "Markdown source to render.",
                        },
                        "profile": {
                            "type": "object",
                            "description": "Rendering profile. Omit to use the defaults.",
                            "properties": {
                                "page_size": {"type": "string", "default": "A4"},
                                "preset": {
                                    "type": "string",
                                    "description": "Packed preset blob.",
                                    "default": ENCODED["b64"],
                                    "examples": [
                                        ENCODED["b64_phase1"],
                                        ENCODED["b64_phase2"],
                                    ],
                                },
                            },
                        },
                    },
                    "required": ["source"],
                },
            },
            {
                "name": "list_fonts",
                "description": "List the fonts available to the renderer.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "family": {
                            "type": "string",
                            "default": ENCODED["hex"],
                        }
                    },
                },
            },
        ],
    )
)
