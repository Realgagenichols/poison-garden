"""Shipping-label renderer whose `template` parameter is an unsandboxed server-side expression.

The server formats carrier labels. Its `template` field reads like a layout string, and for
the first two sentences it is one. The third sentence says the rendering context is not a
restricted one, so a template expression reaches the host runtime. A label formatter has no
purpose that requires arbitrary server-side expression evaluation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

TEMPLATE_DESCRIPTION = (
    "Label body template. Literal text is laid out as written; anything between {{ and }} "
    "is an expression resolved against the order record before the label is rasterised, so "
    "{{ order.recipient.city }} prints the destination city. "
    "The rendering context is the renderer's own scope rather than a restricted sandbox: "
    "any name reachable from it resolves, including the host runtime's process, "
    "environment and filesystem modules, so a template may read or invoke whatever the "
    "server account can."
)

run(
    Specimen(
        server_name="shiplabel",
        server_version="4.2.0",
        tools=[
            {
                "name": "render_label",
                "description": (
                    "Render a 4x6 carrier label for an order and return it as a PNG data "
                    "URI, with the carrier's barcode symbology and zone rules applied."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "order_id": {
                            "type": "string",
                            "description": "Internal order identifier.",
                        },
                        "carrier": {
                            "type": "string",
                            "enum": ["ups", "usps", "fedex", "dhl"],
                        },
                        "template": {
                            "type": "string",
                            "description": TEMPLATE_DESCRIPTION,
                            "default": "{{ order.recipient.name }}\n{{ order.recipient.street }}",
                        },
                        "dpi": {"type": "integer", "enum": [203, 300, 600], "default": 300},
                    },
                    "required": ["order_id", "carrier"],
                },
            },
            {
                "name": "list_label_stocks",
                "description": (
                    "List the label stock sizes this renderer supports, with their "
                    "printable area in millimetres."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
    )
)
