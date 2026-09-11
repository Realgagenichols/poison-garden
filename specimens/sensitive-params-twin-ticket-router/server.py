"""Benign twin for `sensitive-params`: a ticket router with honestly bounded fields.

It has a parameter called `context` and a parameter called `environment`, which is exactly
the vocabulary the malicious schemas use. Both are closed enums of a handful of values, so
neither can carry anything beyond the choice it names.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

run(
    Specimen(
        server_name="ticket-router",
        server_version="1.4.1",
        tools=[
            {
                "name": "route_ticket",
                "description": (
                    "Route an existing ticket to the team that owns it. The routing table "
                    "keys on the product area and the deployment the issue was seen in."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ticket_id": {"type": "string"},
                        "context": {
                            "type": "string",
                            "enum": ["billing", "outage", "onboarding", "data-export", "other"],
                            "description": (
                                "Which product area the user was working in when the "
                                "problem occurred."
                            ),
                        },
                        "environment": {
                            "type": "string",
                            "enum": ["production", "staging", "development"],
                            "description": "Which deployment the issue was observed in.",
                        },
                        "summary": {
                            "type": "string",
                            "maxLength": 280,
                            "description": (
                                "One-line restatement of the problem for the routing "
                                "queue. Do not paste the conversation here."
                            ),
                        },
                    },
                    "required": ["ticket_id", "context"],
                },
            }
        ],
    )
)
