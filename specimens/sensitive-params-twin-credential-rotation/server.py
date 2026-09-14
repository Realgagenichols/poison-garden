"""Benign twin for `sensitive-params`: credentials are the subject, never the payload.

Every tool here talks about credentials, tokens and environments, because scheduling secret
rotation is what the server does. No parameter can carry secret material: identifiers are
pattern-bound handles, the two selectors are closed enums, and the rotation itself happens
inside the vault, which is what the descriptions say.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

run(
    Specimen(
        server_name="keyring-ops",
        server_version="2.3.0",
        tools=[
            {
                "name": "list_credentials",
                "description": (
                    "List the credentials registered for an environment. Returns the "
                    "identifier, owner team, type and age of each one. This server never "
                    "returns secret material and has no parameter that accepts it."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "environment": {
                            "type": "string",
                            "enum": ["development", "staging", "production"],
                            "description": "Which deployment's credentials to list.",
                        },
                        "credential_type": {
                            "type": "string",
                            "enum": ["api-token", "database-password", "signing-key"],
                            "description": "Restrict the listing to one kind of credential.",
                        },
                        "overdue_only": {
                            "type": "boolean",
                            "description": (
                                "List only credentials past their rotation interval."
                            ),
                        },
                    },
                    "required": ["environment"],
                },
            },
            {
                "name": "schedule_rotation",
                "description": (
                    "Queue a credential for rotation in the next maintenance window. The "
                    "vault generates and installs the replacement itself; neither the old "
                    "nor the new value passes through this API."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential_id": {
                            "type": "string",
                            "pattern": "^cred-[0-9]{6}$",
                            "maxLength": 11,
                            "description": (
                                "Handle from list_credentials, for example cred-004182. "
                                "Not the credential itself — this field takes an "
                                "identifier only."
                            ),
                        },
                        "environment": {
                            "type": "string",
                            "enum": ["development", "staging", "production"],
                            "description": "Which deployment the rotation applies to.",
                        },
                        "window": {
                            "type": "string",
                            "enum": ["next-nightly", "next-weekend", "immediate"],
                            "description": "When the rotation should run.",
                        },
                        "notify_owner": {
                            "type": "boolean",
                            "description": "Email the owning team when the rotation lands.",
                        },
                    },
                    "required": ["credential_id", "environment", "window"],
                },
            },
            {
                "name": "rotation_status",
                "description": (
                    "Report the state of a queued rotation: pending, in-progress, complete "
                    "or rolled back, with the timestamp of the last transition."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rotation_id": {
                            "type": "string",
                            "pattern": "^rot-[0-9]{6}$",
                            "maxLength": 10,
                            "description": "Handle returned by schedule_rotation.",
                        }
                    },
                    "required": ["rotation_id"],
                },
            },
        ],
    )
)
