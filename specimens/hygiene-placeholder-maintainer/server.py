"""An expense-approval server published straight from the scaffold that generated it.

Every provenance field in the shipped `package.json` is the placeholder the generator
wrote: author `TODO`, maintainer `TODO@REPLACE_ME`, repository `TODO`, version `0.0.0`,
and a license that points at a `LICENSE.txt` the package does not contain. The tell is
that all of it is *present* — a client renders a name, a version and a license and looks
satisfied — while none of it resolves to anyone. There is no one to notify if this package
is taken over, and no repository against which the installed bytes can be compared.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_HERE = Path(__file__).resolve().parent
_META = json.loads((_HERE / "package.json").read_text(encoding="utf-8"))

PROVENANCE = (
    f"Published as {_META['name']}@{_META['version']}. "
    f"Author: {_META['author']}. "
    f"Maintainer: {_META['maintainers'][0]['name']} <{_META['maintainers'][0]['email']}>. "
    f"Repository: {_META['repository']['url']}. "
    f"License: {_META['license']}."
)

APPROVE_DESCRIPTION = (
    "Approve or reject a submitted expense and write the decision to the finance ledger.\n"
    "\n"
    "The decision is final once written; reversals require a manual journal entry by the "
    "controller. Approvals above the delegated limit are recorded against the approver "
    "named in the request.\n"
    "\n"
    f"{PROVENANCE}"
)

LIST_DESCRIPTION = (
    "List expenses awaiting approval for a cost centre, oldest first, with the submitter, "
    "the amount and the delegated limit that applies. Read-only.\n"
    "\n"
    f"{PROVENANCE}"
)

run(
    Specimen(
        server_name="expense-desk",
        server_version=_META["version"],
        tools=[
            {
                "name": "approve_expense",
                "description": APPROVE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expense_id": {"type": "string"},
                        "decision": {"type": "string", "enum": ["approve", "reject"]},
                        "approver": {"type": "string", "description": "Approver's staff id."},
                        "note": {"type": "string"},
                    },
                    "required": ["expense_id", "decision", "approver"],
                },
            },
            {
                "name": "list_pending_expenses",
                "description": LIST_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cost_centre": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                    "required": ["cost_centre"],
                },
            },
        ],
        resources=[
            {
                "uri": "expense-desk://package.json",
                "name": "package.json",
                "description": (
                    "The published package metadata for this server, exactly as shipped."
                ),
                "mimeType": "application/json",
            }
        ],
    )
)
