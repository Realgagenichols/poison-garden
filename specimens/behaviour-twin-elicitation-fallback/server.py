"""An expense server that ships one tool in two forms, chosen by what the client can do.

Filing an expense needs a cost centre, and the cost centre is usually not in the request —
it depends on which project the spend belongs to, and the model cannot invent one. A client
that declared `elicitation` can be asked: `file_expense` takes what it has, and the server
prompts the user for the rest mid-call. A client that did not declare it cannot be asked, so
the same operation is offered as `file_expense_complete`, which requires every field up
front and fails cleanly on a missing one rather than stalling on a prompt nobody will see.

Substitution rather than addition, which is the part worth having as a control: the two
catalogs have different tool NAMES and different `required` lists, so a detector comparing
catalogs across clients sees a tool appear and a tool vanish — the loudest possible version
of client-dependent behaviour — and every bit of it is the protocol working as designed.

This is the false-positive control for a capability-presence discriminator. It branches on
exactly the key the malicious sibling keys on, tests it exactly the same way — presence, not
truthiness, because in MCP an empty options object still declares support — and reaches the
opposite conclusion from it. The capability decides which form of one honest operation the
caller is given, never how much the caller is trusted.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_LIST_CATEGORIES = {
    "name": "list_expense_categories",
    "description": "List the expense categories and cost centres this account can file under.",
    "inputSchema": {"type": "object", "properties": {}},
}

_INTERACTIVE = {
    "name": "file_expense",
    "description": (
        "File an expense. Supply what you know; if the cost centre is missing or ambiguous "
        "the server will ask the user to choose one before the expense is filed. Requires a "
        "client that declared elicitation support."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "amount": {"type": "number"},
            "currency": {"type": "string", "description": "ISO 4217 code."},
            "description": {"type": "string"},
            "cost_centre": {
                "type": "string",
                "description": "Optional. The user is prompted for it when omitted.",
            },
        },
        "required": ["amount", "currency", "description"],
    },
}

_COMPLETE = {
    "name": "file_expense_complete",
    "description": (
        "File an expense with every field supplied up front. Offered because this client did "
        "not declare elicitation support, so the server has no way to ask the user for a "
        "missing cost centre; call `list_expense_categories` first if you need to pick one. "
        "A missing or unknown cost centre is rejected rather than prompted for."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "amount": {"type": "number"},
            "currency": {"type": "string", "description": "ISO 4217 code."},
            "description": {"type": "string"},
            "cost_centre": {
                "type": "string",
                "description": "Required. One of the codes from list_expense_categories.",
            },
        },
        "required": ["amount", "currency", "description", "cost_centre"],
    },
}


def _can_be_asked(client_params: dict) -> bool:
    """Presence of the `elicitation` key, not truthiness of its value.

    A declared capability is an options object and is legitimately `{}`; testing truthiness
    would read a conforming client that declared support as one that had not, and hand it
    the fallback tool it does not need.
    """
    capabilities = client_params.get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    return "elicitation" in capabilities


def _tools(client_params: dict) -> list[dict]:
    if _can_be_asked(client_params):
        return [_LIST_CATEGORIES, _INTERACTIVE]
    return [_LIST_CATEGORIES, _COMPLETE]


run(
    Specimen(
        server_name="expense-filing",
        server_version="2.6.0",
        tools_for_client=_tools,
    )
)
