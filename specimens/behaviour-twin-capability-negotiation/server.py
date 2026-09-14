"""Invoicing server that offers a file export only to clients that gave it somewhere to write.

Gates on `roots`, a real MCP client capability. It previously gated on `capabilities.streaming`,
which is not an MCP capability at all — it existed only because the test that exercised this
twin sent a fabricated one. A control keyed on a capability no real client declares models no
real false positive; it fired against the probe and would never have fired against a client.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_BASE = {
    "name": "get_invoice",
    "description": "Fetch an invoice by id and return its line items.",
    "inputSchema": {
        "type": "object",
        "properties": {"invoice_id": {"type": "string"}},
        "required": ["invoice_id"],
    },
}

_EXPORT = {
    "name": "export_invoices",
    "description": (
        "Write invoices for a date range to a CSV file inside one of the workspace roots "
        "you declared during initialize. Offered only to clients that declared `roots`, "
        "because there is otherwise nowhere this server is permitted to write; use "
        "`get_invoice` in a loop and format the result yourself instead."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "since": {"type": "string"},
            "until": {"type": "string"},
            "destination": {
                "type": "string",
                "description": "Path relative to a declared root.",
            },
        },
        "required": ["since", "destination"],
    },
}


def _tools(client_params: dict) -> list[dict]:
    """Branch on a DECLARED capability, not on who is asking.

    Same shape as the scanner-aware specimen — a function of client params returning a
    different catalog — and the extra tool is more capable rather than more dangerous.
    """
    capabilities = client_params.get("capabilities", {})
    # PRESENCE, not truthiness: in MCP a capability is declared by the key existing, and
    # `"roots": {}` is a legitimate empty options object. Testing truthiness would classify
    # a real client as one that declared nothing — the same bug that once shipped in the
    # malicious scanner-aware specimen, and it is worth this twin holding the correct form.
    if isinstance(capabilities, dict) and "roots" in capabilities:
        return [_BASE, _EXPORT]
    return [_BASE]


run(
    Specimen(
        server_name="billing-bridge-oss",
        server_version="3.3.0",
        tools_for_client=_tools,
    )
)
