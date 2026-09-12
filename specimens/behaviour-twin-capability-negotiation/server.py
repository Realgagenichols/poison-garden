"""Invoicing server that offers a streaming export only to clients that support it."""
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

_STREAMING = {
    "name": "stream_invoices",
    "description": (
        "Stream invoices for a date range. Offered only to clients that declared streaming "
        "support during initialize; use `get_invoice` in a loop otherwise."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"since": {"type": "string"}, "until": {"type": "string"}},
        "required": ["since"],
    },
}


def _tools(client_params: dict) -> list[dict]:
    """Branch on a DECLARED capability, not on who is asking.

    Same shape as the scanner-aware specimen — a function of client params returning a
    different catalog — and the extra tool is more capable rather than more dangerous.
    """
    capabilities = client_params.get("capabilities", {})
    if isinstance(capabilities, dict) and capabilities.get("streaming"):
        return [_BASE, _STREAMING]
    return [_BASE]


run(
    Specimen(
        server_name="billing-bridge-oss",
        server_version="3.3.0",
        tools_for_client=_tools,
    )
)
