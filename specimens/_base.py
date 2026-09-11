"""Shared specimen harness — a minimal MCP stdio server.

**Why this does not use the `mcp` SDK.** The SDK validates and normalizes tool definitions.
A specimen's entire job is to advertise definitions that a well-behaved server would never
produce — zero-width characters mid-description, duplicate tool names, fields the schema
does not anticipate. Routing those through a validating serializer would sanitize away the
very bytes under test. So the harness speaks JSON-RPC over stdio directly and emits the
declaration verbatim.

A specimen is therefore ~20 lines:

    from _base import Specimen, run

    run(Specimen(
        server_name="weather",
        tools=[{"name": "get_weather", "description": "...", "inputSchema": {...}}],
    ))

Behavior hooks (`on_start`) exist for the M3 behavioral families. M1 specimens leave them
unset: their declaration is the whole payload.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Echoed back to the client when it does not name one.
FALLBACK_PROTOCOL_VERSION = "2025-06-18"


@dataclass
class Specimen:
    """One specimen's advertised surface plus optional runtime behavior."""

    server_name: str
    server_version: str = "1.0.0"
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)

    # Called once before serving. M3 behavioral specimens use this; M1 leaves it None.
    on_start: Callable[[], None] | None = None

    # Called with the client's `initialize` params, returning the tool list to advertise.
    # Lets a scanner-aware specimen (M3/R14) vary its catalog by client identity.
    tools_for_client: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None


def _respond(request_id: Any, result: dict[str, Any]) -> None:
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n"
    )
    sys.stdout.flush()


def _error(request_id: Any, code: int, message: str) -> None:
    sys.stdout.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
        )
        + "\n"
    )
    sys.stdout.flush()


def run(specimen: Specimen) -> None:
    """Serve MCP over stdio until stdin closes."""
    if specimen.on_start is not None:
        specimen.on_start()

    client_params: dict[str, Any] = {}

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = message.get("method")
        request_id = message.get("id")

        # Notifications carry no id and take no response.
        if request_id is None:
            continue

        if method == "initialize":
            client_params = message.get("params", {}) or {}
            _respond(
                request_id,
                {
                    "protocolVersion": client_params.get(
                        "protocolVersion", FALLBACK_PROTOCOL_VERSION
                    ),
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {
                        "name": specimen.server_name,
                        "version": specimen.server_version,
                    },
                },
            )
        elif method == "tools/list":
            tools = (
                specimen.tools_for_client(client_params)
                if specimen.tools_for_client is not None
                else specimen.tools
            )
            _respond(request_id, {"tools": tools})
        elif method == "resources/list":
            _respond(request_id, {"resources": specimen.resources})
        elif method == "resources/templates/list":
            _respond(request_id, {"resourceTemplates": []})
        elif method == "prompts/list":
            _respond(request_id, {"prompts": specimen.prompts})
        elif method == "ping":
            _respond(request_id, {})
        else:
            _error(request_id, -32601, f"method not found: {method}")
