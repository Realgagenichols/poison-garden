"""Serves a different tool depending on the protocol revision the client speaks.

MCP is versioned, and structured tool output is a feature of the later revisions. A server
that has both a structured and a text-only implementation of the same operation has exactly
two honest options: advertise the structured one to everybody and break older clients, or
advertise the one the client can actually consume. Picking the second is the reason
`protocolVersion` is in the `initialize` params at all.

So this server's catalog is a function of the client. `get_changelog` is always present and
never changes. Alongside it, a client on 2025-06-18 or later is offered
`get_changelog_structured`, and an older client is offered `get_changelog_text` instead.

The false-positive this controls for: the catalog is genuinely not a constant. Two scans
run by two different clients get two different catalogs, and a detector that concludes
"this server's tool list depends on who is asking, therefore rug-pull" flags it. What the
catalog does not depend on is position within a session — enumerate a hundred times on one
connection and the bytes never move — which is the property the malicious class actually
has and this one does not.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import enumeration_count  # noqa: E402

# Revisions are dated `YYYY-MM-DD`, so ordering them is a string comparison.
_STRUCTURED_OUTPUT_SINCE = "2025-06-18"

_GET_CHANGELOG = {
    "name": "get_changelog",
    "description": "Return the changelog entry for a release tag as Markdown.",
    "inputSchema": {
        "type": "object",
        "properties": {"release": {"type": "string", "description": "Release tag."}},
        "required": ["release"],
    },
}

_STRUCTURED = {
    "name": "get_changelog_structured",
    "description": (
        "Return a changelog entry as structured content — one object per change, with "
        "`kind`, `summary` and `pull_request`. Offered only to clients that negotiated "
        "protocol 2025-06-18 or later, since earlier revisions cannot carry structured "
        "tool output; those clients get `get_changelog_text` instead."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"release": {"type": "string", "description": "Release tag."}},
        "required": ["release"],
    },
}

_LEGACY_TEXT = {
    "name": "get_changelog_text",
    "description": (
        "Return a changelog entry as pre-rendered plain text. The compatibility path for "
        "clients on protocol revisions before 2025-06-18; newer clients should prefer "
        "`get_changelog_structured`."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"release": {"type": "string", "description": "Release tag."}},
        "required": ["release"],
    },
}


def _tools(client_params: dict) -> list[dict]:
    """Branch on the negotiated protocol revision, and on nothing else.

    `enumeration_count()` is called and its value discarded, exactly as in the shipped
    stable-namesakes twin: a control for a rug-pull has to be a server that could vary
    across a session and demonstrably does not.
    """
    enumeration_count()
    version = client_params.get("protocolVersion")
    if isinstance(version, str) and version >= _STRUCTURED_OUTPUT_SINCE:
        return [_GET_CHANGELOG, _STRUCTURED]
    return [_GET_CHANGELOG, _LEGACY_TEXT]


run(
    Specimen(
        server_name="changelog-service-oss",
        server_version="1.4.0",
        tools_for_client=_tools,
    )
)
