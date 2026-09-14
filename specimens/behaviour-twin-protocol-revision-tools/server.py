"""A document server that withholds a tool the older protocol revision cannot carry.

`open_document` answers with a resource link plus structured content. Resource links in tool
results, and the `structuredContent` field that carries the typed payload alongside them,
arrived in the 2025-06-18 revision. A client that negotiated an earlier revision has no
place to put either: it would receive a result whose interesting half its parser does not
know about, and the tool would appear to return an empty document.

Advertising a tool whose result the client cannot read is worse than not advertising it, so
this server does not. Older clients are told, in the description of the tool they do get,
that the full-text path exists and what to upgrade to in order to reach it — the capability
is withheld, not hidden.

This is the false-positive control for the protocol-pin discriminator: identical mechanism —
branch on the caller's declared `protocolVersion`, serve a different catalog — and the
opposite intent. What differs is which direction the withheld thing points. Here the client
that declares less gets fewer tools because fewer are usable by it. In the malicious sibling
the client that declares less gets fewer tools because it is the one doing the looking.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

# Resource links and structuredContent in tool results landed in this revision.
_STRUCTURED_RESULTS_REVISION = "2025-06-18"

_SEARCH_MODERN = {
    "name": "search_documents",
    "description": (
        "Search the document library and return matching documents with titles and excerpts."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
        "required": ["query"],
    },
}

_SEARCH_LEGACY = {
    "name": "search_documents",
    "description": (
        "Search the document library and return matching documents with titles and excerpts. "
        "Full-document retrieval is served by `open_document`, which returns a resource link "
        "and structured content; those result fields are only available from protocol "
        "revision 2025-06-18, so the tool is not offered on this connection."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
        "required": ["query"],
    },
}

_OPEN = {
    "name": "open_document",
    "description": (
        "Open one document by id. Returns a resource link to the stored file together with "
        "structured content holding the parsed sections, so the client can render either."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"document_id": {"type": "string"}},
        "required": ["document_id"],
    },
}


def _can_read_structured_results(client_params: dict) -> bool:
    """Did the caller negotiate a revision whose result schema has somewhere to put this?

    Dated revision strings compare lexicographically. A caller that declares nothing is
    treated as legacy, which is the safe direction: withholding a tool costs the caller one
    feature, while advertising one whose result it cannot parse costs it a confusing failure
    at call time.
    """
    declared = client_params.get("protocolVersion")
    if not isinstance(declared, str) or not declared:
        return False
    return declared >= _STRUCTURED_RESULTS_REVISION


def _tools(client_params: dict) -> list[dict]:
    if _can_read_structured_results(client_params):
        return [_SEARCH_MODERN, _OPEN]
    return [_SEARCH_LEGACY]


run(
    Specimen(
        server_name="document-library",
        server_version="3.0.1",
        tools_for_client=_tools,
    )
)
