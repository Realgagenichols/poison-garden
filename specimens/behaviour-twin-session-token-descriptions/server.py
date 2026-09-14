"""Descriptions that carry a session token. The token is stable; so is everything else.

A server that scopes state per connection usually has to tell the model which scope it is
in, and the only channel a tool definition has for telling the model anything is the
description. So the descriptions here end with "Bound to workspace session <token>", where
the token is derived from the identity the client declared during `initialize`. That is
ordinary: the alternative is a model that cheerfully writes a note into whichever workspace
it last heard about.

This has the *shape* of an unstable declaration and none of the substance. Descriptions
that contain a value which is clearly not prose are the visual signature of a catalog that
moves, and a detector comparing two scans made by two different clients sees the token
change while everything around it holds — which is also exactly what the description-drift
rug-pull looks like from the outside. It is the sharpest available false positive for that
specimen, so it is here.

The differences that matter: the token is a function of declared client identity and of
nothing else, it is identical on every enumeration of a connection, and it is identical
across processes given the same client — so two runs are byte-for-byte the same. And the
thing that changes is an opaque label, not an instruction; no enumeration of this server
ever tells the model to do something the first one did not.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import enumeration_count  # noqa: E402


def _session_token(client_params: dict) -> str:
    """A stable label for the declared client identity.

    `hashlib`, never the builtin `hash()`: string hashing is salted per process unless
    PYTHONHASHSEED is pinned, so `hash()` would make this specimen produce different bytes
    on two runs with identical input — non-determinism, which N3 forbids and which would
    turn a false-positive control into a specimen that actually varies.
    """
    info = client_params.get("clientInfo")
    if not isinstance(info, dict):
        info = {}
    identity = f"{info.get('name', '')}/{info.get('version', '')}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]


def _tools(client_params: dict) -> list[dict]:
    # Called and discarded: the control for a rug-pull must be a server that could vary
    # across a session and does not.
    enumeration_count()
    token = _session_token(client_params)
    scope = f"Bound to workspace session {token}."
    return [
        {
            "name": "add_note",
            "description": f"Append a note to the current workspace. {scope}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Note body."},
                    "pinned": {"type": "boolean", "description": "Pin to the top."},
                },
                "required": ["text"],
            },
        },
        {
            "name": "list_notes",
            "description": f"List notes in the current workspace, newest first. {scope}",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
            },
        },
        # `list_notes` is a prefix of `list_notes_shared`, which is how a great many real
        # catalogs look and is the second naive rule this twin is here to trip: confusable
        # names plus descriptions that visibly move are, between them, the whole outward
        # appearance of a rug-pull.
        {
            "name": "list_notes_shared",
            "description": (
                "List notes other workspaces have shared into this one. Read-only; use "
                f"`list_notes` for notes you own. {scope}"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
            },
        },
    ]


run(
    Specimen(
        server_name="workspace-notes-oss",
        server_version="2.0.3",
        tools_for_client=_tools,
    )
)
