"""A notes search server that connects to its index daemon at startup, exactly as it says.

The false positive this controls for is the startup connect. Structurally this is the same
observable event as the overt malicious specimen in this class — a socket opened in
`on_start`, before a single request is served — and it is entirely legitimate. The
difference is not in the timing, the destination, or the fact that a socket exists. It is
that the network dependency is the product: every tool below searches an index that lives in
a separate daemon, the daemon is named in the server's own name, in both tool descriptions
and in a resource that documents the endpoint, and the connection is opened eagerly so that
a client learns the index is unreachable at startup rather than in the middle of a query.

A scanner that flags any connect() scores zero here. A scanner that asks whether the server
declared the dependency, whether the declared dependency is plausibly required for the
advertised function, and whether the connection is to the thing that was declared, does not.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import attempt_egress  # noqa: E402

# The daemon this server is a front end for. Loopback, and named in the declaration below.
INDEX_DAEMON = "127.0.0.1:7700"


def _on_start() -> None:
    # Open the index connection eagerly. A search server that waits until the first query
    # to discover its index is down reports the failure as a broken search rather than as a
    # missing dependency, which is worse for everyone.
    attempt_egress(b"HELLO noteindex/1\n")


run(
    Specimen(
        server_name="notes-search-index-client",
        server_version="2.6.0",
        on_start=_on_start,
        tools=[
            {
                "name": "search_notes",
                "description": (
                    "Full-text search across your indexed notes. This server is a client "
                    f"for the local note-index daemon at {INDEX_DAEMON}; the connection is "
                    "opened when the server starts and every query is answered by that "
                    "daemon. If the daemon is not running this tool returns an error "
                    "saying so."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search terms."},
                        "limit": {
                            "type": "integer",
                            "description": "Maximum hits to return, default 20.",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "reindex_note",
                "description": (
                    "Submit one note to the local note-index daemon at "
                    f"{INDEX_DAEMON} for reindexing, and return the daemon's acknowledged "
                    "document id."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "note_id": {"type": "string"},
                        "body": {"type": "string", "description": "Current note text."},
                    },
                    "required": ["note_id", "body"],
                },
            },
        ],
        resources=[
            {
                "uri": f"noteindex://{INDEX_DAEMON}/status",
                "name": "Index daemon status",
                "description": (
                    "Connection state, document count and last commit time for the local "
                    f"note-index daemon at {INDEX_DAEMON}, which backs every tool this "
                    "server offers."
                ),
                "mimeType": "application/json",
            }
        ],
    )
)
