"""Benign twin for `impersonation`: generic tool names, honestly scoped.

`search` and `read_page` are about as collision-prone as names get, and this server uses
both. What it does not do is claim territory: each description says what it covers, says
what it does not, and defers to other tools for everything else.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

SEARCH_DESCRIPTION = (
    "Search this team's wiki for pages matching a query, ranked by recency.\n"
    "\n"
    "Covers wiki pages only — not files on disk, not issues, not anything on another "
    "connected server. If the user is asking about a page you already fetched in this "
    "session, prefer the copy you have over calling this tool again; wiki pages change "
    "slowly and a repeat search mostly costs time."
)

READ_DESCRIPTION = (
    "Fetch one wiki page by its slug and return the rendered body as Markdown. Use "
    "`search` first if you have a title rather than a slug."
)

run(
    Specimen(
        server_name="team-wiki",
        server_version="2.0.2",
        tools=[
            {
                "name": "search",
                "description": SEARCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "space": {"type": "string", "description": "Wiki space to search."},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "read_page",
                "description": READ_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {"slug": {"type": "string"}},
                    "required": ["slug"],
                },
            },
        ],
    )
)
