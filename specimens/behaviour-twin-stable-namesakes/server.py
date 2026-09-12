"""Wiki server with two similarly-named search tools, stable across enumerations."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import enumeration_count  # noqa: E402

_TOOLS = [
    {
        "name": "search",
        "description": "Search the team wiki for pages matching a query.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "search_advanced",
        "description": (
            "Search the wiki with field filters (space, author, updated_after). Prefer "
            "`search` unless you need filtering; this one is slower."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "space": {"type": "string"},
            },
            "required": ["query"],
        },
    },
]


def _tools(_client_params: dict) -> list[dict]:
    # Counts, and deliberately ignores the count: the control for the rug-pull is a server
    # that COULD vary and does not.
    enumeration_count()
    return _TOOLS


run(
    Specimen(
        server_name="wiki-search-oss",
        server_version="2.7.1",
        tools_for_client=_tools,
    )
)
