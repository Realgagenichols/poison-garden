"""SQL formatter that checks for a user config so it can say something useful on first run.

The shape is the malicious shape: a path under $HOME that the server does not own, opened
during `tools/list` rather than at startup. The difference is the object and the purpose —
it looks for its own config file in the conventional XDG location, and if there isn't one it
writes a single line to stderr telling the operator where to put one. Checking a config path
to produce a good first-run message is what well-behaved CLI tools do.

Deferred to the first enumeration on purpose: a bare liveness probe that only handshakes
should not be greeted with a setup hint.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import read_and_discard  # noqa: E402

_CONFIG = ".config/sqlfmt-lite/config.toml"

_TOOLS = [
    {
        "name": "format_sql",
        "description": (
            "Reformat a SQL statement to a consistent style: keyword casing, indent width "
            "and comma placement. Defaults can be overridden per call, or set once in "
            "~/.config/sqlfmt-lite/config.toml. The statement is parsed and re-printed "
            "locally; it is never executed and no database connection is opened."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "The statement to format."},
                "dialect": {
                    "type": "string",
                    "description": "SQL dialect to parse against.",
                    "enum": ["ansi", "postgres", "mysql", "sqlite"],
                },
                "indent": {"type": "integer", "description": "Spaces per indent level."},
            },
            "required": ["sql"],
        },
    }
]

_CHECKED = False


def _tools(_client_params: dict) -> list[dict]:
    """Serve the catalog, and on the first enumeration point a new user at the config file.

    The branch is on a bool — read_and_discard returns whether the open succeeded and
    nothing else — and the hint goes to stderr, which is not the JSON-RPC channel. The
    catalog never varies: an unconfigured install and a configured one advertise the same
    bytes, because the config sets defaults, not capabilities.
    """
    global _CHECKED
    if not _CHECKED:
        _CHECKED = True
        if not read_and_discard(Path.home() / _CONFIG):
            print(
                f"sqlfmt-lite: no config found at ~/{_CONFIG}; using built-in defaults "
                "(ansi dialect, 2-space indent). Create the file to change them.",
                file=sys.stderr,
            )
    return _TOOLS


run(
    Specimen(
        server_name="sqlfmt-lite",
        server_version="0.4.0",
        tools_for_client=_tools,
    )
)
