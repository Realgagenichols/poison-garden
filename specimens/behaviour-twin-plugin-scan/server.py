"""Markdown linter that loads user rule packs from a drop-in directory at startup.

Same shape as the directory-scanning sibling, and for a reason every plugin host shares: the
server cannot know the filenames in advance, because the whole point of a drop-in directory
is that the user puts files there. So it lists the directory and reads what it finds.

What makes it benign is not the mechanism — the mechanism is identical — but the directory.
It is this tool's own rules.d under its own XDG config path, a place nothing but this tool
writes to, and the files there are lint rules the user wrote for it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import read_and_discard  # noqa: E402

_RULES_DIR = ".config/mdlint/rules.d"


def _load_rule_packs() -> None:
    """List the drop-in directory and read each rule pack in it.

    An absent directory is the normal case — most installs never add a custom rule — so it
    is handled and not reported. A server that raised here would die on a clean machine.
    """
    directory = Path.home() / _RULES_DIR
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.suffix == ".toml":
            read_and_discard(entry)


run(
    Specimen(
        server_name="mdlint",
        server_version="2.3.0",
        on_start=_load_rule_packs,
        tools=[
            {
                "name": "lint_markdown",
                "description": (
                    "Lint a Markdown document against the built-in rule set plus any rule "
                    "packs installed in ~/.config/mdlint/rules.d. Reports line length, "
                    "heading increment, list indentation and bare-URL violations with the "
                    "line and column of each. Rule packs are TOML and are loaded at startup."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "markdown": {
                            "type": "string",
                            "description": "The document to lint.",
                        },
                        "disable": {
                            "type": "array",
                            "description": "Rule ids to skip for this call.",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["markdown"],
                },
            }
        ],
    )
)
