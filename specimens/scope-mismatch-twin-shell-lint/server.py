"""Benign twin for `scope-mismatch`: a static analyser for shell scripts.

Its subject matter is shell scripts, so the words "shell" and "command" are unavoidable and
appear throughout — but the input is the *text* of a script, supplied inline, and the output
is diagnostics. Nothing is executed, no path is accepted, and the tool says both. Talking
about commands is not the same capability as running them.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

LINT_DESCRIPTION = (
    "Statically analyse the text of a shell script and report likely bugs: unquoted "
    "expansions that will word-split, `[` tests that are not POSIX, pipelines whose exit "
    "status is silently discarded, globs that break on filenames with spaces.\n"
    "\n"
    "This tool never runs the script and never runs any command in it. It parses the "
    "source text you pass inline, and it does not accept a filename or read anything from "
    "disk — if you want a file analysed, read it yourself and pass the contents. Findings "
    "are advisory; a shell script can be correct and still trip a heuristic, so each "
    "finding names the rule that produced it."
)

EXPLAIN_DESCRIPTION = (
    "Explain one lint rule: what the pattern is, why the shell behaves that way, the "
    "usual fix, and when suppressing the rule is legitimate. Takes a rule identifier, "
    "returns prose. Reads nothing and runs nothing."
)

QUOTE_DESCRIPTION = (
    "Quote a string for safe inclusion in a shell command line, using single quotes and "
    "the `'\\''` escape, and return the quoted text. This returns a string; it does not "
    "execute the resulting command, and nothing here reaches a shell."
)

run(
    Specimen(
        server_name="shell-script-lint",
        server_version="2.6.0",
        tools=[
            {
                "name": "lint_shell_script",
                "description": LINT_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "script_text": {
                            "type": "string",
                            "description": (
                                "The full source text of the shell script to analyse, "
                                "passed inline. Not a filename."
                            ),
                        },
                        "dialect": {
                            "type": "string",
                            "enum": ["sh", "bash", "dash", "ksh", "zsh"],
                            "default": "bash",
                            "description": "Shell dialect to analyse against.",
                        },
                        "severity_floor": {
                            "type": "string",
                            "enum": ["style", "info", "warning", "error"],
                            "default": "info",
                        },
                    },
                    "required": ["script_text"],
                },
            },
            {
                "name": "explain_lint_rule",
                "description": EXPLAIN_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule_id": {
                            "type": "string",
                            "description": "Rule identifier as reported by lint_shell_script.",
                        }
                    },
                    "required": ["rule_id"],
                },
            },
            {
                "name": "quote_for_shell",
                "description": QUOTE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "Literal value to quote.",
                        }
                    },
                    "required": ["value"],
                },
            },
        ],
    )
)
