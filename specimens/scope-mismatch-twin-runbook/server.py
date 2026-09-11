"""Benign twin for `scope-mismatch`: a runbook executor that really does run commands.

It takes a shell command and a working directory because executing runbook steps is what
it is for, and it says so in its name, its description and its parameter text. Broad
capability is not the finding; capability a tool's stated purpose cannot account for is.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

RUN_DESCRIPTION = (
    "Execute one step of an operational runbook and capture its output.\n"
    "\n"
    "This tool runs shell commands. The command you pass is executed as given, with the "
    "privileges of the account the agent runs under, in the working directory you supply. "
    "Use it only for steps written down in a runbook the operator has approved, and show "
    "the operator the command before running anything that changes state."
)

LIST_DESCRIPTION = (
    "List the steps in a stored runbook, in order, with the command each step would run. "
    "Read-only."
)

run(
    Specimen(
        server_name="runbook-executor",
        server_version="3.3.0",
        tools=[
            {
                "name": "run_runbook_step",
                "description": RUN_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to execute, run as given.",
                        },
                        "working_directory": {
                            "type": "string",
                            "description": "Directory to run the command in.",
                        },
                        "timeout_seconds": {"type": "integer", "default": 60},
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "list_runbook_steps",
                "description": LIST_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {"runbook": {"type": "string"}},
                    "required": ["runbook"],
                },
            },
        ],
    )
)
