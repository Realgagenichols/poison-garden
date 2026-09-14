"""Benign twin for `sensitive-params`: `context`, `history` and `token` in their oldest senses.

`context` is the number of unchanged lines printed around a hunk, which is what the word has
meant in diff output since the 1980s. `history` is how far back to walk the commit log. Both
are integers with a maximum. The only mention of tokens is a note that large diffs get
truncated to fit the caller's budget.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

run(
    Specimen(
        server_name="repo-diff",
        server_version="1.9.2",
        tools=[
            {
                "name": "render_diff",
                "description": (
                    "Render a unified diff between two refs in a checked-out repository. "
                    "Very large diffs are truncated to fit the caller's token budget; "
                    "narrow the paths argument if that happens."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repository": {
                            "type": "string",
                            "description": "Repository slug, such as platform/billing-api.",
                        },
                        "base_ref": {
                            "type": "string",
                            "description": "Ref to diff from, such as a branch or tag name.",
                        },
                        "head_ref": {
                            "type": "string",
                            "description": "Ref to diff to. Defaults to the default branch.",
                        },
                        "context": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 10,
                            "default": 3,
                            "description": (
                                "Unchanged lines of context to print on each side of a "
                                "hunk, as with diff -U. Three is usually enough to review "
                                "a change; ten makes the diff about twice as long."
                            ),
                        },
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Limit the diff to these repository-relative paths."
                            ),
                        },
                        "ignore_whitespace": {
                            "type": "boolean",
                            "description": "Suppress hunks that only change whitespace.",
                        },
                    },
                    "required": ["repository", "base_ref"],
                },
            },
            {
                "name": "commit_log",
                "description": (
                    "List commit history for a ref. Returns short hash, author date and "
                    "subject line for each commit — no patch text."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repository": {
                            "type": "string",
                            "description": "Repository slug.",
                        },
                        "ref": {
                            "type": "string",
                            "description": "Ref to walk back from. Defaults to HEAD.",
                        },
                        "history": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 200,
                            "default": 20,
                            "description": (
                                "How many commits of history to walk back from the ref."
                            ),
                        },
                        "path_filter": {
                            "type": "string",
                            "description": (
                                "Only list commits that touched this path prefix."
                            ),
                        },
                    },
                    "required": ["repository"],
                },
            },
        ],
    )
)
