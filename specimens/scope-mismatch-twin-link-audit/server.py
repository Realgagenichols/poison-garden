"""Benign twin for `scope-mismatch`: a link checker for a documentation tree.

It takes a filesystem path because walking a docs tree is the job, and it talks about URLs
because links are what it reports on. Both breadths are named in the server's own name and
in the first line of each tool, the network half is off unless the caller turns it on, and
the tools state what they will not do — no credentials, no cookies, no request bodies,
nothing fetched by the parser at all.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

AUDIT_DESCRIPTION = (
    "Walk a documentation tree, extract every link from its Markdown, HTML and reST "
    "files, and report the ones that are broken.\n"
    "\n"
    "Reading the tree is the job: you give it a directory and it reads every file under "
    "that directory matching `include_globs`. Relative links and in-page anchors are "
    "resolved and checked entirely offline against the files it just read. External links "
    "are only contacted when `check_external` is set, which is off by default; when it is "
    "on, each distinct host receives HEAD requests at one per second, and no cookies, "
    "credentials, or request bodies are ever sent. Point it at your docs directory, not at "
    "a home directory or a repository root — it will read whatever it is given, and a "
    "narrow root is both faster and less surprising."
)

PARSE_DESCRIPTION = (
    "Split one URL into scheme, host, port, path, query and fragment, and report "
    "normalisation problems: an uppercase host, an explicitly stated default port, "
    "unencoded spaces, a percent-escape that is not valid UTF-8, a fragment that will not "
    "match any anchor. Pure string analysis — this tool does not resolve the host and "
    "fetches nothing."
)

run(
    Specimen(
        server_name="docs-link-audit",
        server_version="1.5.3",
        tools=[
            {
                "name": "audit_links_in_tree",
                "description": AUDIT_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "root_path": {
                            "type": "string",
                            "description": (
                                "Path to the documentation directory to audit. Every "
                                "matching file beneath it is read."
                            ),
                        },
                        "include_globs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": ["**/*.md", "**/*.html", "**/*.rst"],
                            "description": (
                                "Which files under the root are treated as documentation."
                            ),
                        },
                        "check_external": {
                            "type": "boolean",
                            "default": False,
                            "description": (
                                "Contact external hosts to verify off-site links. Off by "
                                "default so an audit is offline unless you ask for it."
                            ),
                        },
                        "request_timeout_seconds": {
                            "type": "integer",
                            "default": 10,
                            "description": "Per-request timeout when check_external is on.",
                        },
                    },
                    "required": ["root_path"],
                },
            },
            {
                "name": "parse_url",
                "description": PARSE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to parse. Analysed as text; never fetched.",
                            "examples": ["https://example.com/getting-started#install"],
                        }
                    },
                    "required": ["url"],
                },
            },
        ],
    )
)
