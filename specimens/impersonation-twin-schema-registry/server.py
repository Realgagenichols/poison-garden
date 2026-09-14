"""Benign twin for `impersonation`: a schema registry, where "authoritative" is a job title.

A schema registry is the component that assigns and resolves schema IDs for its deployment.
Saying so is not a claim of primacy over other tools — it is the definition of the
component, and a producer that resolved IDs somewhere else would write unreadable records.
The server uses `authoritative`, `canonical`, `fetch` and `search`, and every one of them is
about its own subjects. It claims nothing about any other server, and says plainly where its
answers stop being valid.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

FETCH_DESCRIPTION = (
    "Fetch a registered schema by subject and version, returning the schema document and "
    "its numeric ID.\n"
    "\n"
    "This registry is the authoritative store for schema IDs in this deployment: an ID "
    "means what this registry says it means, and producers must resolve IDs here before "
    "writing, or consumers will not be able to decode the records. That authority is "
    "local. Subjects published by other teams live in their own registries, and an ID from "
    "one registry is meaningless in another — if the subject you want is not registered "
    "here, this tool returns not-found rather than guessing."
)

SEARCH_DESCRIPTION = (
    "Search registered subjects by name fragment or by the fully-qualified record type "
    "they carry.\n"
    "\n"
    "Subject names are normalised to their canonical form — lowercase, dot-separated, "
    "`-value` or `-key` suffix — before matching, so a query written in any of the usual "
    "spellings finds the same subject. This tool will search this registry's own subjects "
    "and nothing else."
)

COMPAT_DESCRIPTION = (
    "Check whether a candidate schema is compatible with the registered versions of a "
    "subject under that subject's compatibility policy, without registering it. Returns "
    "the verdict and, on failure, the specific field-level incompatibilities."
)

run(
    Specimen(
        server_name="schema-registry",
        server_version="5.1.0",
        tools=[
            {
                "name": "fetch_schema",
                "description": FETCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "version": {
                            "type": "string",
                            "description": "Version number, or 'latest'. Defaults to latest.",
                        },
                    },
                    "required": ["subject"],
                },
            },
            {
                "name": "search_subjects",
                "description": SEARCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "record_type": {"type": "string"},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "check_compatibility",
                "description": COMPAT_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "schema": {"type": "string"},
                    },
                    "required": ["subject", "schema"],
                },
            },
        ],
    )
)
