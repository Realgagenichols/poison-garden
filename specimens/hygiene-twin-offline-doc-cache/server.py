"""Benign twin for `hygiene`: an air-gapped documentation reader.

It talks constantly about fetching, about a URL, and about versions — and every one of
those is local. The "fetch" is a read from a snapshot on disk, the URL is this process's
own loopback admin endpoint, and the version is the frozen upstream release the snapshot
was built from, disclosed so nobody mistakes it for current. The snapshot's digest is
verified against the shipped manifest before anything is served.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_HERE = Path(__file__).resolve().parent
_MANIFEST = json.loads((_HERE / "cache-manifest.json").read_text(encoding="utf-8"))

PROVENANCE = (
    f"Snapshot {_MANIFEST['snapshot_id']} ({_MANIFEST['entry_count']} pages), built from "
    f"upstream release {_MANIFEST['source_release']} on {_MANIFEST['built_at']}. Its "
    f"sha256 is {_MANIFEST['sha256']}, verified against the shipped `cache-manifest.json` "
    f"at start-up (`verify_on_start: {_MANIFEST['verify_on_start']}`); a snapshot whose "
    "digest does not match is refused and nothing is served."
)

OFFLINE = (
    "This server has no network access. Every read is satisfied from the snapshot on "
    "disk, so it is deliberately not the latest upstream documentation — it is the "
    f"release {_MANIFEST['source_release']} text, frozen. Re-snapshotting is a separate, "
    "operator-run process that this server cannot trigger."
)

FETCH_DESCRIPTION = (
    "Fetch a documentation page from the offline snapshot by its path.\n"
    "\n"
    "Returns the page as Markdown with its heading anchors. A path that is absent from "
    "the snapshot returns not-found rather than falling back to anything else.\n"
    "\n"
    f"{OFFLINE}\n"
    "\n"
    f"{PROVENANCE}"
)

SEARCH_DESCRIPTION = (
    "Search the offline snapshot's full-text index and return matching page paths with a "
    "short excerpt each, ranked by score.\n"
    "\n"
    f"{OFFLINE}"
)

STATUS_DESCRIPTION = (
    "Report the cache's provenance: snapshot id, sha256, the upstream release version it "
    "was built from, the build date and the page count.\n"
    "\n"
    f"Live cache statistics — hit rate, index size, last verification — are served by this "
    f"process on loopback at {_MANIFEST['admin_endpoint']}, reachable only from the host "
    "running the server.\n"
    "\n"
    f"{PROVENANCE}"
)

run(
    Specimen(
        server_name="docs-cache",
        server_version="1.14.3",
        tools=[
            {
                "name": "fetch_cached_page",
                "description": FETCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Page path within the snapshot, e.g. guide/install.",
                        }
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "search_cached_docs",
                "description": SEARCH_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "default": 10},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "snapshot_status",
                "description": STATUS_DESCRIPTION,
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
        resources=[
            {
                "uri": "docs-cache://cache-manifest.json",
                "name": "cache-manifest.json",
                "description": (
                    "Provenance of the offline snapshot: id, digest, upstream release "
                    "version and build date, exactly as shipped."
                ),
                "mimeType": "application/json",
            }
        ],
    )
)
