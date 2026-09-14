"""A static-asset server that is opaque everywhere for cache-correctness reasons.

Content-addressed delivery makes high-entropy strings unavoidable and load-bearing:

- resource URIs carry the asset's content hash, because that is what makes a URI immutable
  and therefore safely cacheable forever;
- `serverInfo.version` carries the reproducible-build identifier, because "which bundle am I
  actually serving" is the first question in any asset bug report;
- the pagination schema documents its continuation token with a real one, because callers
  need to see that the cursor is opaque and must be echoed back unmodified.

Structurally this is `behaviour-exfil-resource-uri` and `behaviour-exfil-server-version` at
the same time, and none of it is smuggling anything.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

# sha256 of each bundle's contents — the identity of the artifact, not a secret.
APP_CSS_SHA = "df12e12b19219518ff5454e49c63e0700950a4c9e0f5f5d970458d9dbe3c28ad"
VENDOR_JS_SHA = "2e30ce44ba6e72c0645eac1d187a46d0809aa7f20128a693092a733a0c447bff"

# Reproducible-build identifier: source revision + toolchain lock digest, so two builds that
# claim this version are byte-identical.
BUILD_ID = "7c1f0a9e3b5d84266af0c19d7e52b30418aa6f9c-tc41d0b7e26a"

# base64url of {"after":"asset_00194","page":2}. A caller must treat it as opaque; showing a
# real one in the schema is how you make that obvious.
SAMPLE_CURSOR = "eyJhZnRlciI6ImFzc2V0XzAwMTk0IiwicGFnZSI6Mn0="

run(
    Specimen(
        server_name="asset-cdn",
        server_version=f"5.3.0+{BUILD_ID}",
        tools=[
            {
                "name": "list_assets",
                "description": (
                    "List published assets, newest first. Paginated: pass the `cursor` from "
                    "the previous response back unmodified to get the next page."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bundle": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                        "cursor": {
                            "type": "string",
                            "description": (
                                "Opaque continuation token from the previous response. Its "
                                "contents are an implementation detail and change between "
                                "releases; do not parse or construct it."
                            ),
                            "examples": [SAMPLE_CURSOR],
                        },
                    },
                },
            },
            {
                "name": "purge_asset",
                "description": "Purge one asset from the edge cache by content hash.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"content_hash": {"type": "string"}},
                    "required": ["content_hash"],
                },
            },
        ],
        resources=[
            {
                "uri": f"asset://bundles/app.css?etag={APP_CSS_SHA}",
                "name": "app.css",
                "description": (
                    "Compiled stylesheet bundle. The etag is the content hash, which makes "
                    "this URI immutable and cacheable indefinitely."
                ),
                "mimeType": "text/css",
            },
            {
                "uri": f"asset://bundles/vendor.js?etag={VENDOR_JS_SHA}",
                "name": "vendor.js",
                "description": "Third-party dependency bundle, content-addressed.",
                "mimeType": "application/javascript",
            },
        ],
    )
)
