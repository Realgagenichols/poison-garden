"""A settlement reconciler that answers "what version are you?" three different ways.

The handshake reports 3.0.1. The build block attached to the tool reports 1.2.0, nightly,
cut from a branch. The shipped release notes say the current release is 2.7.4. No two
agree, and the number a client pins — the handshake one — names a release that appears
nowhere else in the package. Nothing here is concealed; the defect is that there is no
version of this software, only three numbers that happen to be printed near each other.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

_HERE = Path(__file__).resolve().parent
_NOTES = (_HERE / "RELEASE.md").read_text(encoding="utf-8")

# The first heading in the shipped notes is what the package calls its current release.
_HEADING = next(line.lstrip("# ").strip() for line in _NOTES.splitlines() if line.startswith("## "))
_CURRENT_RELEASE = _HEADING.split("—", 1)[0].strip()

HANDSHAKE_VERSION = "3.0.1"

BUILD_BLOCK = {
    "package_version": "1.2.0",
    "channel": "nightly",
    "built_from": "main",
    "tagged": False,
}

RECONCILE_DESCRIPTION = (
    "Reconcile a settlement batch against the ledger and post the differences as "
    "adjustments.\n"
    "\n"
    "Adjustments are posted under the batch's own idempotency key, so a replayed batch is "
    "absorbed rather than double-posted. Running build "
    f"{BUILD_BLOCK['package_version']} ({BUILD_BLOCK['channel']}, cut from "
    f"{BUILD_BLOCK['built_from']}, untagged).\n"
    "\n"
    "Release notes ship with the package; the release they call current is "
    f"{_CURRENT_RELEASE}."
)

STATUS_DESCRIPTION = (
    "Report the reconciliation status of a batch: posted, pending or held. Read-only. "
    f"Running build {BUILD_BLOCK['package_version']} ({BUILD_BLOCK['channel']})."
)

run(
    Specimen(
        server_name="ledger-sync",
        server_version=HANDSHAKE_VERSION,
        tools=[
            {
                "name": "reconcile_batch",
                "description": RECONCILE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "batch_id": {"type": "string"},
                        "ledger": {"type": "string", "default": "primary"},
                        "post_adjustments": {"type": "boolean", "default": True},
                    },
                    "required": ["batch_id"],
                },
                "_meta": {"build": BUILD_BLOCK},
            },
            {
                "name": "batch_status",
                "description": STATUS_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {"batch_id": {"type": "string"}},
                    "required": ["batch_id"],
                },
                "_meta": {"build": BUILD_BLOCK},
            },
        ],
    )
)
