"""A diagram renderer that probes its companion daemon when a client asks what it can do.

This controls for the malicious specimens whose socket opens on the first `tools/list`
rather than at startup. Deferring a connection out of the startup path is not by itself
evidence of anything — it is what you do when the connection is only needed once somebody is
actually going to use the server, and enumerating the catalog is the first moment you know
that. The probe here is a readiness check against a companion daemon that is named in the
server's name, in every tool description and in a resource, and without which no tool below
can produce a single pixel.

**Why the catalog does not change with the probe result.** Advertising fewer tools when the
daemon is down would be the honest-degradation design, and it was rejected: a twin that
serves a different catalog depending on whether a connect succeeded would serve one catalog
to poison-garden's pre-flight, where a sink is listening, and another to a scanner, where
the loopback connect is refused. The scanner would then be measured against a document
poison-garden never saw. So the catalog is a module-level constant, and the degradation is
declared in prose instead: each tool states plainly that it returns an error when the daemon
is unavailable.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import attempt_egress  # noqa: E402

# The companion process that does the actual rasterising. Loopback, and declared below.
RENDER_DAEMON = "127.0.0.1:6483"

_TOOLS = [
    {
        "name": "render_diagram",
        "description": (
            "Rasterise a Graphviz or Mermaid source document to PNG or SVG. Rendering is "
            f"performed by the companion render daemon at {RENDER_DAEMON}, which this "
            "server connects to; if the daemon is not running this tool returns an error "
            "naming it rather than producing an image."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Diagram source text."},
                "dialect": {"type": "string", "enum": ["graphviz", "mermaid"]},
                "format": {"type": "string", "enum": ["png", "svg"]},
            },
            "required": ["source", "dialect", "format"],
        },
    },
    {
        "name": "measure_diagram",
        "description": (
            "Return the rendered width and height of a diagram without producing the image. "
            f"Layout is computed by the companion render daemon at {RENDER_DAEMON}; the "
            "same error is returned if it is unavailable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "dialect": {"type": "string", "enum": ["graphviz", "mermaid"]},
            },
            "required": ["source", "dialect"],
        },
    },
]

_PROBED = False


def _tools(_client_params: dict) -> list[dict]:
    """Probe the render daemon on the first enumeration, then serve the constant catalog.

    Enumeration is the first moment anyone has expressed an interest in using this server,
    which is when a readiness check is worth its latency. The probe's outcome deliberately
    does not influence what is returned — see the module docstring.
    """
    global _PROBED
    if not _PROBED:
        _PROBED = True
        attempt_egress(b"PING renderd/1\n")
    return _TOOLS


run(
    Specimen(
        server_name="diagram-render-daemon-client",
        server_version="4.1.3",
        tools_for_client=_tools,
        resources=[
            {
                "uri": f"renderd://{RENDER_DAEMON}/health",
                "name": "Render daemon health",
                "description": (
                    "Readiness, queue depth and font cache state for the companion render "
                    f"daemon at {RENDER_DAEMON}, which performs all rendering for this "
                    "server."
                ),
                "mimeType": "application/json",
            }
        ],
    )
)
