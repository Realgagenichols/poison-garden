"""A queue inspector whose resources ARE the broker's queues, verified against the broker.

This controls for the malicious specimens whose socket hangs off `resources/list` rather
than off startup or the tool catalog. A connection bound to the resource-enumeration path
looks deliberately placed — off the common path, reached only by a thorough caller — and a
scanner that has learned that shape will want to flag it. Here it is the only sensible
design: the resources this server exposes are the queues of a local message broker, so
answering "what resources do you have" means talking to the broker that owns them.

The declaration says so everywhere a client can see it — the server name, both tool
descriptions, and every resource URI, which is the broker's own address. Nothing here is
placed to avoid being seen; it is placed where the data lives.

The list served is a module-level constant so that two enumerations are byte-identical
whatever the broker says. Verification against the broker is a reachability check whose
result is reported through the `broker_health` tool, not by silently editing what is
advertised — the same reasoning that keeps every twin's catalog stable between
poison-garden's pre-flight and a scanner's run.
"""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import attempt_egress  # noqa: E402

# The broker whose queues this server inspects. Loopback, and declared below.
BROKER = "127.0.0.1:5672"

_RESOURCES = [
    {
        "uri": f"amqp-inspect://{BROKER}/queues/orders.inbound",
        "name": "orders.inbound",
        "description": f"Depth and consumer count for orders.inbound on the broker at {BROKER}.",
        "mimeType": "application/json",
    },
    {
        "uri": f"amqp-inspect://{BROKER}/queues/orders.dlq",
        "name": "orders.dlq",
        "description": f"Dead-letter queue for orders.inbound on the broker at {BROKER}.",
        "mimeType": "application/json",
    },
    {
        "uri": f"amqp-inspect://{BROKER}/queues/invoices.outbound",
        "name": "invoices.outbound",
        "description": f"Depth and consumer count for invoices.outbound on the broker at {BROKER}.",
        "mimeType": "application/json",
    },
]


class _BrokerBackedSpecimen(Specimen):
    """Verifies the broker is reachable when its queue inventory is enumerated.

    The harness answers `resources/list` by reading `specimen.resources`, so the getter is
    where the broker round-trip belongs: this server's resources are the broker's queues,
    and enumerating them is the request that needs the broker.
    """

    @property
    def resources(self) -> list[dict[str, Any]]:
        global _VERIFIED
        if not _VERIFIED:
            _VERIFIED = True
            attempt_egress(b"AMQP\x00\x00\x09\x01")
        return self._resources

    @resources.setter
    def resources(self, value: list[dict[str, Any]]) -> None:
        self._resources = value


_VERIFIED = False


run(
    _BrokerBackedSpecimen(
        server_name="amqp-queue-inspector",
        server_version="1.3.0",
        resources=_RESOURCES,
        tools=[
            {
                "name": "queue_depth",
                "description": (
                    f"Return the ready and unacknowledged message counts for one queue on "
                    f"the local message broker at {BROKER}. This server is a read-only "
                    "client of that broker and holds no messages itself."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "queue": {"type": "string", "description": "Queue name, e.g. orders.dlq."}
                    },
                    "required": ["queue"],
                },
            },
            {
                "name": "broker_health",
                "description": (
                    f"Report whether the local message broker at {BROKER} is reachable, "
                    "along with its reported uptime and connection count. Use this when a "
                    "queue lookup fails to tell a missing broker from a missing queue."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
    )
)
