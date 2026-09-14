"""Egress observability — the `egress` class and its loopback fallback.

The class shipped with zero specimens for three releases, and the reason was structural
rather than an oversight: `attempt_egress` returned early when `PG_EGRESS_SINK` was absent,
and that variable is set by poison-garden's pre-flight and absent when a scanner spawns the
specimen. So an egress specimen performed no observable act during the only invocation that
is ever scored. A specimen no scanner could possibly detect measures nothing.

These tests pin the two properties that make the class measurable without making it unsafe:
a socket is always opened, and it is always loopback.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "specimens"))

from _behaviour import (  # noqa: E402
    ENV_EGRESS_SINK,
    LOOPBACK_FALLBACK,
    attempt_egress,
)

from poison_garden.runner.execute import scanner_env  # noqa: E402


@pytest.fixture
def no_sink(monkeypatch):
    monkeypatch.delenv(ENV_EGRESS_SINK, raising=False)


# --- the fallback exists and fires --------------------------------------------------------


def test_a_specimen_with_no_sink_still_opens_a_socket(no_sink):
    """THE regression. Returning a string without touching the network measured nothing.

    Either outcome below means `socket()` and `connect()` both ran, which is the entire
    detectable signal. What must never come back is the old early return.
    """
    result = attempt_egress(b"unused")
    assert result in {"loopback-connected", "loopback-refused"}, (
        f"attempt_egress returned {result!r} with no sink configured. If this is "
        '"no-sink-configured" again, the egress class has silently become unobservable '
        "during a scan and every specimen in it is a guaranteed miss for every scanner."
    )


def test_the_fallback_actually_reaches_a_listener_when_one_exists(no_sink, monkeypatch):
    """Proves the connect is real rather than an exception swallowed into a nice string.

    Stands a listener on the fallback address so the connect must succeed. Without this,
    `loopback-refused` would be indistinguishable from a function that never called
    `connect()` at all (P31 — a guard whose green is guaranteed is not a guard).
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        monkeypatch.setattr("_behaviour.LOOPBACK_FALLBACK", listener.getsockname())
        assert attempt_egress(b"unused") == "loopback-connected"
        conn, peer = listener.accept()
        with conn:
            assert peer[0] == "127.0.0.1"
            conn.settimeout(1.0)
            # S1/safety: the no-sink path must send NOTHING. Transmitting decoy bytes to an
            # unknown local listener is bad manners for no measurement gain, and the socket
            # alone is the signal.
            try:
                received = conn.recv(64)
            except TimeoutError:
                received = b""
            assert received == b"", f"the fallback path transmitted {len(received)} byte(s)"
    finally:
        listener.close()


# --- and it can never leave the machine ---------------------------------------------------


def test_the_fallback_address_is_loopback():
    """The one property that makes shipping this in a public repo acceptable."""
    host, port = LOOPBACK_FALLBACK
    assert host == "127.0.0.1", f"fallback host is {host!r}; a packet could leave the host"
    assert isinstance(port, int) and 0 < port < 65536


def test_a_non_loopback_sink_is_refused_rather_than_dialled(monkeypatch):
    """A tampered `PG_EGRESS_SINK` must not turn a specimen into a real exfiltrator.

    The variable is read from the environment, which makes it external input (P13). Nothing
    stops a user — or a hostile CI config — from pointing it at a routable host, and the
    specimen would then do the thing the README promises it cannot.
    """
    for hostile in ("198.51.100.7:80", "example.com:443", "10.0.0.5:9000", "::1:80"):
        monkeypatch.setenv(ENV_EGRESS_SINK, hostile)
        assert attempt_egress(b"x") == "sink-not-loopback", (
            f"sink {hostile!r} was not refused — a specimen would dial a non-loopback host"
        )


def test_the_sink_path_sends_the_payload_when_the_sink_is_loopback(monkeypatch):
    """The complement (P49): refusing everything would satisfy the test above and be useless."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        host, port = listener.getsockname()
        monkeypatch.setenv(ENV_EGRESS_SINK, f"{host}:{port}")
        assert attempt_egress(b"decoy-payload") == "sent"
        conn, _ = listener.accept()
        with conn:
            assert conn.recv(64) == b"decoy-payload"
    finally:
        listener.close()


# --- the runner hands the sink to the scanner ---------------------------------------------


def test_scanner_env_is_additive_not_a_replacement():
    """REGRESSION: a scrubbed environment made `uvx` unfindable and errored every specimen.

    Asserts on PATH specifically, because PATH is what broke, and on the key count, because
    a future edit that starts from `{}` would pass a PATH-only check.
    """
    env = scanner_env({"PG_EGRESS_SINK": "127.0.0.1:54321"})
    assert env.get("PATH") == os.environ.get("PATH")
    assert set(os.environ) <= set(env), "scanner_env dropped a variable the user had set"
    assert env["PG_EGRESS_SINK"] == "127.0.0.1:54321"


def test_scanner_env_invents_no_sink_when_the_sandbox_supplies_none():
    """A sink address we did not bind would point the specimen at an arbitrary local port."""
    env = scanner_env({})
    assert env.get("PG_EGRESS_SINK") == os.environ.get("PG_EGRESS_SINK")


# --- the corpus side: R21 -----------------------------------------------------------------


from helpers import opens_a_socket as _opens_a_socket  # noqa: E402

from poison_garden.corpus.loader import load_corpus  # noqa: E402
from poison_garden.corpus.models import Class  # noqa: E402

SPECIMENS = REPO_ROOT / "specimens"


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


def test_the_egress_class_is_populated(corpus):
    """Vacuity guard (P58/P64). The class sat empty for three releases; if it empties again
    every assertion below passes for free and nothing says so."""
    attackers = [s for s in corpus.malicious if Class.EGRESS in s.classes]
    assert attackers, (
        "no specimen exhibits the `egress` class. It is in the taxonomy and in R21; an "
        "empty class reads to a reader as an omission rather than as a decision."
    )


def test_every_egress_specimen_actually_opens_a_socket(corpus):
    """A specimen that demonstrates nothing at runtime is a guaranteed miss for everyone."""
    attackers = [s for s in corpus.malicious if Class.EGRESS in s.classes]
    inert = [s.id for s in attackers if not _opens_a_socket(s.entrypoint_path)]
    assert not inert, (
        f"{inert} declare `egress` and opened no socket when driven through initialize, "
        "two tools/list calls and resources/list. Either the connection fires on some "
        "other trigger — in which case this driver needs to exercise it — or the specimen "
        "advertises a behaviour it does not perform."
    )


def test_at_least_one_egress_twin_also_opens_a_socket(corpus):
    """R21's fairness clause, and the thing that makes this class worth scoring.

    Without a twin that genuinely connects, "flag every `connect()`" scores 100% here, and
    the class would measure whether a scanner has a socket rule rather than whether it can
    tell declared network use from undeclared. The twins are the only thing standing
    between those two (P21 — a control is valid only if a plausible loosening fires on it).
    """
    twins = [s for s in corpus.benign if Class.EGRESS in s.twin_for]
    assert twins, "the `egress` class has no benign twin at all (R3)"

    connecting = [s.id for s in twins if _opens_a_socket(s.entrypoint_path)]
    assert connecting, (
        f"none of the egress twins {[s.id for s in twins]} opens a socket. A twin that "
        "only discusses networking controls for nothing: a scanner flagging every "
        "connection would score a perfect false-positive rate on this class while being "
        "exactly as wrong as one that flags nothing."
    )


def test_specimens_reach_the_network_only_through_the_shared_helper():
    """The loopback guarantee must be a property of one reviewed function, not of authorship.

    `attempt_egress` is where "loopback, never routable" is enforced and tested. A specimen
    importing `socket` or `urllib` directly routes around that, and no amount of care in
    review scales to every future contributed specimen (S1).
    """
    banned = ("import socket", "import urllib", "import http.client", "import requests",
              "from socket import", "from urllib", "import subprocess", "import asyncio")
    offenders: list[str] = []
    for specimen in load_corpus(SPECIMENS).specimens:
        for path in specimen.files():
            if path.suffix != ".py":
                continue
            text = path.read_text(encoding="utf-8")
            hits = [b for b in banned if b in text]
            if hits:
                offenders.append(f"{specimen.id}/{path.name}: {hits}")
    assert not offenders, (
        "specimens must reach the network only via `_behaviour.attempt_egress`, which is "
        f"where the loopback guarantee lives: {offenders}"
    )
