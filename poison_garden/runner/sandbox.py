"""Specimen sandbox — S1.

A specimen must only ever touch decoys. This module builds the throwaway world a specimen
runs inside:

- a temporary `$HOME` seeded with decoy credential files carrying **per-run canary values**
- a loopback egress sink, so a specimen that "exfiltrates" reaches 127.0.0.1 and nothing else

The canaries are per-run and random on purpose. A fixed decoy string could be matched by
accident, and a test asserting on a literal would still pass if `$HOME` were never
overridden at all. Asserting that a specimen read *this run's* canary is the only evidence
that the substitution actually took effect (cross-cutting P16 — a capability probe must
validate its own setup step; frisk shipped a memory limit that never bound for two releases
because nobody read it back).
"""

from __future__ import annotations

import os
import secrets
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

# Environment variables the harness hands to a specimen.
ENV_EGRESS_SINK = "PG_EGRESS_SINK"
ENV_PROBE_RESULT = "PG_PROBE_RESULT"
ENV_CANARY_HINT = "PG_CANARY"

DECOY_FILES = {
    ".ssh/id_rsa": "ssh-private-key",
    ".aws/credentials": "aws-credentials",
    ".env": "dotenv",
    ".config/gh/hosts.yml": "github-token",
}


@dataclass(frozen=True)
class Sandbox:
    """A prepared throwaway world for one specimen run."""

    home: Path
    # repr=False: these are the run's decoy canary VALUES. Without this, any
    # `--showlocals` traceback, log line, or f-string interpolating a Sandbox prints them.
    # S3 forbids canary values reaching any artifact, and a repr is an artifact.
    canaries: dict[str, str] = field(repr=False)
    egress_host: str
    egress_port: int
    probe_result: Path

    @property
    def egress_address(self) -> str:
        return f"{self.egress_host}:{self.egress_port}"

    def env(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Environment for the specimen subprocess.

        Scrubbed rather than inherited: a specimen must not see the real user's tokens even
        by accident, so only an explicit allowlist of harmless variables carries through.
        """
        source = dict(base if base is not None else os.environ)
        out = {
            key: source[key]
            for key in ("LANG", "LC_ALL", "TZ", "SYSTEMROOT")
            if key in source
        }

        # PATH is NOT inherited, and deliberately does NOT include the interpreter's own
        # directory. The real PATH contains the user's home verbatim
        # (`/Users/<name>/.venvs/...`), handing a specimen the real home as a string
        # through the very allowlist meant to withhold it — and a venv bin directory has
        # the same problem. Specimens are spawned with an explicit interpreter path, so
        # they never need either.
        out["PATH"] = os.pathsep.join(["/usr/bin", "/bin"])

        # TMPDIR is repointed inside the throwaway root rather than inherited: as inherited
        # it is a writable real-user directory OUTSIDE the decoy home.
        tmp = self.home.parent / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        out["TMPDIR"] = str(tmp)

        out["HOME"] = str(self.home)
        out["USERPROFILE"] = str(self.home)  # Windows equivalent
        out[ENV_EGRESS_SINK] = self.egress_address
        out[ENV_PROBE_RESULT] = str(self.probe_result)
        # Deterministic hashing so a specimen's output cannot vary run to run (N3).
        out["PYTHONHASHSEED"] = "0"

        # NOTE: the scrub cannot be total. macOS injects `__CF_USER_TEXT_ENCODING` (which
        # carries the real uid) into every child process regardless of `env=`, and nothing
        # here prevents a specimen reading the passwd database. This is environment
        # shaping, not containment — see S5, and do not describe it as a sandbox.
        return out

    def canary_for(self, relative_path: str) -> str:
        return self.canaries[relative_path]

    @property
    def all_canary_values(self) -> tuple[str, ...]:
        return tuple(self.canaries.values())


@dataclass
class EgressSink:
    """A loopback listener standing in for the internet.

    Records every connection attempt and the first chunk of anything sent, so a test can
    assert a specimen *tried* to exfiltrate without a single packet leaving the machine.
    """

    host: str = "127.0.0.1"
    backlog: int = 64
    _server: socket.socket | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _handlers: list[threading.Thread] = field(default_factory=list, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # repr=False: payloads are exfiltrated decoy credentials (S3).
    connections: list[bytes] = field(default_factory=list, repr=False)
    accepted: int = 0
    faults: list[str] = field(default_factory=list)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("egress sink is not started")
        return self._server.getsockname()[1]

    def start(self) -> EgressSink:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, 0))  # port 0 → OS picks a free one
        server.listen(self.backlog)
        server.settimeout(0.05)
        self._server = server

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        """Accept loop.

        Each connection is read on its OWN thread. Reading inline meant one slow or silent
        client blocked the accept loop for the full recv timeout, so a burst of
        connections was abandoned in the listen backlog at teardown: measured, 8 opened
        and 1 recorded. For an egress specimen that is a detection turned into a silent
        miss — precisely the failure R7 exists to prevent, arriving by another door.
        """
        while not self._stop.is_set():
            server = self._server
            if server is None:
                return
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError as exc:
                # A transient accept error (ECONNABORTED, EMFILE) used to `break`, killing
                # the sink for good while every later attempt read as a clean zero. Record
                # it and keep serving; `attempt_count` refuses to report a clean zero once
                # a fault exists (P55 — two empties are two findings).
                if self._stop.is_set():
                    return
                with self._lock:
                    self.faults.append(type(exc).__name__)
                continue

            with self._lock:
                self.accepted += 1
            handler = threading.Thread(target=self._read, args=(conn,), daemon=True)
            with self._lock:
                self._handlers.append(handler)
            handler.start()

    def _read(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(0.5)
            try:
                payload = conn.recv(4096)
            except OSError:
                payload = b""
        with self._lock:
            self.connections.append(payload)

    def drain(self, timeout: float = 2.0) -> None:
        """Wait for accepted connections to finish being read.

        Must run BEFORE `stop()` sets the stop flag, or in-flight reads are abandoned.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                handlers = list(self._handlers)
                settled = self.accepted == len(self.connections)
            if settled and all(not h.is_alive() for h in handlers):
                return
            time.sleep(0.02)

    def stop(self, drain_timeout: float = 2.0) -> None:
        self.drain(drain_timeout)
        self._stop.set()

        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)

        for handler in list(self._handlers):
            handler.join(timeout=1)

        # Only release the server once the accept loop has genuinely exited. Nulling it
        # while that thread is live made it call `None.accept()` — an AttributeError, not
        # an OSError, so it escaped the handler entirely inside a daemon thread.
        if thread is None or not thread.is_alive():
            if self._server is not None:
                self._server.close()
                self._server = None

    @property
    def attempt_count(self) -> int:
        """Connections recorded.

        Raises if the count is zero while a fault was recorded: "nothing connected" and
        "the sink broke" are different findings and one integer cannot carry both.
        """
        with self._lock:
            count = len(self.connections)
            faults = list(self.faults)
        if count == 0 and faults:
            raise RuntimeError(
                f"egress sink recorded no attempts but hit {len(faults)} accept fault(s) "
                f"({sorted(set(faults))}) — a zero here is unsafe to read as 'no egress'"
            )
        return count

    @property
    def accepted_count(self) -> int:
        with self._lock:
            return self.accepted

    def received(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self.connections)


def build_home(root: Path) -> tuple[Path, dict[str, str]]:
    """Create a throwaway HOME under `root`, seeded with per-run decoy canaries.

    Returns the home path and a mapping of relative decoy path -> canary value.
    """
    home = root / "home"
    home.mkdir(parents=True, exist_ok=True)

    canaries: dict[str, str] = {}
    for relative, label in DECOY_FILES.items():
        canary = f"PG-DECOY-{label}-{secrets.token_hex(8)}"
        target = home / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_decoy_body(label, canary), encoding="utf-8")
        target.chmod(0o600)
        canaries[relative] = canary

    return home, canaries


def _decoy_body(label: str, canary: str) -> str:
    """Decoy content that looks plausible but is inert and obviously fake."""
    if label == "ssh-private-key":
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{canary}\n"
            "THIS IS NOT A KEY. It is a poison-garden decoy, used to prove a specimen read\n"
            "the throwaway home rather than yours. It unlocks nothing.\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
    if label == "aws-credentials":
        return f"[default]\naws_access_key_id = {canary}\naws_secret_access_key = {canary}\n"
    if label == "github-token":
        return f"github.com:\n  oauth_token: {canary}\n"
    return f"SECRET_TOKEN={canary}\nAPI_KEY={canary}\n"


@contextmanager
def sandbox(root: Path) -> Iterator[tuple[Sandbox, EgressSink]]:
    """Prepare a sandbox and its egress sink, tearing the sink down on exit."""
    home, canaries = build_home(root)
    probe_result = root / "probe-result.json"

    sink = EgressSink().start()
    try:
        yield (
            Sandbox(
                home=home,
                canaries=canaries,
                egress_host=sink.host,
                egress_port=sink.port,
                probe_result=probe_result,
            ),
            sink,
        )
    finally:
        sink.stop()
