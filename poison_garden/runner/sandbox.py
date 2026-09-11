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
    canaries: dict[str, str]
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
    _server: socket.socket | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    connections: list[bytes] = field(default_factory=list)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("egress sink is not started")
        return self._server.getsockname()[1]

    def start(self) -> EgressSink:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, 0))  # port 0 → OS picks a free one
        server.listen(8)
        server.settimeout(0.2)
        self._server = server

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.5)
                try:
                    payload = conn.recv(4096)
                except OSError:
                    payload = b""
            with self._lock:
                self.connections.append(payload)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._server is not None:
            self._server.close()
            self._server = None

    @property
    def attempt_count(self) -> int:
        with self._lock:
            return len(self.connections)

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
