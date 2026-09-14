"""Sandbox safety tests — S1, S2, N3.

The single most important test in the project is
`test_specimen_reads_the_decoy_not_the_real_home`. If the throwaway `$HOME` does not
actually bind, specimens read the *real* user's credentials, the README's safety claim
becomes false, and every other test still passes. Set-then-read-back is the only proof
(cross-cutting P16).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from poison_garden.runner.sandbox import (
    DECOY_FILES,
    ENV_EGRESS_SINK,
    EgressSink,
    build_home,
    sandbox,
)

FIXTURES = Path(__file__).parent / "fixtures"
SPECIMENS_DIR = Path(__file__).parent.parent / "specimens"
REAL_HOME = Path.home()


def _run_specimen(script: Path, env: dict[str, str], timeout: float = 20.0):
    """Spawn a specimen, complete a handshake, and shut it down."""
    handshake = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "pytest"}},
    }
    stdin_text = (
        json.dumps(handshake)
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
    )

    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        # communicate() owns stdin: writing and closing it by hand makes its own flush
        # raise ValueError on a closed file.
        stdout, stderr = proc.communicate(input=stdin_text, timeout=timeout)
        return stdout, stderr
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


# --- S1 / P16: the sandbox must actually bind -------------------------------------------


def test_build_home_seeds_every_decoy_with_a_unique_canary(tmp_path: Path):
    home, canaries = build_home(tmp_path)
    assert set(canaries) == set(DECOY_FILES)
    for relative, canary in canaries.items():
        assert (home / relative).is_file()
        assert canary in (home / relative).read_text(encoding="utf-8")
    assert len(set(canaries.values())) == len(canaries), "canaries must be distinct per file"


def test_canaries_differ_between_runs(tmp_path: Path):
    """Per-run canaries: a fixed decoy could be matched by accident (P16)."""
    _, first = build_home(tmp_path / "one")
    _, second = build_home(tmp_path / "two")
    assert set(first.values()).isdisjoint(set(second.values()))


def test_specimen_reads_the_decoy_not_the_real_home(tmp_path: Path):
    """THE sandbox proof (S1, P16).

    Spawns a specimen that reads every decoy path and asserts it got THIS RUN's canary.
    If `$HOME` were not substituted the specimen would read the real file (or fail to find
    it) and the canary would not appear — either way this test reddens. Nothing here ever
    opens the real user's key.
    """
    with sandbox(tmp_path) as (box, _sink):
        _run_specimen(FIXTURES / "probe_specimen.py", box.env())

        assert box.probe_result.is_file(), "probe specimen produced no result"
        findings = json.loads(box.probe_result.read_text(encoding="utf-8"))

        assert findings["home"] == str(box.home), "specimen did not run under the decoy HOME"

        for relative in DECOY_FILES:
            content = findings["reads"][relative]
            assert box.canary_for(relative) in content, (
                f"{relative}: specimen did not read this run's decoy. "
                "The throwaway HOME did not bind."
            )


def test_specimen_cannot_see_the_real_home_path(tmp_path: Path):
    """The decoy HOME must not merely shadow the real one — it must replace it.

    Asserts HOME is non-empty FIRST. Without that, an unset HOME resolves to cwd, which is
    also != the real home, so the test would pass while the sandbox was entirely absent —
    a green guaranteed by the failure mode it is meant to detect (P50).
    """
    with sandbox(tmp_path) as (box, _sink):
        _run_specimen(FIXTURES / "probe_specimen.py", box.env())
        findings = json.loads(box.probe_result.read_text(encoding="utf-8"))

        reported = findings["home"]
        assert reported, "specimen saw an empty $HOME — the sandbox did not bind at all"
        assert Path(reported).resolve() == box.home.resolve(), (
            "specimen's $HOME is neither the decoy nor absent — substitution went wrong"
        )
        assert Path(reported).resolve() != REAL_HOME.resolve()


def test_env_is_scrubbed_not_inherited(tmp_path: Path):
    """A specimen must not see the real user's tokens even by accident."""
    with sandbox(tmp_path) as (box, _sink):
        env = box.env({"AWS_SECRET_ACCESS_KEY": "REAL-SECRET", "PATH": "/opt/evil/bin"})
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert env["HOME"] == str(box.home)
        assert "/opt/evil/bin" not in env["PATH"], "PATH must not be inherited at all"


def test_no_environment_variable_discloses_the_real_home(tmp_path: Path):
    """REGRESSION: the allowlist used to pass PATH straight through.

    The real PATH contains the user's home verbatim (`/Users/<name>/.venvs/...`), so the
    very allowlist meant to withhold the real home was handing it over as a string. An
    absent guarantee is worse than a weak one when the README makes a promise about it.
    """
    with sandbox(tmp_path) as (box, _sink):
        real_home = str(Path.home())
        leaks = {k: v for k, v in box.env().items() if real_home in str(v)}
        assert not leaks, f"environment discloses the real home: {leaks}"


def test_tmpdir_points_inside_the_throwaway_root(tmp_path: Path):
    """An inherited TMPDIR is a writable real-user directory outside the decoy home."""
    with sandbox(tmp_path) as (box, _sink):
        tmpdir = Path(box.env()["TMPDIR"]).resolve()
        assert tmpdir.is_relative_to(tmp_path.resolve()), (
            f"TMPDIR {tmpdir} is outside the throwaway root {tmp_path}"
        )


# --- S1: egress reaches loopback and nothing else ----------------------------------------


def test_egress_sink_records_an_exfiltration_attempt(tmp_path: Path):
    with sandbox(tmp_path) as (box, sink):
        _run_specimen(FIXTURES / "egress_specimen.py", box.env())

        deadline = time.monotonic() + 5
        while sink.attempt_count == 0 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert sink.attempt_count == 1, "the sink recorded no connection attempt"
        payload = sink.received()[0].decode("utf-8", errors="replace")
        assert box.canary_for(".aws/credentials") in payload, (
            "the specimen exfiltrated something other than this run's decoy"
        )


def test_sink_binds_loopback_only():
    sink = EgressSink().start()
    try:
        assert sink.host == "127.0.0.1"
        assert sink.port > 0
    finally:
        sink.stop()


def test_sink_address_is_handed_to_the_specimen(tmp_path: Path):
    with sandbox(tmp_path) as (box, sink):
        assert box.env()[ENV_EGRESS_SINK] == f"127.0.0.1:{sink.port}"


# --- S1 / S2: no specimen may reference anything real ------------------------------------

# Public IPv4 literal, excluding loopback/private ranges which are legitimate here.
_IP_LITERAL = re.compile(
    r"\b(?!"
    r"127\.|10\.|0\.0\.0\.0"
    r"|192\.168\."
    r"|169\.254\."                      # link-local
    r"|172\.(?:1[6-9]|2\d|3[01])\."      # 172.16.0.0/12
    r")\d{1,3}(?:\.\d{1,3}){3}\b"
)
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "example.com", "example.org", "example.net"}


def _shipped_specimen_sources() -> list[Path]:
    """EVERY file shipped in the corpus, from the loader's own definition.

    Not `rglob("*.py")`. A specimen ships whatever files it contains and all of them are
    hashed, so globbing Python left `manifest.toml` shipped, hashed, and never scanned —
    despite carrying author prose (`summary`, `notes`) where a hostname would plausibly
    land. A future `payload.json` or `hosts.txt` would have been invisible the same way.

    Sourcing the population from `Specimen.files()` means "the files in the corpus" has a
    single definition feeding both the hash and this scan, so the two cannot drift (P95).
    """
    from poison_garden.corpus.loader import load_corpus

    if not SPECIMENS_DIR.is_dir():
        return []
    files = [path for s in load_corpus(SPECIMENS_DIR).specimens for path in s.files()]
    # Shared harness modules are shipped and hashed too, so they are scanned too.
    files += sorted(SPECIMENS_DIR.glob("_*.py"))
    return sorted(files)


def test_there_are_specimen_sources_to_scan():
    """Vacuity guard (P58/P64): an empty population makes every check below pass for free."""
    sources = _shipped_specimen_sources()
    assert sources, f"no specimen sources found under {SPECIMENS_DIR}"


@pytest.mark.parametrize("source", _shipped_specimen_sources(), ids=lambda p: p.name)
def test_no_specimen_contains_a_public_ip_literal(source: Path):
    text = source.read_text(encoding="utf-8")
    assert not _IP_LITERAL.findall(text), (
        f"{source.name} contains a public IP literal; specimens reach loopback only (S1)"
    )


@pytest.mark.parametrize("source", _shipped_specimen_sources(), ids=lambda p: p.name)
def test_no_specimen_contacts_a_real_host(source: Path):
    text = source.read_text(encoding="utf-8")
    hosts = {h.lower() for h in _URL.findall(text)}
    offenders = hosts - _ALLOWED_HOSTS
    assert not offenders, (
        f"{source.name} references non-reserved host(s) {sorted(offenders)}. "
        "Specimens must be inert outside the harness (S1, S2)."
    )


# Every way a specimen could reach the REAL home or a real host despite the $HOME
# substitution. This list exists because the substitution is a naming convention, not a
# jail: `pwd.getpwuid()` and `expanduser("~user")` read the passwd database and ignore
# $HOME entirely, and an allowlisted PATH hands over the real home path as a string.
# Each entry was measured escaping the harness before being added here.
_ESCAPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bpwd\.getpw"), "pwd.getpw* reads the passwd database and ignores $HOME"),
    (re.compile(r"\bexpanduser\b"), "expanduser('~user') resolves the REAL home"),
    (re.compile(r"/Users/"), "absolute macOS home path"),
    (re.compile(r"/home/"), "absolute Linux home path"),
    (re.compile(r"\bos\.environ\[[\"']PATH"), "mining PATH for the real home"),
    (re.compile(r"\bgetpass\.getuser\b"), "username lookup feeding a ~user expansion"),
    (re.compile(r"\bpathlib\.Path\.home\b"), "Path.home() bypasses if $HOME is unset"),
    (re.compile(r"\bwss?://"), "websocket egress to a non-loopback host"),
    (re.compile(r"\bsocket\.gethostbyname\b"), "DNS resolution of a real host"),
]


@pytest.mark.parametrize("source", _shipped_specimen_sources(), ids=lambda p: p.name)
def test_no_specimen_escapes_the_home_substitution(source: Path):
    """A specimen must reach credentials via $HOME, never around it.

    The harness substitutes $HOME; it does NOT contain the process. So a specimen that
    consults the passwd database, expands `~username`, or reads an absolute home path
    reaches the real user's credentials with every test still green. This grep is the
    only thing enforcing that for shipped specimens — see `S2` in SPEC.md and the
    "Safety" section of the README, which are explicit that the harness is not a jail.
    """
    text = source.read_text(encoding="utf-8")
    hits = [why for pattern, why in _ESCAPE_PATTERNS if pattern.search(text)]
    assert not hits, f"{source.name} can escape the $HOME substitution: {hits}"


@pytest.mark.parametrize("source", _shipped_specimen_sources(), ids=lambda p: p.name)
def test_no_specimen_names_a_bare_external_host(source: Path):
    """A hostname need not carry a scheme to be an egress target."""
    text = source.read_text(encoding="utf-8")
    bare = re.findall(r"[\"']([a-z0-9-]+(?:\.[a-z0-9-]+){1,})[\"']", text, re.I)
    offenders = [
        host
        for host in bare
        if not host.endswith((".py", ".toml", ".json", ".md", ".txt", ".yml", ".yaml"))
        and host.lower() not in _ALLOWED_HOSTS
        and re.search(r"\.(io|com|net|org|dev|sh|co|ai|app|cloud)$", host, re.I)
    ]
    assert not offenders, (
        f"{source.name} names external host(s) {offenders}; specimens reach loopback only"
    )


def test_the_escape_guard_actually_catches_escapes(tmp_path: Path):
    """P31/P50: a grep-based guard that has never been shown to fire is decoration.

    Feeds each measured bypass through the same patterns the guard uses and asserts every
    one is caught. Without this, broadening the guard would be unfalsifiable.
    """
    bypasses = {
        "pwd bypass": "import pwd, os\nhome = pwd.getpwuid(os.getuid()).pw_dir\n",
        "named tilde": "import os.path, getpass\nos.path.expanduser('~' + getpass.getuser())\n",
        "linux home": "open('/home/ci/.aws/credentials')\n",
        "macos home": "open('/Users/someone/.ssh/id_rsa')\n",
        "path mining": "import os\nos.environ['PATH'].split(':')\n",
        "websocket egress": "URL = 'wss://drop.example-attacker.io/ingest'\n",
        "Path.home": "import pathlib\npathlib.Path.home()\n",
    }
    missed = [
        label
        for label, code in bypasses.items()
        if not any(pattern.search(code) for pattern, _ in _ESCAPE_PATTERNS)
    ]
    assert not missed, f"the escape guard misses these known bypasses: {missed}"


# --- N3: determinism ---------------------------------------------------------------------


def test_specimen_catalog_is_byte_identical_across_runs(tmp_path: Path):
    """N3/P103: compare the two runs to EACH OTHER, not each against a literal."""
    with sandbox(tmp_path / "a") as (box_a, _):
        first, _ = _run_specimen(FIXTURES / "probe_specimen.py", box_a.env())
    with sandbox(tmp_path / "b") as (box_b, _):
        second, _ = _run_specimen(FIXTURES / "probe_specimen.py", box_b.env())

    def _tools_line(stdout: str) -> str:
        for line in stdout.splitlines():
            if '"tools"' in line:
                return line
        raise AssertionError(f"no tools/list response in specimen output: {stdout!r}")

    assert _tools_line(first) == _tools_line(second)


# --- S3: no artifact may carry a canary, and a repr is an artifact ----------------------


def test_sandbox_repr_does_not_leak_canaries(tmp_path: Path):
    """REGRESSION: `--showlocals`, a log line, or an f-string would have printed them."""
    with sandbox(tmp_path) as (box, _sink):
        rendered = repr(box)
        for canary in box.all_canary_values:
            assert canary not in rendered, "Sandbox repr leaks a decoy canary (S3)"


def test_egress_sink_repr_does_not_leak_payloads(tmp_path: Path):
    with sandbox(tmp_path) as (_box, sink):
        sink.connections.append(b"PG-EXFILTRATED-SECRET")
        assert "PG-EXFILTRATED-SECRET" not in repr(sink), "sink repr leaks a payload (S3)"


BURST = 40


def test_sink_records_every_attempt_in_a_burst():
    """REGRESSION (W1, and again): connections opened, one recorded — lost in the backlog.

    For an egress specimen that is a detection turned into a silent miss, which is the
    failure R7 exists to prevent arriving through another door.

    Burst raised from 8 to 40. At 8 this passed on every machine for weeks and then failed
    on one CI runner, because `drain()` never waited for the listen backlog and whether the
    accept thread had caught up was a scheduling accident.

    **This test is load-dependent and cannot prove the fix.** Reverting the backlog drain
    leaves it green on an unloaded machine at 40 connections, because the accept thread
    simply keeps up; it went red on a CI runner under contention. Treat a local pass as
    weak evidence. The deterministic pin on the mechanism is
    `test_drain_stops_the_accept_loop_only_once_the_queue_is_empty` below — that one fails
    the moment the drain is removed, on any machine.
    """
    import socket as _socket

    sink = EgressSink().start()
    conns = []
    try:
        for _ in range(BURST):
            conn = _socket.create_connection((sink.host, sink.port), timeout=2)
            conn.sendall(b"x")
            conns.append(conn)
        sink.stop()
        assert sink.accepted_count == BURST, (
            f"accepted only {sink.accepted_count} of {BURST} — connections were abandoned "
            "in the listen backlog, which is a silent miss for an egress specimen"
        )
        assert len(sink.received()) == BURST, (
            f"recorded only {len(sink.received())} of {BURST}"
        )
    finally:
        for conn in conns:
            conn.close()


def test_attempt_count_refuses_a_clean_zero_after_a_fault():
    """P55: 'nothing connected' and 'the sink broke' cannot share one integer."""
    sink = EgressSink()
    sink.faults.append("ECONNABORTED")
    with pytest.raises(RuntimeError, match="unsafe to read"):
        _ = sink.attempt_count


def test_drain_stops_the_accept_loop_only_once_the_queue_is_empty():
    """The mechanism behind the backlog fix, pinned deterministically.

    `drain()` sets `_finishing` and joins the accept thread; the loop exits on its first
    `accept()` timeout, and a timeout is the sockets API's only honest answer to "is the
    queue empty?". So after `drain()` returns, the accept thread must have exited *by that
    route* — which is what guarantees every queued connection was taken first.

    Deterministic where the burst test is not: it asserts the thread is alive before and
    dead after, which does not depend on how fast any scheduler happens to be.
    """
    sink = EgressSink().start()
    try:
        assert sink._thread is not None and sink._thread.is_alive(), (
            "precondition: the accept loop should be running before drain"
        )
        sink.drain()
        assert not sink._thread.is_alive(), (
            "the accept loop is still running after drain() returned, so connections queued "
            "in the listen backlog can still be abandoned by stop()"
        )
    finally:
        sink.stop()


def test_a_connection_made_before_drain_is_never_abandoned():
    """The property the backlog fix exists to provide, stated as a contract.

    A client's `connect()` returns once the connection is queued, so anything connected
    before `drain()` is already in the accept queue and must be recorded. This holds however
    far behind the accept thread happens to be.
    """
    import socket as _socket

    sink = EgressSink().start()
    conns = []
    try:
        for index in range(12):
            conn = _socket.create_connection((sink.host, sink.port), timeout=2)
            conn.sendall(f"payload-{index}".encode())
            conns.append(conn)
        sink.stop()
        assert len(sink.received()) == 12
        assert {p.decode() for p in sink.received()} == {f"payload-{i}" for i in range(12)}, (
            "every queued connection must be recorded, and recorded with its own payload"
        )
    finally:
        for conn in conns:
            conn.close()
