"""Probe coverage — how much redundancy is there inside a behavioural class? (R23)

A per-class recall figure of `1/6` invites the reading "six independent things were tested
and one was caught". For the behavioural classes that reading is too generous to the corpus:
a single well-chosen probe exposes every specimen in some of them, so the six are closer to
one test repeated than to six separate ones.

**This is an upper bound on redundancy, not an effective sample size, and the distinction is
load-bearing.** `namesake-rugpull` has coverage 6/6 — one probe reveals all six — yet frisk
scored 1/6 on it. Perfect coverage would predict 0/6 or 6/6. So coverage says "one observer
capability suffices to *see* all of these", not "a scanner that catches one catches all".
Detection still requires a rule, and rules can partially succeed.

Why not a design effect instead. The obvious alternative is to estimate an intracluster
correlation from a scanner's per-class results and widen the intervals. That was measured and
rejected: on the one result document available it yields rho = 0.375 (Pearson chi-square
29.08 on df 10, permutation p = 0.0003), but a simulation of classes with *genuinely
different* true rates and *perfectly independent* specimens reproduces a median chi-square of
34.5 — higher than observed, and exceeding it 87% of the time. The statistic cannot separate
"specimens within a class are correlated" from "classes differ from each other", and classes
differing is the thing per-class reporting exists to express. Correcting an interval with it
would adjust for something that is not there. With one outcome per specimen, within-class
correlation is not identifiable; coverage is the measurable thing, so coverage is what ships.

Only the behavioural classes are measured. For a declaration class the payload is in the
served catalog, so one enumeration exposes every member trivially — that is a statement about
how cheap *observation* is, not about redundancy, and reporting 6/6 there would be a category
error.

    uv run python scripts/measure_probe_coverage.py [--json]
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from poison_garden.corpus.loader import load_corpus  # noqa: E402
from poison_garden.corpus.models import Class  # noqa: E402

INSPECTOR = {
    "protocolVersion": "2025-06-18",
    "clientInfo": {"name": "mcp", "version": "0.1.0"},
    "capabilities": {},
}
AGENT = {
    "protocolVersion": "2025-06-18",
    "clientInfo": {"name": "acme-desktop", "version": "1.4.0", "title": "Acme Desktop"},
    "capabilities": {"roots": {"listChanged": True}, "sampling": {}, "elicitation": {}},
}


def _catalogs(path: Path, params: dict, *, enums: int, initialized: bool,
              sweep_first: bool, env: dict | None = None) -> list[str]:
    msgs: list[dict] = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}]
    if initialized:
        msgs.append({"jsonrpc": "2.0", "method": "notifications/initialized"})
    if sweep_first:
        msgs.append({"jsonrpc": "2.0", "id": 90, "method": "resources/list"})
    for i in range(enums):
        msgs.append({"jsonrpc": "2.0", "id": 100 + i, "method": "tools/list"})
    msgs.append({"jsonrpc": "2.0", "id": 200, "method": "resources/list"})
    try:
        out = subprocess.run(
            [sys.executable, str(path)],
            input="\n".join(json.dumps(m) for m in msgs) + "\n",
            capture_output=True, text=True, timeout=30, env=env,
        ).stdout
    except subprocess.TimeoutExpired:
        return []
    got = []
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(d.get("id"), int) and 100 <= d["id"] < 200:
            got.append(json.dumps(d.get("result", {}), sort_keys=True))
    return got


def _exposed_by_client_profile(path: Path) -> bool:
    """Does one realistic agent see something an inspector does not?"""
    inspector = _catalogs(path, INSPECTOR, enums=1, initialized=False, sweep_first=True)
    agent = _catalogs(path, AGENT, enums=2, initialized=True, sweep_first=False)
    return bool(inspector) and bool(agent) and inspector[-1] != agent[-1]


def _exposed_by_repeated_enumeration(path: Path) -> bool:
    """Does the catalog change within one session, given enough enumerations?"""
    cats = _catalogs(path, AGENT, enums=9, initialized=True, sweep_first=False)
    return len(set(cats)) > 1


def _exposed_by_single_enumeration(path: Path) -> bool:
    """Is there anything to see in one ordinary enumeration?"""
    return bool(_catalogs(path, AGENT, enums=1, initialized=True, sweep_first=False))


def _exposed_by_loopback_listener(specimens: list) -> dict[str, bool]:
    """Does the specimen open a socket when a sink is offered? One listener serves all."""
    import os

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(8)
    seen = threading.Event()

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            seen.set()
            conn.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    host, port = listener.getsockname()
    out: dict[str, bool] = {}
    try:
        for s in specimens:
            seen.clear()
            _catalogs(s.entrypoint_path, AGENT, enums=2, initialized=True, sweep_first=True,
                      env={**os.environ, "PG_EGRESS_SINK": f"{host}:{port}"})
            out[s.id] = seen.wait(timeout=2.0)
    finally:
        listener.close()
    return out


PROBES = {
    Class.SCANNER_AWARE: ("one realistic client profile", _exposed_by_client_profile),
    Class.NAMESAKE_RUGPULL: ("nine enumerations in one session", _exposed_by_repeated_enumeration),
    Class.EXFIL_ENUMERATION: ("a single enumeration", _exposed_by_single_enumeration),
}


def measure(corpus_root: Path) -> dict:
    corpus = load_corpus(corpus_root)
    report: dict[str, dict] = {}

    for klass, (label, probe) in PROBES.items():
        members = sorted(
            (s for s in corpus.malicious if klass in s.classes), key=lambda s: s.id
        )
        exposed = [s.id for s in members if probe(s.entrypoint_path)]
        report[str(klass)] = {
            "specimens": len(members),
            "exposed_by_one_probe": len(exposed),
            "probe": label,
        }

    egress = sorted(
        (s for s in corpus.malicious if Class.EGRESS in s.classes), key=lambda s: s.id
    )
    if egress:
        hits = _exposed_by_loopback_listener(egress)
        report[str(Class.EGRESS)] = {
            "specimens": len(egress),
            "exposed_by_one_probe": sum(hits.values()),
            "probe": "one loopback listener",
        }

    # Deliberately not measured. Exposing a credential read needs filesystem tracing, which
    # this harness does not do. Reporting an unmeasured class as 0 would read as "no
    # redundancy" — the opposite of the truth — so it is named as unmeasured instead.
    report[str(Class.CREDENTIAL_ACCESS)] = {
        "specimens": sum(1 for s in corpus.malicious if Class.CREDENTIAL_ACCESS in s.classes),
        "exposed_by_one_probe": None,
        "probe": "not measured — requires filesystem tracing",
    }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(REPO_ROOT / "specimens"))
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory():
        report = measure(Path(args.corpus))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print("Probe coverage — behavioural classes only")
    print("UPPER BOUND on redundancy. NOT an effective sample size: namesake-rugpull has")
    print("coverage 6/6 and frisk still scored 1/6, so a scanner can partially succeed.\n")
    print(f"  {'class':<20}{'coverage':>10}   probe")
    for klass in sorted(report):
        r = report[klass]
        cov = (
            "not measured" if r["exposed_by_one_probe"] is None
            else f"{r['exposed_by_one_probe']}/{r['specimens']}"
        )
        print(f"  {klass:<20}{cov:>10}   {r['probe']}")
    print("\nDeclaration classes are not measured: the payload is catalog-resident, so one")
    print("enumeration exposes every member trivially. That is a fact about how cheap")
    print("observation is, not about redundancy, and reporting it as coverage would mislead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
