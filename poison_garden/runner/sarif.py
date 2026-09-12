"""Optional SARIF attribution — R17.

Exit codes answer one question: *did you flag this specimen at all?* That is enough to
produce a first number with zero integration work, which is why it is the baseline and why
it will stay the baseline. SARIF answers a second question — *what did you think was wrong?*
— and lets a run credit a scanner per class rather than per specimen.

**Strictly optional, and its absence never blocks a run (R17).** A scanner that emits no
SARIF still scores exactly as before. The moment per-class attribution became mandatory,
participation would require per-vendor work, and a precise number nobody produces is worth
less than a coarse one everybody does.

What SARIF buys, concretely: a specimen carrying two classes (`hidden-content` +
`injection`) is one verdict under exit codes, so flagging it credits both classes even if
the scanner only saw one. With SARIF the run can tell those apart.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from poison_garden.corpus.models import Class

# Substrings that map a SARIF rule id or message to one of our classes. Deliberately
# generous: a scanner names its rules whatever it likes, and failing to map one costs only
# the finer-grained credit, never the baseline verdict.
_CLASS_HINTS: dict[Class, tuple[str, ...]] = {
    Class.INJECTION: ("inject", "prompt", "instruction", "override"),
    Class.HIDDEN_CONTENT: (
        "hidden", "invisible", "zero-width", "zerowidth", "bidi", "ansi", "unicode",
    ),
    Class.SENSITIVE_PARAMS: ("sensitive", "credential", "secret", "token", "param"),
    Class.SCOPE_MISMATCH: ("scope", "capability", "mismatch", "shell", "exec"),
    Class.IMPERSONATION: ("impersonat", "shadow", "typosquat", "namesake", "spoof"),
    Class.HYGIENE: ("hygiene", "provenance", "unpinned", "metadata", "origin"),
    Class.CREDENTIAL_ACCESS: ("credential-access", "honeypot", "decoy", "canary", "filesystem"),
    Class.EGRESS: ("egress", "network", "exfil", "outbound"),
    Class.EXFIL_ENUMERATION: ("exfil", "leak", "disclos"),
    Class.NAMESAKE_RUGPULL: ("rugpull", "rug-pull", "mutat", "duplicate", "changed"),
    Class.SCANNER_AWARE: ("evasion", "scanner-aware", "conditional", "cloak"),
}


class SarifError(ValueError):
    """The scanner's output was requested as SARIF and is not usable as SARIF."""


@dataclass(frozen=True)
class SarifFindings:
    """What a scanner reported about one specimen, as classes we recognise."""

    classes: frozenset[Class]
    result_count: int
    unmapped_rules: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        """Any result at all means the scanner flagged the specimen.

        Independent of whether we could map the rule to a class: a finding we cannot
        classify is still a finding, and treating it as `clean` would penalise a scanner
        for naming its rules in a way we did not anticipate.
        """
        return self.result_count > 0


def parse_sarif(text: str) -> SarifFindings:
    """Extract classes from a SARIF 2.1.0 document.

    Tolerant by design. A malformed document raises — that is an `error`, not a verdict —
    but an unrecognised rule id is merely unmapped, because the alternative is scoring a
    scanner by how well its vocabulary matches ours.
    """
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SarifError(f"not valid JSON ({type(exc).__name__})") from exc

    if not isinstance(payload, dict) or "runs" not in payload:
        raise SarifError("no 'runs' key; not a SARIF document")

    found: set[Class] = set()
    unmapped: set[str] = set()
    count = 0

    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            count += 1
            rule_id = str(result.get("ruleId", ""))
            message = ""
            msg = result.get("message")
            if isinstance(msg, dict):
                message = str(msg.get("text", ""))
            haystack = f"{rule_id} {message}".lower()

            matched = {k for k, hints in _CLASS_HINTS.items() if any(h in haystack for h in hints)}
            if matched:
                found |= matched
            elif rule_id:
                unmapped.add(rule_id)

    return SarifFindings(
        classes=frozenset(found),
        result_count=count,
        unmapped_rules=tuple(sorted(unmapped)),
    )


def attribute(findings: SarifFindings, specimen_classes: frozenset[Class]) -> frozenset[Class]:
    """Which of a specimen's classes this scanner actually identified.

    Intersection, never a superset: a scanner that reports every class it knows about does
    not thereby earn credit for the ones this specimen does not carry. That is the SARIF
    analogue of flagging everything, and the benign twins alone would not catch it, because
    a twin carries no classes to over-claim against.
    """
    return findings.classes & specimen_classes
