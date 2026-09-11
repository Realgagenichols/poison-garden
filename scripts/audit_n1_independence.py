"""N1 audit: prove the corpus was not derived from frisk's detector fixtures.

Run manually, not in CI. It needs a checkout of a *different* repo, so as a pytest test it
would either fail everywhere frisk is absent or — worse — skip silently and look like a
pass. An authorship check is a one-time measurement anyway, not a regression guard: record
its output in `tasks/lessons.md` when a corpus release is cut.

    uv run python scripts/audit_n1_independence.py [--frisk PATH]

Exits non-zero if any specimen shares a long phrase with frisk's fixtures.

Why this matters (cross-cutting P35): a corpus authored from a scanner's own test fixtures
cannot measure that scanner. It would only demonstrate that the scanner matches its own
regexes. N1 is the rule; this script is the evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FRISK = REPO_ROOT.parent / "frisk"

# A shared run of this many normalised words is treated as copied rather than coincidental.
# Six is long enough that ordinary security vocabulary ("read the file and pass it as")
# does not trip it, short enough to catch a lightly-reworded lift.
NGRAM = 6

_WORD = re.compile(r"[a-z0-9_]+")


def normalise(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def ngrams(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def gather_frisk_corpus(frisk_root: Path) -> tuple[str, list[Path]]:
    """Concatenate frisk's fixture sources — the thing we must NOT have copied."""
    candidates = [
        frisk_root / "tests" / "fixtures" / "definitions.py",
        frisk_root / "tests" / "fixtures" / "mcp_server.py",
    ]
    found = [p for p in candidates if p.is_file()]
    # Extract only STRING LITERALS from frisk's fixtures. Comparing whole source files
    # would match shared Python scaffolding rather than shared payload.
    literal = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    chunks: list[str] = []
    for path in found:
        chunks.extend(literal.findall(path.read_text(encoding="utf-8")))
    return "\n".join(chunks), found


def _strings_from(node: object) -> list[str]:
    """Every string anywhere in a nested JSON structure."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        out: list[str] = []
        for key, value in node.items():
            # Author-chosen keys are model-visible prose; JSON Schema's own vocabulary is
            # not. Excluding structural keywords is what keeps this measuring payload
            # rather than scaffolding.
            if key not in _SCHEMA_KEYWORDS:
                out.append(key)
            out.extend(_strings_from(value))
        return out
    if isinstance(node, list):
        return [s for item in node for s in _strings_from(item)]
    return []


# JSON Schema structural vocabulary. Two unrelated servers both saying "type": "string"
# is not evidence of anything.
_SCHEMA_KEYWORDS = frozenset(
    {
        "type", "properties", "required", "items", "enum", "format", "default",
        "additionalProperties", "minimum", "maximum", "minLength", "maxLength",
        "pattern", "description", "title", "inputSchema", "name", "anyOf", "oneOf",
    }
)

# Descriptions whose wording is effectively forced by the parameter they document. Two
# independent authors writing a `command` parameter will both reach for "the shell command
# to run"; treating that as copying would make the audit unpassable rather than rigorous.
#
# Every entry must EARN its place: `_check_exemptions_are_live()` asserts each phrase
# actually appears in frisk's fixtures. An exemption for a collision that does not exist is
# a pre-authorization for future specimens with no record of what motivated it, and it
# silently widens the audit's blind spot over time (P51/P76).
_FORCED_PHRASINGS = frozenset(
    {
        "the shell command to run",
        "shell command used to fetch data",
        "contents of the process environment variables",
    }
)


def _check_exemptions_are_live(frisk_text: str) -> list[str]:
    """Return exemptions that no longer correspond to anything in frisk's fixtures."""
    haystack = " ".join(normalise(frisk_text))
    return sorted(
        phrase
        for phrase in _FORCED_PHRASINGS
        if " ".join(normalise(phrase)) not in haystack
    )


def gather_specimens(specimens_root: Path) -> list[tuple[str, str]]:
    """(specimen id, advertised strings) — the PAYLOAD, not the source scaffolding.

    Runs each specimen and reads its served catalog, because that is what a scanner sees
    and therefore what N1 is a claim about. Comparing source files instead measures shared
    Python boilerplate (`import sys`, `from pathlib import Path`) and JSON Schema
    structure, which every MCP server on earth has in common (cross-cutting P86 — a number
    can be measured and still be about the wrong object).

    The population comes from `load_corpus()`, not from globbing for `server.py`. A
    specimen may legitimately declare a subdirectory entrypoint, and hardcoding the
    filename meant any such specimen was silently skipped while the audit still printed
    "N1 OK" over a quietly smaller denominator — the same silent-shrink failure the loader
    refuses on principle (P84: ask what an item must DO to appear in the output).
    """
    from poison_garden.corpus.loader import load_corpus

    corpus = load_corpus(specimens_root)
    out: list[tuple[str, str]] = []

    for specimen in corpus.specimens:
        try:
            served = _serve_catalog(specimen.entrypoint_path)
        except Exception as exc:
            # Never skip. A specimen the audit cannot run is an audit that cannot make a
            # claim about this corpus.
            raise RuntimeError(
                f"{specimen.id}: could not enumerate ({type(exc).__name__}). "
                "Refusing to report an N1 result over a partial corpus."
            ) from exc

        strings = _strings_from(served)

        # Every shipped file's text counts as authored content, not just the entrypoint:
        # manifests carry `summary` and `notes`, which is prose a human wrote.
        for path in specimen.files():
            if path.suffix in {".toml", ".md", ".txt", ".json"}:
                strings.append(path.read_text(encoding="utf-8", errors="replace"))

        text = "\n".join(strings)
        for forced in _FORCED_PHRASINGS:
            text = text.replace(forced, " ")
        out.append((specimen.id, text))

    return out


def _serve_catalog(entrypoint: Path) -> object:
    """Drive a handshake and return the specimen's tools/list result."""
    stdin_text = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "audit"}},
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
    )
    proc = subprocess.run(
        [sys.executable, str(entrypoint)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=30,
    )
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        message = json.loads(line)
        if message.get("id") == 2:
            return message.get("result", {})
    raise RuntimeError(f"{entrypoint}: no tools/list response; cannot audit what it serves")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frisk", type=Path, default=DEFAULT_FRISK)
    parser.add_argument("--ngram", type=int, default=NGRAM)
    args = parser.parse_args()

    if not args.frisk.is_dir():
        print(
            f"frisk checkout not found at {args.frisk}. This audit needs it to compare "
            "against; it cannot report a pass without having looked.",
            file=sys.stderr,
        )
        return 2

    frisk_text, frisk_files = gather_frisk_corpus(args.frisk)
    if not frisk_files:
        print(f"no frisk fixture files found under {args.frisk}", file=sys.stderr)
        return 2

    specimens = gather_specimens(REPO_ROOT / "specimens")
    if not specimens:
        print("no specimens found — nothing to audit (this is a vacuous pass)", file=sys.stderr)
        return 2

    stale = _check_exemptions_are_live(frisk_text)
    if stale:
        print(
            f"\nSTALE EXEMPTION(S): {stale}\n"
            "These phrases are exempted from the comparison but appear nowhere in frisk's "
            "fixtures, so they exempt nothing today and pre-authorize future specimens "
            "for a collision that does not exist. Remove them.",
            file=sys.stderr,
        )
        return 1

    frisk_ngrams = ngrams(normalise(frisk_text), args.ngram)
    print(
        f"comparing {len(specimens)} specimen(s) "
        f"against {len(frisk_files)} frisk fixture file(s)"
    )
    print(f"frisk {args.ngram}-gram population: {len(frisk_ngrams)}")

    offenders: list[tuple[str, tuple[str, ...]]] = []
    for specimen_id, text in specimens:
        shared = ngrams(normalise(text), args.ngram) & frisk_ngrams
        status = "clean" if not shared else f"{len(shared)} shared phrase(s)"
        print(f"  {specimen_id:<34} {status}")
        offenders.extend((specimen_id, phrase) for phrase in sorted(shared))

    if offenders:
        print(f"\nN1 VIOLATION: {len(offenders)} shared phrase(s) with frisk fixtures:")
        for specimen_id, phrase in offenders:
            print(f"  {specimen_id}: {' '.join(phrase)!r}")
        return 1

    print("\nN1 OK: no shared phrase of length >= " f"{args.ngram} between any specimen and frisk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
