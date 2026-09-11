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
import re
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
    return "\n".join(p.read_text(encoding="utf-8") for p in found), found


def gather_specimens(specimens_root: Path) -> list[tuple[str, str]]:
    """(specimen id, concatenated source+manifest) for every shipped specimen."""
    out: list[tuple[str, str]] = []
    for directory in sorted(specimens_root.iterdir()):
        if not directory.is_dir() or directory.name.startswith(("_", ".")):
            continue
        text_parts = [
            path.read_text(encoding="utf-8")
            for path in sorted(directory.rglob("*"))
            if path.is_file() and path.suffix in {".py", ".toml"}
        ]
        if text_parts:
            out.append((directory.name, "\n".join(text_parts)))
    return out


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
