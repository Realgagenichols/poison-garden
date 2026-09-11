"""N2 release gate: the KNOWN-MISSES register must hold at least three entries.

N2 binds at **release**, not at merge — M1 delivers declaration classes, which is frisk's
strongest ground, so the register legitimately fills up over M2/M3. But "binds at release"
only means something if something checks at release. Without this, `KNOWN-MISSES.md` could
drop to zero rows and nothing anywhere would notice, which turns the project's central
honesty commitment into a promise in prose.

    uv run python scripts/check_known_misses.py [--min 3]

Exits non-zero if the register is short, so a release tag fails rather than shipping a
corpus its author's own scanner aces.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = REPO_ROOT / "KNOWN-MISSES.md"
MIN_ENTRIES = 3

# A row in the misses table: | `specimen-id` | class | verdict | rationale |
_ROW = re.compile(r"^\|\s*`([a-z0-9-]+)`\s*\|", re.MULTILINE)


def count_entries(text: str) -> list[str]:
    """Specimen ids registered as misses.

    Only rows inside the "three misses" table count. A row must name a real specimen id in
    backticks, so a placeholder line or a prose mention cannot inflate the count.
    """
    return _ROW.findall(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min", type=int, default=MIN_ENTRIES)
    parser.add_argument("--corpus", type=Path, default=REPO_ROOT / "specimens")
    args = parser.parse_args()

    if not REGISTER.is_file():
        print(f"{REGISTER} is missing — N2 has no register", file=sys.stderr)
        return 1

    entries = count_entries(REGISTER.read_text(encoding="utf-8"))
    print(f"KNOWN-MISSES registers {len(entries)} specimen(s): {sorted(entries)}")

    if len(entries) < args.min:
        print(
            f"\nN2 FAILED: the register holds {len(entries)} entries, minimum {args.min}.\n"
            "A release must ship at least three specimens that frisk does not flag. If frisk "
            "has since fixed a miss, strike that row AND add new specimens — do not relax the "
            "requirement. A benchmark its author's own scanner aces is a marketing asset, not "
            "a measurement.",
            file=sys.stderr,
        )
        return 1

    # Every registered id must be a real specimen. A register naming specimens that no
    # longer exist would satisfy the count while measuring nothing (P59 — derive the
    # population from the artifact, and guard against vacuity).
    if args.corpus.is_dir():
        present = {
            d.name
            for d in args.corpus.iterdir()
            if d.is_dir() and not d.name.startswith(("_", "."))
        }
        phantom = sorted(set(entries) - present)
        if phantom:
            print(
                f"\nN2 FAILED: register names specimen(s) not in the corpus: {phantom}. "
                "A register of specimens that no longer exist passes the count while "
                "measuring nothing.",
                file=sys.stderr,
            )
            return 1

    print(f"N2 OK: {len(entries)} registered misses, all present in the corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
