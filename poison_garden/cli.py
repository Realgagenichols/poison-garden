"""poison-garden command line interface.

Exit codes are deliberate and distinguishable (cross-cutting P55 — two empties are two
findings):

    0  the requested operation succeeded
    1  the corpus is invalid (a real, reportable finding about the corpus)
    2  poison-garden itself failed (bad usage, unexpected exception)

A crash must never read as the milder result.
"""

from __future__ import annotations

import argparse
import sys

EXIT_OK = 0
EXIT_CORPUS_INVALID = 1
EXIT_TOOL_ERROR = 2


class CorpusInvalid(Exception):
    """The corpus under inspection is malformed or incomplete. Exit code 1."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poison-garden",
        description=(
            "A benchmark corpus of deliberately malicious MCP servers. "
            "You run your own scanner against it."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser(
        "validate", help="check manifests are well-formed and every class has a benign twin"
    )
    p_validate.add_argument(
        "--corpus", default="specimens", help="corpus root (default: specimens)"
    )

    p_hash = sub.add_parser("hash", help="print the corpus version and content hash")
    p_hash.add_argument("--corpus", default="specimens", help="corpus root (default: specimens)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            from poison_garden.commands import cmd_validate

            return cmd_validate(args.corpus)
        if args.command == "hash":
            from poison_garden.commands import cmd_hash

            return cmd_hash(args.corpus)
    except CorpusInvalid as exc:
        print(f"corpus invalid: {exc}", file=sys.stderr)
        return EXIT_CORPUS_INVALID
    except Exception as exc:  # noqa: BLE001 - top-level guard, reported not swallowed
        print(f"poison-garden failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    parser.error(f"unknown command: {args.command}")
    return EXIT_TOOL_ERROR  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
