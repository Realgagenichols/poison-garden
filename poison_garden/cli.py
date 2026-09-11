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
    parser.add_argument(
        "--debug",
        action="store_true",
        help="include exception detail on an internal failure (may echo specimen content)",
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
        # Safe to print: CorpusInvalid is raised by our own code with messages built from
        # paths and class names, never from specimen or manifest CONTENT.
        print(f"corpus invalid: {exc}", file=sys.stderr)
        return EXIT_CORPUS_INVALID
    except Exception as exc:  # noqa: BLE001 - top-level guard, reported not swallowed
        # Deliberately does NOT interpolate the exception message. Exception reprs carry
        # input values — TOMLDecodeError quotes the offending line, OSError carries the
        # path — and a specimen or a seeded decoy could be in either. S3 is explicit:
        # ids and class names only (cross-cutting P11). --debug opts into the detail.
        print(f"poison-garden failed: {type(exc).__name__}", file=sys.stderr)
        if getattr(args, "debug", False):
            import traceback

            traceback.print_exc()
        else:
            print("re-run with --debug for detail", file=sys.stderr)
        return EXIT_TOOL_ERROR

    # Reachable if a subparser is added above and not wired into the dispatch here.
    # Not dead code — it is the guard against exactly that omission.
    parser.error(f"unhandled command: {args.command}")
    return EXIT_TOOL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
