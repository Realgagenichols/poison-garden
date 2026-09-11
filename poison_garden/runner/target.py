"""Scanner invocation — R5.

The scanner is supplied by the user as a command template containing `{target}`. We never
bundle, vendor, or special-case a scanner: that is the founding constraint (see CLAUDE.md).

`{target}` expands to the argv needed to launch one specimen, which is more than one
element — an interpreter plus a script path. So the template is `shlex.split` into argv
parts first and the placeholder is expanded *in place*, producing a flat argv list. The
command is then executed with `shell=False`.

Two consequences worth stating, because both are load-bearing:

- **No shell.** A specimen path containing a space, a quote, or a `$` is passed as one argv
  element rather than re-parsed by `sh`. Nothing the corpus contains can influence the
  command that runs (cross-cutting P4).
- **No pipeline.** The caller reads the exit status of the scanner process directly. Piping
  it would report the *last* process's status, and since the verdict IS the exit code,
  every verdict would silently become `clean` (cross-cutting P10).
"""

from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from poison_garden.corpus.models import Specimen

PLACEHOLDER = "{target}"


class ScannerTemplateError(ValueError):
    """The scanner command template is unusable."""


@dataclass(frozen=True)
class ScannerCommand:
    """A parsed scanner template, ready to be specialised per specimen.

    `parts` is `repr=False` and the original template string is NOT retained. The CLI's own
    help text warns that a template may contain an API key, and `--debug` prints tracebacks;
    a dataclass repr in a traceback frame would have published it. `sandbox.py` applies the
    same treatment to the decoy canaries and exfiltrated payloads, for the same reason (S3).
    """

    parts: tuple[str, ...] = field(repr=False)

    @property
    def program(self) -> str:
        return self.parts[0]

    def argv_for(self, specimen: Specimen, python: str | None = None) -> list[str]:
        """Flat argv for scanning one specimen, with `{target}` expanded in place."""
        target = target_argv(specimen, python=python)
        out: list[str] = []
        for part in self.parts:
            if part == PLACEHOLDER:
                out.extend(target)
            elif PLACEHOLDER in part:
                # Embedded in a larger token (e.g. `--server={target}`): join with spaces
                # rather than silently dropping the extra elements.
                out.append(part.replace(PLACEHOLDER, " ".join(target)))
            else:
                out.append(part)
        return out


def parse_scanner(template: str) -> ScannerCommand:
    """Parse and validate a scanner command template.

    A template without `{target}` is refused rather than run. Running it would invoke the
    scanner once per specimen against nothing at all, and every specimen would come back
    with whatever that produced — a full set of verdicts describing no specimen.
    """
    if not template or not template.strip():
        raise ScannerTemplateError("scanner template is empty")

    try:
        parts = shlex.split(template)
    except ValueError as exc:
        raise ScannerTemplateError(
            f"scanner template is not parseable as a command ({type(exc).__name__}); "
            "check for an unbalanced quote"
        ) from exc

    if not parts:
        raise ScannerTemplateError("scanner template parsed to no command")

    if not any(PLACEHOLDER in part for part in parts):
        # The template is NOT echoed. It is the one user-supplied string the CLI's own
        # help text warns may carry an API key, and this message reaches stderr and any
        # CI log. Naming the program is enough to locate the mistake (S3, P11).
        raise ScannerTemplateError(
            f"scanner template for {parts[0]!r} contains no {PLACEHOLDER} placeholder. "
            "Without it the scanner would be run once per specimen against nothing, "
            "producing a full set of verdicts that describe no specimen at all."
        )

    return ScannerCommand(parts=tuple(parts))


def target_argv(specimen: Specimen, python: str | None = None) -> list[str]:
    """The argv that launches one specimen as a stdio MCP server.

    A specimen is a program (R1), so the target a scanner receives is a command, not a URL
    or a file of definitions.
    """
    interpreter = python or sys.executable
    return [interpreter, str(Path(specimen.entrypoint_path).resolve())]
