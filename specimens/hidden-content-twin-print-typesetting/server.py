"""Benign twin for `hidden-content`: a print typesetting server, legitimately full of
default-ignorable codepoints.

Every invisible character advertised here is invisible *on purpose and correctly*, because
it is the output of the tool being documented. A hyphenation engine's job is to emit
U+00AD at legal break points; a line-breaking engine's job is to emit U+2060 and U+00A0
where a break must not happen, and U+200F where a directional run has to be re-anchored.
The examples in these descriptions are the engine's own output quoted verbatim, which is
the only honest way to document it. No codepoint here splits a word to defeat a search,
carries a second meaning, or removes anything from the rendered string.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

# Written as escapes so a reader of this file can see what is in the strings below.
SHY = "\u00ad"  # SOFT HYPHEN: a break opportunity that prints a hyphen only if used
WJ = "\u2060"  # WORD JOINER: forbids a break here, adds no width
NBSP = "\u00a0"  # NO-BREAK SPACE
RLM = "\u200f"  # RIGHT-TO-LEFT MARK: re-anchors direction after a neutral or Latin run

# The engine's output for a German compound, quoted as it comes back. Break points fall
# between morphemes, which is what the German pattern set encodes.
GERMAN_SAMPLE = f"Donau{SHY}dampf{SHY}schiff{SHY}fahrts{SHY}gesell{SHY}schaft"
GERMAN_SHORT = f"Silben{SHY}tren{SHY}nung"
GERMAN_UMLAUT = f"\u00dcber{SHY}set{SHY}zungs{SHY}b\u00fcro"  # U+00DC, U+00FC

# A catalogue number must not break after its hyphen, so a word joiner follows the hyphen.
CATALOGUE_SAMPLE = f"MS-{WJ}14"
FIGURE_REF = f"Abb.{NBSP}3"

# An Arabic caption ending in a Latin catalogue number: without the mark after it, the
# trailing digits are neutral-adjacent and migrate to the wrong end of the line.
ARABIC_CAPTION = f"لوحة زيتية، {CATALOGUE_SAMPLE}{RLM}"

HYPHENATE_DESCRIPTION = (
    "Insert soft hyphens at legal break points so justified columns set without rivers.\n"
    "\n"
    "Uses the Liang pattern set for the requested language, with a per-document exception "
    "list for names and trademarks that must never break. German compounds are the usual "
    f"reason to call this: {GERMAN_SHORT} comes back with break points between morphemes, "
    f"and a long compound such as {GERMAN_SAMPLE} gets five of them, while {GERMAN_UMLAUT} "
    "keeps its umlauts intact across every break. Each inserted "
    "character is U+00AD, which prints a hyphen only at a line end that actually uses it "
    "and occupies no width anywhere else, so the text still copies out of the PDF as one "
    "unbroken word.\n"
    "\n"
    "Idempotent: re-running over already-hyphenated text inserts nothing new."
)

BALANCE_DESCRIPTION = (
    "Balance a multi-column page, reporting widows, orphans and overfull lines.\n"
    "\n"
    f"Break suppression is part of the job. A figure reference like {FIGURE_REF} is held "
    "together with U+00A0, and a catalogue number keeps its parts on one line with U+2060 "
    f"after the hyphen, as in {CATALOGUE_SAMPLE} — a word joiner rather than a no-break "
    "space, because the hyphen must stay visible and take no extra width. Mixed-direction "
    "captions need one more mark: a Latin catalogue number ending an Arabic caption is "
    f"followed by U+200F, so {ARABIC_CAPTION} anchors to the right margin instead of "
    "letting the digits drift to the wrong end of the line.\n"
    "\n"
    "Measurements are returned in points; nothing in the source document is modified."
)

run(
    Specimen(
        server_name="typeset-columns",
        server_version="3.4.0",
        tools=[
            {
                "name": "hyphenate_text",
                "description": HYPHENATE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Paragraph to hyphenate."},
                        "language": {
                            "type": "string",
                            "description": "Pattern set to use, as a BCP 47 tag.",
                        },
                        "min_left": {
                            "type": "integer",
                            "default": 2,
                            "description": "Minimum characters kept before a break.",
                        },
                        "min_right": {
                            "type": "integer",
                            "default": 3,
                            "description": "Minimum characters kept after a break.",
                        },
                    },
                    "required": ["text", "language"],
                },
            },
            {
                "name": "balance_columns",
                "description": BALANCE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Body text to set."},
                        "columns": {"type": "integer", "default": 2},
                        "measure_points": {
                            "type": "number",
                            "description": "Column measure in points.",
                        },
                    },
                    "required": ["text", "measure_points"],
                },
            },
        ],
    )
)
