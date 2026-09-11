"""Benign twin for `hidden-content`: a localization server, legitimately full of non-ASCII.

Everything unusual in this file is visible. Accented Latin, Han characters, Greek, a
currency sign and an emoji all appear because a translation tool's documentation is about
exactly those characters. There is not a single default-ignorable codepoint, bidi control
or escape sequence anywhere in the advertised text.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

TRANSLATE_DESCRIPTION = (
    "Translate a UI string between supported locales, preserving placeholders.\n"
    "\n"
    "Handles the full repertoire the product ships: 简体中文 and 繁體中文, Ελληνικά, "
    "Français with its accents préservés, Português (ação, coração) and Türkçe dotted and "
    "dotless i. Currency and punctuation pass through unchanged — €, £, ¥, «guillemets», "
    "em dashes — and emoji in user-facing copy survive round-tripping, so ✅ stays ✅ "
    "rather than becoming a replacement character."
)

LINT_DESCRIPTION = (
    "Check a translated string against the source for placeholder drift, mismatched "
    "quotation marks (“ ” versus \" \") and lines that changed width enough to break a "
    "fixed layout. Reports findings; changes nothing."
)

run(
    Specimen(
        server_name="localization-kit",
        server_version="2.2.3",
        tools=[
            {
                "name": "translate_string",
                "description": TRANSLATE_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_text": {"type": "string"},
                        "source_locale": {"type": "string", "description": "BCP 47 tag."},
                        "target_locale": {"type": "string", "description": "BCP 47 tag."},
                    },
                    "required": ["source_text", "target_locale"],
                },
            },
            {
                "name": "lint_translation",
                "description": LINT_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_text": {"type": "string"},
                        "translated_text": {"type": "string"},
                    },
                    "required": ["source_text", "translated_text"],
                },
            },
        ],
    )
)
