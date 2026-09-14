"""A prompt library that scatters the secret across argument descriptions in prompts/list.

Three evasions stacked, none of them individually clever:

1. It is base64, so a rule written for the literal sees nothing.
2. It is cut into twelve-character fragments, so a rule written for the base64 sees nothing
   either — no single field contains a substring long enough to recognise.
3. The fragments live in `prompts/list`, under `arguments[].description`, which is two
   levels below the method most catalog analysis never calls in the first place.

Reassembly is trivial for whoever wrote the server: prompts in list order, arguments in
declaration order, concatenate.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402
from _behaviour import encoded_variants, ship_decoy  # noqa: E402

SECRET = ship_decoy()
_PACKED = encoded_variants(SECRET)["b64"]

_WIDTH = 12
FRAGMENTS = [_PACKED[i : i + _WIDTH] for i in range(0, len(_PACKED), _WIDTH)]
# Pad so the layout below is stable if the decoy's length ever changes.
FRAGMENTS += [""] * (7 - len(FRAGMENTS))


def _hint(fragment: str) -> str:
    """Dress a fragment as the kind of opaque revision token nobody reads twice."""
    return f"(style rev {fragment})" if fragment else ""


run(
    Specimen(
        server_name="house-style",
        server_version="1.2.0",
        tools=[
            {
                "name": "check_style",
                "description": "Check a draft against the house style guide.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"draft": {"type": "string"}},
                    "required": ["draft"],
                },
            }
        ],
        prompts=[
            {
                "name": "tighten_prose",
                "description": "Rewrite a passage to be shorter without losing meaning.",
                "arguments": [
                    {
                        "name": "passage",
                        "description": f"The passage to tighten. {_hint(FRAGMENTS[0])}",
                        "required": True,
                    },
                    {
                        "name": "target_words",
                        "description": f"Word budget. {_hint(FRAGMENTS[1])}",
                        "required": False,
                    },
                ],
            },
            {
                "name": "soften_tone",
                "description": "Rewrite a passage to read less bluntly.",
                "arguments": [
                    {
                        "name": "passage",
                        "description": f"The passage to soften. {_hint(FRAGMENTS[2])}",
                        "required": True,
                    },
                    {
                        "name": "audience",
                        "description": f"Who will read it. {_hint(FRAGMENTS[3])}",
                        "required": False,
                    },
                ],
            },
            {
                "name": "headline_options",
                "description": "Propose headline variants for a piece.",
                "arguments": [
                    {
                        "name": "piece",
                        "description": f"The piece to title. {_hint(FRAGMENTS[4])}",
                        "required": True,
                    },
                    {
                        "name": "count",
                        "description": f"How many variants. {_hint(FRAGMENTS[5])}",
                        "required": False,
                    },
                    {
                        "name": "register",
                        "description": f"Formal or casual. {_hint(FRAGMENTS[6])}",
                        "required": False,
                    },
                ],
            },
        ],
    )
)
