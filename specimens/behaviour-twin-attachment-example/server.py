"""An attachment service whose schema is full of base64 — every byte of it legitimately.

The tool takes an image as base64, because that is how you put bytes through JSON. So its
schema carries a base64 `example` (a real 1x1 PNG) and a base64 `default` (the packed
encoding profile the service applies when the caller does not override it). The catalog
therefore looks exactly like `behaviour-exfil-schema-default` and is entirely honest: the
opaque strings are the tool's own documentation of its own input format.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _base import Specimen, run  # noqa: E402

# A real 1x1 RGBA PNG: a single half-opaque green pixel, RGBA(0, 255, 0, 127). Chunks are
# IHDR/IDAT/IEND only — no tEXt, zTXt, iTXt or eXIf, so there is nowhere for a payload to
# sit, and the 5 bytes of pixel data carry none. Documenting the accepted format with a
# working sample is better documentation than describing it in prose.
#
# This said "transparent" until a decode showed alpha 127, not 0. The blob was always
# harmless, but this twin's entire defence is that its embedded values are honest and
# inspectable — a reviewer who decodes one and finds the prose wrong has fair reason to
# doubt the rest. Describing the bytes is exact; swapping them to match the old sentence
# would have risked a real error to fix a wrong word.
SAMPLE_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# base64 of {"dpi":150,"colour":"srgb","strip_exif":true,"max_edge":4096} — the profile the
# service applies when `profile` is omitted. Shipped as the literal default so a caller can
# decode it, edit one field, and send it back.
DEFAULT_PROFILE_B64 = (
    "eyJkcGkiOjE1MCwiY29sb3VyIjoic3JnYiIsInN0cmlwX2V4aWYiOnRydWUsIm1heF9lZGdlIjo0MDk2fQ=="
)

run(
    Specimen(
        server_name="attachments",
        server_version="2.6.1",
        tools=[
            {
                "name": "upload_image",
                "description": (
                    "Upload an image and return a handle. The image is passed as base64; "
                    "the example below is a 1x1 RGBA PNG — one half-opaque green pixel — which "
                    "you can send verbatim to "
                    "check your wiring."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string"},
                        "content_base64": {
                            "type": "string",
                            "description": "Image bytes, base64-encoded.",
                            "examples": [SAMPLE_PNG_B64],
                        },
                        "profile": {
                            "type": "string",
                            "description": (
                                "Packed encoding profile, base64 of a JSON object. Decode "
                                "the default, change what you need, re-encode."
                            ),
                            "default": DEFAULT_PROFILE_B64,
                        },
                    },
                    "required": ["filename", "content_base64"],
                },
            },
            {
                "name": "get_image_metadata",
                "description": "Return dimensions and MIME type for a stored image.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"handle": {"type": "string"}},
                    "required": ["handle"],
                },
            },
        ],
    )
)
