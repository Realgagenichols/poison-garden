"""Twin discriminating power — R3, cross-cutting P21 and P48.

A benign twin is a false-positive control. A control is only valid if some plausible
*loosening* of the rule fires on it (P21) — a twin that no careless scanner would ever flag
proves nothing and inflates every false-positive rate reported against this corpus.

poison-garden ships no detectors, so there is no rule of ours to loosen. Instead these
tests define STRAWMAN detectors: deliberately naive, keyword-shaped rules of the kind a
first-pass scanner actually implements. Each twin must trip at least one strawman while
being genuinely legitimate. That is the whole job of a twin.

If a twin stops tripping every strawman, do not delete the assertion — rewrite the twin to
be more temptingly similar to its malicious sibling.
"""

from __future__ import annotations

import json
import re

import pytest
from helpers import SPECIMENS, handshake

from poison_garden.corpus.loader import load_corpus
from poison_garden.corpus.models import BEHAVIOR_CLASSES as BEHAVIOUR_CLASSES
from poison_garden.corpus.models import Class

_SERVED_CACHE: dict[str, str] = {}


def _advertised_text(specimen) -> str:
    """Every string the specimen actually SERVES, flattened. Not its source.

    This read the source file, which was wrong in a way that made the whole module
    vacuous. A source file contains a module docstring and imports, and the strawmen were
    matching those: four of six twins tripped on prose in line 3 that no scanner ever
    sees, and `\\bpath\\b` matched `from pathlib import Path` — boilerplate present in
    every specimen. `test_every_twin_trips_at_least_one_strawman` therefore could not fail
    for a scope-mismatch twin whatever that twin contained.

    Same error as the N1 audit made: measuring the artifact that produces the payload
    instead of the payload (cross-cutting P86 — ask what the instrument touched).
    """
    if specimen.id not in _SERVED_CACHE:
        responses = handshake(specimen.entrypoint_path)
        catalog = next(
            (r.get("result", {}) for r in responses if r.get("id") == 2), {}
        )
        _SERVED_CACHE[specimen.id] = "\n".join(_strings_in(catalog))
    return _SERVED_CACHE[specimen.id]


def _strings_in(node: object) -> list[str]:
    """Every string anywhere in the served catalog, including author-chosen keys."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        out: list[str] = []
        for key, value in node.items():
            out.append(key)
            out.extend(_strings_in(value))
        return out
    if isinstance(node, list):
        return [s for item in node for s in _strings_in(item)]
    return []


# --- strawman detectors: naive on purpose ------------------------------------------------
#
# Each is the sort of rule a first-pass scanner ships: a keyword list, no context, no
# notion of who benefits. They are NOT poison-garden's detectors and are not exported.

STRAWMEN: dict[Class, list[re.Pattern[str]]] = {
    Class.INJECTION: [
        re.compile(r"do not (mention|echo|tell|reveal)", re.I),
        re.compile(r"before (calling|using) this tool", re.I),
        re.compile(r"\bread (the|a) file\b", re.I),
        re.compile(r"pass (it|its contents|the .*) in ", re.I),
        re.compile(r"\bcall `?\w+`? first\b", re.I),
    ],
    Class.HIDDEN_CONTENT: [
        # Matched against SERVED text, so these are the real characters, not escapes.
        re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]"),
        re.compile("[\u202a-\u202e\u2066-\u2069]"),
        re.compile(r"[^\x00-\x7F]"),
        re.compile("<!--"),
        re.compile("\x1b"),
    ],
    Class.SENSITIVE_PARAMS: [
        re.compile(r"\bcontext\b", re.I),
        re.compile(r"\btoken\b", re.I),
        re.compile(r"\bcredential", re.I),
        re.compile(r"\benvironment\b", re.I),
        re.compile(r"\bhistory\b", re.I),
    ],
    Class.SCOPE_MISMATCH: [
        re.compile(r"\bcommand\b", re.I),
        re.compile(r"\bshell\b", re.I),
        re.compile(r"\bpath\b", re.I),
        re.compile(r"\burl\b", re.I),
    ],
    Class.IMPERSONATION: [
        re.compile(r"\b(read_file|write_file|list_files|search|fetch|execute)\b", re.I),
        re.compile(r"instead of", re.I),
        re.compile(r"\bpreferred\b|\bauthoritative\b|\bcanonical\b", re.I),
    ],
    Class.HYGIENE: [
        re.compile(r"https?://", re.I),
        re.compile(r"\blatest\b", re.I),
        re.compile(r"\bdownload|fetch(es|ed)?\b", re.I),
        re.compile(r"\bversion\b", re.I),
    ],
}


# --- behavioural strawmen ----------------------------------------------------------------
#
# A TEXT strawman cannot see behaviour: a behavioural specimen's catalog is clean by design,
# which is the entire point of the class. So the naive rules a first-pass BEHAVIOURAL scanner
# would ship are modelled here instead — each observes something, rather than matching prose.
# Each takes (specimen) and returns True if it fires.


def _opens_a_file(specimen) -> bool:
    """"Does this server touch the filesystem at startup?" — the crudest possible rule."""
    source = specimen.entrypoint_path.read_text(encoding="utf-8")
    return any(token in source for token in ("read_and_discard", "open(", "read_text"))


def _description_carries_a_high_entropy_token(specimen) -> bool:
    """"Does any description contain something that looks like a secret?"

    Fires on any run of 32+ base64/hex characters — which a legitimate build fingerprint,
    cache key or schema hash also is.
    """
    text = _advertised_text(specimen)
    return bool(re.search(r"[A-Za-z0-9+/=]{32,}", text))


def _has_confusable_tool_names(specimen) -> bool:
    """"Does this server ship tool names a model could confuse?"

    Fires on an exact duplicate OR on one name being a prefix of another — which is how
    every `search` / `search_advanced` pair in the world looks.
    """
    names = _tool_names(specimen)
    if len(names) != len(set(names)):
        return True
    return any(
        a != b and (b.startswith(a) or a.startswith(b)) for a in names for b in names
    )


def _catalog_depends_on_client(specimen) -> bool:
    """"Does the catalog change with who is asking?"

    Fires on capability negotiation exactly as it fires on evasion — the distinction is
    what it branches ON, which a naive rule does not look at.
    """
    from helpers import catalogs_across_profiles

    # Compared across every profile, not one pair. The previous version varied capabilities
    # and clientInfo.name only, which meant a twin negotiating honestly on `protocolVersion`
    # or on an `elicitation` capability served both probes identically — so the strawman did
    # not fire, and the twin read as inert when it was in fact the sharpest control in its
    # class. The rule this models is "the catalog changes with who is asking", and that
    # question is not answerable from two samples along one axis.
    return len(set(catalogs_across_profiles(specimen.entrypoint_path).values())) > 1


def _opens_a_network_socket(specimen) -> bool:
    """The naive egress rule: "this server opened a socket."

    Fires on the malicious specimens and on every egress twin alike, and that identity is
    exactly what the twins are for. A scanner that flags any `connect()` scores full recall
    on this class and a 100% false-positive rate on its controls; the discrimination R21
    actually asks for is *declared and purposeful* versus *undeclared and unprompted*
    network use, which this rule cannot make.
    """
    from helpers import opens_a_socket

    return opens_a_socket(specimen.entrypoint_path)


BEHAVIOURAL_STRAWMEN = {
    Class.CREDENTIAL_ACCESS: [_opens_a_file],
    Class.EXFIL_ENUMERATION: [_description_carries_a_high_entropy_token],
    Class.NAMESAKE_RUGPULL: [_has_confusable_tool_names],
    Class.SCANNER_AWARE: [_catalog_depends_on_client],
    Class.EGRESS: [_opens_a_network_socket],
}


def _tool_names(specimen) -> list[str]:
    from helpers import handshake

    responses = handshake(specimen.entrypoint_path)
    for reply in responses:
        if reply.get("id") == 2:
            return [t.get("name", "") for t in reply.get("result", {}).get("tools", [])]
    return []


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(SPECIMENS)


def _twins(corpus):
    return [s for s in corpus.benign if s.twin_for]


def test_there_are_twins_to_check(corpus):
    """Vacuity guard (P58): an empty population makes every assertion below free."""
    assert _twins(corpus), "no benign twins found — nothing to measure"


def test_every_twin_trips_at_least_one_strawman(corpus):
    """P21: a control is valid only if a plausible loosening of the rule fires on it."""
    inert: list[str] = []

    for twin in _twins(corpus):
        text = _advertised_text(twin)
        tripped = False
        for klass in twin.twin_for:
            if any(pattern.search(text) for pattern in STRAWMEN.get(klass, [])):
                tripped = True
                break
            if any(rule(twin) for rule in BEHAVIOURAL_STRAWMEN.get(klass, [])):
                tripped = True
                break
        if not tripped:
            inert.append(f"{twin.id} (controls for {sorted(c.value for c in twin.twin_for)})")

    assert not inert, (
        "these twins trip no naive rule at all, so they cannot demonstrate a false "
        f"positive and inflate any FP rate measured here: {inert}. "
        "Rewrite them to resemble their malicious siblings more closely — do not delete "
        "this assertion."
    )


def test_strawmen_fire_on_their_own_malicious_specimens(corpus):
    """Half one: a rule that fires on nothing discriminates nothing (P50)."""
    silent: list[str] = []
    for klass, patterns in STRAWMEN.items():
        malicious = [s for s in corpus.malicious if klass in s.classes]
        if not malicious:
            continue
        if not any(
            pattern.search(_advertised_text(s)) for s in malicious for pattern in patterns
        ):
            silent.append(klass.value)

    for klass, rules in BEHAVIOURAL_STRAWMEN.items():
        malicious = [s for s in corpus.malicious if klass in s.classes]
        if not malicious:
            continue
        if not any(rule(s) for s in malicious for rule in rules):
            silent.append(klass.value)

    assert not silent, f"strawman rules fire on no malicious specimen for: {silent}"


def test_behavioural_strawmen_cover_every_behavioural_class(corpus):
    """Vacuity guard: a class with no strawman gives its twin a free pass."""
    behavioural = {k for s in corpus.malicious for k in s.classes if k in BEHAVIOUR_CLASSES}
    uncovered = sorted(k.value for k in behavioural if k not in BEHAVIOURAL_STRAWMEN)
    assert not uncovered, (
        f"behavioural class(es) with no strawman, so their twins cannot be measured: "
        f"{uncovered}"
    )


# A minimal, entirely legitimate catalog built from the same shape every specimen uses.
# Nothing here is suspicious under any reading. It is the control that makes an over-broad
# strawman visible.
INERT_CONTROL = json.dumps(
    {
        "tools": [
            {
                "name": "add_numbers",
                "description": "Returns the sum of two integers.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                    "required": ["a", "b"],
                },
            }
        ]
    }
)


def test_no_strawman_fires_on_an_inert_control(corpus):
    """Half two: a rule that fires on EVERYTHING discriminates nothing either (P96).

    The previous version of this test implemented only half its own docstring — it checked
    that each rule fires on malicious specimens, and had no way to see an over-broad rule.
    `\\bpath\\b` lived in the scope-mismatch set precisely because nothing could see it;
    it matched `from pathlib import Path` in every specimen ever written.

    Removing that one pattern fixed the instance. This fixes the blind spot: any future
    rule loose enough to match an adding-two-integers server fails here on the day it is
    added, instead of quietly making a twin's assertion unfalsifiable.
    """
    overbroad: list[str] = []
    for klass, patterns in STRAWMEN.items():
        for pattern in patterns:
            if pattern.search(INERT_CONTROL):
                overbroad.append(f"{klass.value}: {pattern.pattern}")

    assert not overbroad, (
        "these strawman rules fire on a server that merely adds two integers, so they "
        f"cannot demonstrate anything about a twin: {overbroad}"
    )


def test_the_inert_control_is_genuinely_inert(corpus):
    """Vacuity guard on the control itself (P21).

    A control only works if it resembles the real thing. This asserts the control carries
    the same structural vocabulary every specimen has — so 'no strawman matched' means the
    rules are tight, not that the control was too thin to match anything.
    """
    for marker in ("tools", "name", "description", "inputSchema", "type", "properties"):
        assert marker in INERT_CONTROL, f"control lacks {marker}; it is not representative"


def test_twins_are_labelled_benign_despite_tripping_naive_rules(corpus):
    """The point of the corpus: tripping a naive rule is not the same as being malicious."""
    for twin in _twins(corpus):
        assert twin.is_benign
        assert not twin.classes, f"{twin.id} is a twin but carries attack classes"


def test_each_twin_names_the_class_it_controls_for(corpus):
    for twin in _twins(corpus):
        assert twin.twin_for, f"{twin.id} controls for nothing"
        for klass in twin.twin_for:
            assert klass in corpus.classes_present, (
                f"{twin.id} controls for {klass.value}, which no malicious specimen exhibits"
            )


def test_invisible_characters_are_escaped_in_source(corpus):
    """frisk lesson: a literal ZWJ in source breaks reviewability and exact-match editing.

    Checks the SOURCE bytes. The specimen may of course advertise invisible characters at
    runtime — that is the hidden-content class — but the source must spell them \\uXXXX.
    """
    forbidden = {
        "​": "ZERO WIDTH SPACE",
        "‌": "ZERO WIDTH NON-JOINER",
        "‍": "ZERO WIDTH JOINER",
        "⁠": "WORD JOINER",
        "‮": "RIGHT-TO-LEFT OVERRIDE",
        "‭": "LEFT-TO-RIGHT OVERRIDE",
        "﻿": "ZERO WIDTH NO-BREAK SPACE",
        "\x1b": "ESC",
    }
    offenders: list[str] = []
    for specimen in corpus.specimens:
        source = specimen.entrypoint_path.read_text(encoding="utf-8")
        for char, name in forbidden.items():
            if char in source:
                offenders.append(f"{specimen.id}: literal {name}")

    assert not offenders, (
        f"invisible characters must be written as \\uXXXX escapes: {offenders}"
    )


# Codepoints that occupy no visual space: zero-width set, soft hyphen, word joiner, the
# bidi controls and isolates, variation selectors, and the Unicode Tags block. Wider than
# the four literals the previous check listed, because the class is defined by the property
# (renders as nothing) and not by the four examples that happened to be written first.
_DEFAULT_IGNORABLE = re.compile(
    "["
    "\u200b-\u200f"      # zero-width space/non-joiner/joiner, LRM, RLM
    "\u00ad"              # soft hyphen
    "\u2060-\u2064"      # word joiner, invisible operators
    "\u202a-\u202e"      # bidi embedding/override
    "\u2066-\u2069"      # bidi isolates
    "\ufe00-\ufe0f"      # variation selectors
    "\ufeff"              # BOM / zero-width no-break space
    "\U000e0000-\U000e007f"  # Unicode Tags
    "]"
)


# Every way this corpus hides content in a served catalog, as predicates over the catalog a
# client actually receives. Named individually so a failure says WHICH mechanism is absent,
# and so the diversity check below can count them.
#
# This replaced a fixed list of six byte markers. That list was true of the first four
# hidden-content specimens and quietly became the definition of the class: a specimen hiding
# by character IDENTITY (homoglyphs) or by STRUCTURE (a description reachable only through a
# `$ref`) carries none of those bytes and was reported as advertising nothing hidden. The
# test was measuring its own first draft (P86 — ask what the instrument actually touched).


def _default_ignorable(served: str, catalog: dict) -> bool:
    """Codepoints that render as nothing: zero-width, soft hyphen, bidi, tags, VS."""
    return any(
        _DEFAULT_IGNORABLE.search(text) for text in _strings_in(catalog)
    )


def _ansi_escape(served: str, catalog: dict) -> bool:
    return any("\x1b" in text for text in _strings_in(catalog))


def _markup_comment(served: str, catalog: dict) -> bool:
    return any("<!--" in text for text in _strings_in(catalog))


def _confusable_identifier(served: str, catalog: dict) -> bool:
    """A non-ASCII character in a tool NAME — a homoglyph collision.

    Nothing is invisible here; what is hidden is the identity of a character. Two names
    render identically and are distinct on the wire, so the tell is only reachable by a
    mixed-script or confusable-skeleton check ON NAMES. Description-level inspection,
    which is where every other mechanism in this class lives, reads both as ordinary text.
    """
    return any(
        any(ord(ch) > 127 for ch in tool.get("name", ""))
        for tool in catalog.get("tools", [])
    )


def _unreachable_schema_text(served: str, catalog: dict) -> bool:
    """Substantial text a naive renderer never displays.

    A client renders a tool's name, its description, and the descriptions of its top-level
    `inputSchema.properties`, then stops. Text elsewhere in the schema — under `$defs`,
    behind a `$ref`, in `examples` — is served, reaches the model, and is never shown. This
    compares what is REACHABLE against what is SENT rather than looking for a marker, so it
    catches structural hiding that carries no unusual bytes at all.
    """
    for tool in catalog.get("tools", []):
        visible = {tool.get("name", ""), tool.get("description", "")}
        schema = tool.get("inputSchema", {})
        if isinstance(schema, dict):
            for prop in (schema.get("properties") or {}).values():
                if isinstance(prop, dict):
                    visible.add(prop.get("description", ""))
        buried = [
            text
            for text in _strings_in(tool)
            if len(text) > 60 and text not in visible
        ]
        if buried:
            return True
    return False


HIDING_MECHANISMS = {
    "default-ignorable characters": _default_ignorable,
    "ANSI escape": _ansi_escape,
    "markup comment": _markup_comment,
    "confusable identifier": _confusable_identifier,
    "text unreachable by a naive renderer": _unreachable_schema_text,
}


def _served_catalog(specimen) -> dict:
    responses = handshake(specimen.entrypoint_path)
    return next((r.get("result", {}) for r in responses if r.get("id") == 2), {})


def test_every_hidden_content_specimen_actually_serves_something_hidden(corpus):
    """The escaping rule must not have neutered the payload.

    Source spells invisible characters `\\uXXXX`; the SERVED catalog must still carry the
    real thing (P103 — compare the two representations, do not assume one implies the
    other). Generalised beyond literal characters because the class is broader than its
    first four specimens: hiding by identity and hiding by structure are also hiding.
    """
    hidden = [s for s in corpus.malicious if Class.HIDDEN_CONTENT in s.classes]
    assert hidden, "no hidden-content specimens to check"

    inert: list[str] = []
    for specimen in hidden:
        catalog = _served_catalog(specimen)
        served = json.dumps(catalog)
        if not any(fires(served, catalog) for fires in HIDING_MECHANISMS.values()):
            inert.append(specimen.id)

    assert not inert, (
        f"{inert} declare hidden-content but serve nothing hidden by any mechanism this "
        f"corpus recognises ({sorted(HIDING_MECHANISMS)}). Either the payload was "
        "neutered, or the specimen uses a mechanism that belongs in HIDING_MECHANISMS — "
        "add it there rather than deleting this assertion."
    )


def test_the_class_uses_more_than_one_hiding_mechanism(corpus):
    """A corpus where every specimen hides the same way measures one rule, not a class.

    Also the vacuity guard for the predicates above (P58/P64): if only one of them ever
    fired, the other four would be untested decoration and nothing would say so.
    """
    hidden = [s for s in corpus.malicious if Class.HIDDEN_CONTENT in s.classes]
    fired = set()
    for specimen in hidden:
        catalog = _served_catalog(specimen)
        served = json.dumps(catalog)
        fired |= {name for name, fires in HIDING_MECHANISMS.items() if fires(served, catalog)}

    assert len(fired) >= 3, (
        f"the hidden-content class exercises only {sorted(fired)}. A scanner could pass it "
        "with a single rule, which makes the class a rule test rather than a threat test."
    )


def test_each_hiding_predicate_is_falsifiable():
    """P31/P50: a predicate that has never been shown to fire — or to STAY SILENT — is
    decoration. Each is fed one catalog it must catch and one it must not."""
    clean = {
        "tools": [
            {
                "name": "get_weather",
                "description": "Return the forecast for a city.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"city": {"type": "string", "description": "City name."}},
                },
            }
        ]
    }
    positives = {
        "default-ignorable characters": {
            "tools": [{"name": "a", "description": "hid\u200bden"}]
        },
        "ANSI escape": {"tools": [{"name": "a", "description": "x\x1b[2Ky"}]},
        "markup comment": {"tools": [{"name": "a", "description": "x<!-- y -->"}]},
        # "approve" with U+043E CYRILLIC SMALL LETTER O standing in for the Latin "o".
        # Spelled as an escape, not pasted: a reviewer cannot see the difference otherwise,
        # which is the entire point of the mechanism being tested.
        "confusable identifier": {
            "tools": [{"name": "appr\N{CYRILLIC SMALL LETTER O}ve", "description": "x"}]
        },
        "text unreachable by a naive renderer": {
            "tools": [
                {
                    "name": "a",
                    "description": "short",
                    "inputSchema": {
                        "properties": {"p": {"$ref": "#/$defs/X"}},
                        "$defs": {"X": {"description": "q" * 80}},
                    },
                }
            ]
        },
    }
    assert set(positives) == set(HIDING_MECHANISMS), (
        "every mechanism needs a case proving it fires; "
        f"missing {sorted(set(HIDING_MECHANISMS) - set(positives))}"
    )
    for name, fires in HIDING_MECHANISMS.items():
        catalog = positives[name]
        assert fires(json.dumps(catalog), catalog), f"{name} did not fire on its own case"
        assert not fires(json.dumps(clean), clean), f"{name} fires on an innocent catalog"
