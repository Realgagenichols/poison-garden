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
        if not tripped:
            inert.append(f"{twin.id} (controls for {sorted(c.value for c in twin.twin_for)})")

    assert not inert, (
        "these twins trip no naive rule at all, so they cannot demonstrate a false "
        f"positive and inflate any FP rate measured here: {inert}. "
        "Rewrite them to resemble their malicious siblings more closely — do not delete "
        "this assertion."
    )


def test_strawmen_are_not_vacuous(corpus):
    """P50/P96: a rule that fires on nothing, or on everything, discriminates nothing.

    Each strawman set must fire on its own MALICIOUS specimens too. A strawman that
    matched only twins would be measuring the wrong thing entirely.
    """
    silent: list[str] = []
    for klass, patterns in STRAWMEN.items():
        malicious = [s for s in corpus.malicious if klass in s.classes]
        if not malicious:
            continue
        if not any(
            pattern.search(_advertised_text(s)) for s in malicious for pattern in patterns
        ):
            silent.append(klass.value)

    assert not silent, f"strawman rules fire on no malicious specimen for: {silent}"


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


def test_runtime_catalog_does_carry_the_hidden_characters(corpus):
    """The escaping rule must not have neutered the payload.

    Source spells them `\\uXXXX`; the SERVED catalog must still contain the real
    characters, or the hidden-content specimens advertise nothing hidden (P103 — compare
    the two representations, do not assume one implies the other).
    """
    hidden = [s for s in corpus.malicious if Class.HIDDEN_CONTENT in s.classes]
    assert hidden, "no hidden-content specimens to check"

    carriers = 0
    for specimen in hidden:
        responses = handshake(specimen.entrypoint_path)
        served = json.dumps([r for r in responses if r.get("id") == 2])
        # json.dumps escapes non-ASCII by default, so look for the escaped form too.
        if any(
            marker in served
            for marker in ("\\u200b", "\\u200c", "\\u200d", "\\u202e", "\\u001b", "<!--")
        ):
            carriers += 1

    assert carriers == len(hidden), (
        f"only {carriers}/{len(hidden)} hidden-content specimens actually serve hidden "
        "content — the rest advertise nothing a scanner could miss"
    )
