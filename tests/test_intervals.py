"""Confidence intervals and the minimum-n gate — R18, R19.

The defect these requirements close was in the *presentation*, not the arithmetic, which is
why it survived every earlier review: a class with one specimen reported `0/1` as recall
`0.0`, and a reader quite reasonably read "0%" as "this scanner has a gap here". It does not
mean that. One observation cannot separate a gap from a hard specimen (cross-cutting P48),
and the interval is the part of the figure that says so.

This is the same defect R10 exists to prevent — a number that looks like a measurement and
is not one — arriving through a door R10 does not cover.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from poison_garden.corpus.loader import load_corpus
from poison_garden.runner.execute import ExitCodeMapping, SpecimenResult, Verdict
from poison_garden.scoring.document import build_document
from poison_garden.scoring.score import (
    MIN_SPECIMENS_FOR_A_CLAIM,
    ClassScore,
    wilson_interval,
)


@pytest.fixture(scope="module")
def corpus():
    """The real corpus — the interval must hold on the artifact we actually publish."""
    return load_corpus(Path(__file__).resolve().parent.parent / "specimens")


def _normal_approximation(caught: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """The textbook interval, here ONLY as the thing Wilson must not be.

    Kept in the test rather than the source because it is the wrong answer. Its failure mode
    is the entire reason R18 names Wilson specifically: at 0/1 it returns (0.0, 0.0),
    asserting from a single observation that the true rate is certainly zero.
    """
    p = caught / total
    half = z * math.sqrt(p * (1 - p) / total)
    return (max(0.0, p - half), min(1.0, p + half))


# --- R18: the interval is reported, and it is a real interval -----------------------------


def test_single_observation_does_not_pin_the_rate_to_zero():
    """THE motivating case. `0/1` must not read as "0%, measured"."""
    low, high = wilson_interval(0, 1)
    assert low == 0.0
    assert high > 0.5, (
        f"a single miss yielded the interval [{low:.2f}, {high:.2f}]. One observation "
        "cannot exclude a scanner that catches this class most of the time."
    )
    assert high == pytest.approx(0.7935, abs=0.001), "Wilson upper bound for 0/1"


def test_single_hit_does_not_pin_the_rate_to_one():
    """The flattering direction of the same error, which matters more, not less.

    A vendor quoting "100% recall on credential-access" from one specimen is the failure
    this project was built to make impossible.
    """
    low, high = wilson_interval(1, 1)
    assert high == 1.0
    assert low < 0.5, f"a single hit yielded [{low:.2f}, {high:.2f}] — that is not evidence"
    assert low == pytest.approx(0.2065, abs=0.001)


def test_wilson_is_not_the_normal_approximation_where_it_counts():
    """FALSIFICATION (P31): swapping in the textbook formula must redden this.

    Without it, `wilson_interval` could be replaced by the normal approximation and every
    other test here would still pass for the mid-range cases — while the degenerate
    endpoints, the only cases this corpus actually has, silently became certainties.
    """
    for caught, total in [(0, 1), (1, 1), (0, 2), (2, 2), (0, 4), (4, 4)]:
        naive = _normal_approximation(caught, total)
        assert naive[1] - naive[0] == pytest.approx(0.0), "precondition: degenerate at edges"
        low, high = wilson_interval(caught, total)
        assert high - low > 0.4, (
            f"{caught}/{total} produced the interval [{low:.2f}, {high:.2f}]; the normal "
            f"approximation produces {naive}. An all-hit or all-miss class is exactly where "
            "the point estimate is least trustworthy and this interval is widest."
        )


def test_interval_brackets_the_point_estimate():
    """A mechanical relation between the two published numbers (P68).

    Not a tautology: a sign error, a swapped bound, or a z applied to the wrong centre all
    produce an interval that excludes its own point estimate.
    """
    for total in range(1, 40):
        for caught in range(total + 1):
            low, high = wilson_interval(caught, total)
            point = caught / total
            assert low <= point <= high, f"{caught}/{total}: {point} outside [{low}, {high}]"
            assert 0.0 <= low <= high <= 1.0


def test_interval_narrows_as_the_corpus_grows():
    """The property that makes expanding the corpus worth doing, asserted rather than assumed.

    If this did not hold, adding specimens would buy nothing and R19's threshold would be
    arbitrary.
    """
    widths = [
        wilson_interval(n // 2, n)[1] - wilson_interval(n // 2, n)[0] for n in (2, 6, 12, 30)
    ]
    assert widths == sorted(widths, reverse=True), f"widths did not shrink: {widths}"
    assert widths[0] - widths[-1] > 0.3, "growing the corpus must buy meaningful precision"


def test_no_specimens_means_no_claim_in_either_direction():
    """A class with nothing scorable is total ignorance, not a 50/50 (P55)."""
    assert wilson_interval(0, 0) == (0.0, 1.0)


# --- R19: the sufficiency gate ------------------------------------------------------------


def _score(caught: int, total: int) -> ClassScore:
    from poison_garden.corpus.models import Class

    return ClassScore(
        klass=Class.INJECTION, caught=caught, total=total, missed=(), errored=()
    )


def test_a_class_below_threshold_is_marked_insufficient():
    assert not _score(0, 1).sufficient
    assert not _score(2, 2).sufficient
    assert not _score(4, 4).sufficient, "one below the threshold is still below it"


def test_a_class_at_the_threshold_is_sufficient():
    n = MIN_SPECIMENS_FOR_A_CLAIM
    assert _score(n, n).sufficient, "the threshold is inclusive"
    assert _score(0, n + 1).sufficient, "sufficiency is about n, not about the result"


def test_sufficiency_does_not_depend_on_whether_the_scanner_did_well():
    """A gate that only fires on bad news is advocacy, not measurement."""
    n = MIN_SPECIMENS_FOR_A_CLAIM
    assert _score(0, n).sufficient == _score(n, n).sufficient


# --- both, as they reach the published artifact -------------------------------------------


def test_document_carries_the_interval_for_every_class(corpus):
    """R18 names the DOCUMENT. A property on a dataclass nobody serialises is not a fix."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    assert doc.payload["per_class"], "precondition: the corpus has classes to report"
    for entry in doc.payload["per_class"]:
        interval = entry["recall_ci95"]
        assert interval is not None, f"{entry['class']} published recall with no interval"
        low, high = interval
        assert low <= entry["recall"] <= high
        assert "sufficient_n" in entry


def test_document_interval_matches_the_scored_counts(corpus):
    """The published interval must be derived from the published counts (P26/P68).

    Recomputing it from `caught`/`total` in the same document is what makes the figure
    checkable by a reader rather than trusted.
    """
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    for entry in doc.payload["per_class"]:
        expected = wilson_interval(entry["caught"], entry["total"])
        assert entry["recall_ci95"] == [round(expected[0], 4), round(expected[1], 4)]
        assert entry["sufficient_n"] == (entry["total"] >= MIN_SPECIMENS_FOR_A_CLAIM)


# --- R20: declared difficulty -------------------------------------------------------------


def test_a_typod_tier_is_rejected_not_silently_defaulted(tmp_path: Path):
    """A typo SHALL NOT fall back to MODERATE.

    Silently defaulting would move a specimen into the tier a scanner's misses are read as
    defects in — the same failure mode as a typo'd class name quietly making a malicious
    specimen benign, which is why this parser treats its own manifests as external input.
    """
    from poison_garden.corpus.manifest import parse_manifest
    from poison_garden.corpus.models import ManifestError

    path = tmp_path / "manifest.toml"
    path.write_text(
        'id = "x"\nsummary = "s"\ndeclaration = ["injection"]\ndifficulty = "subtile"\n',
        encoding="utf-8",
    )
    with pytest.raises(ManifestError, match="subtile"):
        parse_manifest(path)


def test_every_tier_name_actually_parses(tmp_path: Path):
    """The complement of the test above: rejecting everything would also pass it (P49)."""
    from poison_garden.corpus.manifest import parse_manifest
    from poison_garden.corpus.models import Difficulty

    for tier in Difficulty:
        path = tmp_path / f"{tier.value}.toml"
        path.write_text(
            f'id = "x"\nsummary = "s"\ndeclaration = ["injection"]\n'
            f'difficulty = "{tier.value}"\n',
            encoding="utf-8",
        )
        assert parse_manifest(path).difficulty is tier


def test_tier_counts_sum_to_the_class_total(corpus):
    """A mechanical relation between two published figures (P40/P68).

    The tiers are built from the same `scorable` list as `total`, so this cannot drift —
    but that is the claim, and an unasserted claim is how drift starts.
    """
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    for entry in doc.payload["per_class"]:
        tiers = entry["by_difficulty"]
        assert sum(t["total"] for t in tiers.values()) == entry["total"], entry["class"]
        assert sum(t["caught"] for t in tiers.values()) == entry["caught"], entry["class"]


def test_tier_counts_are_counts_and_never_a_rate(corpus):
    """R20 forbids a per-tier percentage — two specimens cannot support one."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())

    for entry in doc.payload["per_class"]:
        for tier, counts in entry["by_difficulty"].items():
            assert set(counts) == {"caught", "total"}, (
                f"{entry['class']}/{tier} publishes {sorted(counts)}; a tier holding one or "
                "two specimens must not carry a rate"
            )
            assert all(isinstance(v, int) for v in counts.values())


def test_empty_tiers_are_dropped_rather_than_published_as_zero_over_zero(corpus):
    """`0/0` reads as a failure and is not one."""
    results = [
        SpecimenResult(s.id, Verdict.CLEAN if s.is_benign else Verdict.FLAGGED, 1)
        for s in corpus.specimens
    ]
    doc = build_document(corpus, results, "stub", ExitCodeMapping())
    for entry in doc.payload["per_class"]:
        for tier, counts in entry["by_difficulty"].items():
            assert counts["total"] > 0, f"{entry['class']}/{tier} published an empty tier"


# --- R19 at the rendered surface ----------------------------------------------------------


def _rendered(tmp_path: Path, entries: list[dict]) -> str:
    import json

    from poison_garden.leaderboard.render import render

    (tmp_path / "a.json").write_text(
        json.dumps(
            {
                "scanner": {"name": "stub"},
                "corpus": {"version": "9.9.9"},
                "per_class": entries,
                "false_positives": {"specimens": [], "benign_total": 3},
            }
        ),
        encoding="utf-8",
    )
    return render(tmp_path)


def test_an_undersized_class_is_marked_in_the_table(tmp_path: Path):
    """R19: the cell must not be quotable as a property of the scanner."""
    from poison_garden.leaderboard.render import INSUFFICIENT_MARK

    page = _rendered(
        tmp_path,
        [{"class": "injection", "caught": 1, "total": 1, "sufficient_n": False}],
    )
    assert f"1/1 {INSUFFICIENT_MARK}" in page
    assert INSUFFICIENT_MARK in page.split("## Reading this table")[1], (
        "the mark appears in the table with nothing explaining it"
    )


def test_a_sufficient_class_is_NOT_marked(tmp_path: Path):
    """FALSIFICATION (P31): marking every cell would satisfy the test above and mean nothing."""
    from poison_garden.leaderboard.render import INSUFFICIENT_MARK

    page = _rendered(
        tmp_path,
        [{"class": "injection", "caught": 4, "total": 6, "sufficient_n": True}],
    )
    row = next(ln for ln in page.splitlines() if ln.startswith("| stub "))
    assert "4/6" in row
    assert INSUFFICIENT_MARK not in row, f"a class with n=6 was marked insufficient: {row}"


def test_a_pre_R19_document_is_marked_from_its_own_counts(tmp_path: Path):
    """A missing flag must not read as "sufficient".

    Documents submitted before R19 existed carry no `sufficient_n`. Defaulting it to True
    would leave exactly the old, unmarked cells unmarked — making the guard apply only to
    the documents that least need it.
    """
    from poison_garden.leaderboard.render import INSUFFICIENT_MARK

    page = _rendered(tmp_path, [{"class": "injection", "caught": 0, "total": 1}])
    assert f"0/1 {INSUFFICIENT_MARK}" in page
