"""The result document — R4, R6, R9, R10, S3.

This is the artifact a vendor publishes, so it has to carry everything a reader needs to
check it and nothing they must take on trust:

- the corpus **version and hash**, so two documents are only comparable when they describe
  the same corpus (R4)
- the **exit-code mapping** actually applied, so a reader can see how a number became a
  verdict (R6)
- every **per-specimen verdict**, so the stated figures are recomputable from the document
  itself rather than believed (P26)
- per-class recall **and** a false-positive rate, together or not at all (R9)
- **no composite score**, ever (R10)

What it must never carry (S3): a decoy canary, a scanner token, an environment value, or
raw specimen output. Specimen ids and class names only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from poison_garden.corpus.hash import corpus_hash, refuse_mismatch
from poison_garden.corpus.models import Corpus
from poison_garden.runner.execute import ExitCodeMapping, SpecimenResult
from poison_garden.scoring.score import Scores, ScoringRefused, score_run

SCHEMA_VERSION = "poison-garden/result@1"

# Fields a reader might expect but which are deliberately absent (R10). Tests pin this set
# EXACTLY, because a guard that iterates a list can be nullified by emptying the list — the
# check keeps passing and a composite score ships.
FORBIDDEN_FIELDS = frozenset(
    {"score", "grade", "rating", "composite", "aggregate", "index"}
)

# Every key the document is allowed to contain, at any depth. This is the guard that
# actually holds: a name-based rule cannot catch a field called `accuracy` or
# `detection_rate`, which would be a composite score wearing an innocent word. Since we
# generate this document ourselves from a known schema, an exact key set catches ANY new
# field — and adding one becomes a deliberate edit to this list.
ALLOWED_KEYS = frozenset(
    {
        "schema", "generated_utc", "notes",
        "corpus", "version", "hash", "specimen_count",
        "scanner", "name", "exit_code_mapping",
        "verdicts", "specimen", "verdict", "exit_code", "duration_s", "error_reason",
        "attributed", "sarif_note",
        "per_class", "class", "caught", "total", "recall", "missed", "errored",
        "false_positives", "specimens", "benign_total", "rate",
        "errors",
    }
)


def composite_fields_in(payload: object, _path: str = "") -> list[str]:
    """Keys that read as an aggregate score, matched on underscore TOKENS.

    Two independent reviews converged on tokens over prefix/suffix: the prefix/suffix form
    missed a mid-compound name like `spearman_rank_correlation`, and tokens close that at
    no extra complexity. Both also caught a crash I had not: `key.lower()` raises
    AttributeError on a non-string key, which is plausible here because per-class results
    are keyed by class.

    `overall` and `rank` were DROPPED from the list deliberately. `overall` collides with
    `overall_false_positive_rate` — a document-level aggregate R9 explicitly requires — and
    banning a word the spec mandates is the guard contradicting the requirement it serves.
    `rank` collides with ordinary statistics (`rank_correlation`) and has only a weak link
    to composite scoring. What replaces them is `unexpected_fields_in`, which is strictly
    stronger: it catches a headline number under ANY name, including the `accuracy` and
    `detection_rate` cases no wordlist can reach.
    """
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{_path}.{key}" if _path else key
            if isinstance(key, str):
                tokens = set(key.lower().replace("-", "_").split("_"))
                # Singular and plural: `class_scores` must not slip past `score`.
                tokens |= {t.rstrip("s") for t in tokens}
                if tokens & FORBIDDEN_FIELDS:
                    found.append(here)
            found.extend(composite_fields_in(value, here))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            found.extend(composite_fields_in(item, f"{_path}[{index}]"))
    return found


def unexpected_fields_in(payload: object, _path: str = "") -> list[str]:
    """Any key not in `ALLOWED_KEYS`, at any depth.

    The guard that actually holds. A name-based rule is structurally blind to a composite
    score named `accuracy`, `detection_rate` or `success_rate` — none of those words can be
    banned without banning legitimate per-class metrics too. Since poison-garden generates
    this document from a schema it controls, an exact key set catches every new field
    regardless of what it is called, and adding one becomes a deliberate edit rather than a
    drift nobody notices.
    """
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{_path}.{key}" if _path else key
            if isinstance(key, str) and key not in ALLOWED_KEYS:
                found.append(here)
            found.extend(unexpected_fields_in(value, here))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            found.extend(unexpected_fields_in(item, f"{_path}[{index}]"))
    return found


@dataclass(frozen=True)
class ResultDocument:
    payload: dict[str, Any]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.payload, indent=indent, sort_keys=True) + "\n"

    def write(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.to_json(), encoding="utf-8")
        return out

    @property
    def corpus_hash(self) -> str:
        return self.payload["corpus"]["hash"]


def build_document(
    corpus: Corpus,
    results: list[SpecimenResult],
    scanner_name: str,
    mapping: ExitCodeMapping,
    scores: Scores | None = None,
    corpus_hash_before_run: str | None = None,
) -> ResultDocument:
    """Assemble the document. Scoring's refusal rules apply before anything is written."""
    measured_hash = corpus_hash_before_run or corpus_hash(corpus)
    if corpus_hash_before_run is not None:
        after = corpus_hash(corpus)
        if after != corpus_hash_before_run:
            raise ScoringRefused(
                "the corpus changed during the run: "
                f"before={corpus_hash_before_run} after={after}. A specimen wrote into the "
                "corpus tree, so the figures describe a corpus that no longer exists. "
                "Fix the specimen — a corpus must be inert under measurement."
            )

    scores = scores if scores is not None else score_run(corpus, results)

    # R9 names the EMITTER: "SHALL refuse to emit a document containing one without the
    # other". Keeping that check only inside `score_run` left a bypass — passing a
    # pre-computed `Scores` skipped it entirely, and a run where every twin errored
    # produced a schema-valid document showing 100% recall on all six classes with
    # `"rate": null`. Measured, not hypothesised. No shipped caller did that, but the
    # obvious future optimisation (score once, then build) is exactly that call.
    if scores.false_positive_rate is None:
        raise ScoringRefused(
            "refusing to emit a document with no false-positive rate. Every benign twin "
            "errored or was absent, so the per-class recall figures below have no control "
            "and would read as a clean sweep. Recall without a false-positive rate is not "
            "a measurement (R9)."
        )

    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus": {
            "version": corpus.version,
            # The hash AS MEASURED, captured before the run. Computing it afterwards meant a
            # specimen that wrote into its own directory — plausible for R13's state, or an
            # R12 decoy that regenerates — changed the hash that got published. Two honest
            # runs over one corpus would then cite different hashes and `compare()` would
            # refuse them with nothing saying why (R4).
            "hash": measured_hash,
            "specimen_count": len(corpus),
        },
        "scanner": {
            # The scanner's IDENTITY, not the command line: a template can contain an API
            # token, and this document is meant to be published (S3).
            "name": scanner_name,
            "exit_code_mapping": mapping.describe(),
        },
        "verdicts": [
            {
                "specimen": r.specimen_id,
                "verdict": str(r.verdict),
                "exit_code": r.exit_code,
                # Scan cost, which a vendor comparing tools has a real use for. Rounded:
                # sub-millisecond precision is noise and would make two runs of the same
                # corpus differ in every line for no reason.
                "duration_s": round(r.duration_s, 2),
                # A category, never the scanner's output.
                "error_reason": r.error_reason,
                # R17: present only when SARIF was requested AND usable. Absent means the
                # verdict came from the exit code alone, which is the supported baseline.
                "attributed": (
                    sorted(str(c) for c in r.attributed)
                    if r.attributed is not None
                    else None
                ),
                "sarif_note": r.sarif_note,
            }
            for r in sorted(results, key=lambda r: r.specimen_id)
        ],
        "per_class": [
            {
                "class": str(c.klass),
                "caught": c.caught,
                "total": c.total,
                "recall": c.recall,
                "missed": list(c.missed),
                "errored": list(c.errored),
            }
            for c in scores.per_class
        ],
        "false_positives": {
            "specimens": list(scores.false_positives),
            "benign_total": scores.benign_total,
            "rate": scores.false_positive_rate,
            "errored": list(scores.benign_errored),
        },
        "errors": list(scores.errored),
        "notes": (
            "No composite score is reported, by design (R10). An aggregate hides the "
            "lopsided class, which is usually the interesting one, and invites the "
            "rank-ordering poison-garden refuses to perform. Recall and false positives "
            "are reported together because either alone misrepresents the run."
        ),
    }
    return ResultDocument(payload=payload)


def compare(
    a: ResultDocument, b: ResultDocument, *, label_a: str = "a", label_b: str = "b"
) -> None:
    """Refuse to compare documents describing different corpora (R4).

    Completes R4's scenario: M1 built `refuse_mismatch`, this is the consumer it was
    built for.
    """
    refuse_mismatch(a.corpus_hash, b.corpus_hash, label_a=label_a, label_b=label_b)


def load_document(path: str | Path) -> ResultDocument:
    return ResultDocument(payload=json.loads(Path(path).read_text(encoding="utf-8")))
