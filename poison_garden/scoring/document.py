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
FORBIDDEN_FIELDS = frozenset({"score", "overall", "total_score", "grade", "rating", "rank"})


def composite_fields_in(payload: object, _path: str = "") -> list[str]:
    """Every key in the document that reads as an aggregate score.

    Walks KEYS rather than matching substrings in the rendered JSON. A substring check for
    `"overall"` does not match a field named `overall_recall`, so the obvious way to add a
    headline number would have slipped straight past it.
    """
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{_path}.{key}" if _path else key
            lowered = key.lower()
            if any(
                lowered == bad or lowered.startswith(f"{bad}_") or lowered.endswith(f"_{bad}")
                for bad in FORBIDDEN_FIELDS
            ):
                found.append(here)
            found.extend(composite_fields_in(value, here))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            found.extend(composite_fields_in(item, f"{_path}[{index}]"))
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
