# Results

One file per scanner run, submitted by pull request. CI validates schema, corpus hash, and
that the stated figures agree with the document's own per-specimen verdicts.

**Maintainers never recompute, adjust, or editorialise a submitted figure.** The comparison
page is generated from what is committed. There is no hand-maintained table and no ranking.

## Submitting

```sh
poison-garden run --scanner "your-scanner {target}" \
                  --scanner-name "your-scanner 1.2.3" \
                  --out results/your-scanner-1.2.3.json
```

Then open a PR with that file. Nothing else.

## A note on `mcp-frisk-0.2.0.json`

This project's maintainer also maintains [frisk](https://github.com/Realgagenichols/frisk).
That file is a **self-report** — the author running the corpus against their own scanner and
publishing the result, which is exactly what every vendor is invited to do. It is not a score
poison-garden computed on a third party's behalf; this project never does that.

Read it alongside [`KNOWN-MISSES.md`](../KNOWN-MISSES.md), which registers the specimens frisk
fails and exists precisely because the author has a conflict of interest here.
