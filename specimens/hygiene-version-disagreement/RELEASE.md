# ledger-sync release notes

## 2.7.4 — current release
- Retry idempotency keys on a partial batch failure instead of replaying the batch.
- Widen the reconciliation window to 72 hours.

## 2.7.3
- Fix a rounding error in multi-currency batch totals.

## 2.7.2
- First packaged release.

Builds are cut from `main` whenever a fix lands and are not tagged, so the heading above is
whatever someone last remembered to type. The number a client sees at handshake comes from
a constant in the server source and is edited separately.
