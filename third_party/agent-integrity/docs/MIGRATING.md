# Migration and Compatibility Policy

Before 1.0, minor or alpha releases may change TypeScript APIs, JSON fields, finding codes, receipt bodies, and CLI arguments. Patch releases should remain compatible unless a security flaw requires a breaking fail-closed change.

For every protocol-changing release:

1. Read `CHANGELOG.md` and the compatibility matrix.
2. Upgrade all `@agent-integrity/*` packages together.
3. Regenerate envelopes from source data; do not rewrite old signed receipts.
4. Retain old public keys while unexpired receipts from the old release remain valid, unless the key is compromised.
5. Run conformance fixtures and your release-path integration tests.
6. Deploy to a review-only environment before enabling release.

Receipts bind their engine version. A verifier must reject receipts for an unexpected engine version. There is no promise that alpha receipts remain consumable across upgrades.

Deprecations will be documented for at least one alpha release when security permits. Security-critical behavior may be removed immediately and called out prominently.
