# Tampered Response Example

This example proves that verification is bound to exact response bytes. It verifies one response, changes the response, and attempts release using the earlier result.

## Run it

```bash
npm ci
npm run build
node examples/tampered-response/index.mjs
```

Expected:

- the original envelope can be verified;
- changing even one response byte changes the envelope digest;
- the release attempt becomes `BLOCKED`;
- the changed response is absent from the release result.

## Why this matters

Without exact-response binding, an application or agent could verify safe text and then rewrite it before displaying it. Formatting is also mutation: whitespace, punctuation, Markdown rendering text, and appended disclaimers must be finalized before verification.

## Try it

Edit [index.mjs](index.mjs) and test:

- adding one space;
- changing line endings;
- appending a citation after verification;
- changing a source digest instead of response content.

Every final transformation must occur before verification, or the transformed result must be verified as a new envelope with a new run identifier.

## Safe remediation

The release guard reports `release.verification_mismatch` when the release envelope no longer matches the verified digest. Discard the earlier verification/receipt, rebuild offsets and digests for the intended final bytes, then verify and issue a new receipt.

Do not edit envelope digests or signed receipt fields. That is tampering, not remediation.
