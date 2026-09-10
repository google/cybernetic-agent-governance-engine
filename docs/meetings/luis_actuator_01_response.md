# Response to Luis — actuator_01 Wire Protocol Fixes

**Date:** 2026-09-08  
**Thread:** v3.0.1 actuator_01 contract review  
**Status:** Both bugs fixed, all tests passing

---

Hi Luis,

Thanks for the careful read of actuator_01 and catching both bugs before the harness integration — you saved us a 421 at the door for a reason that would've been painful to debug in a supervised run.

## Both Bugs Fixed

You were exactly right on both counts:

**Bug 1 — Domain tag mismatch ([`signatures.py:32`](../../src/integrations/actuator_01/signatures.py:32)):**  
Fixed. Was signing with `ACTUATOR_01_QUORUM_V1:`, now correctly uses `ARCHYTAN_QUORUM_V1:` to match your kernel's verification path.

**Bug 2 — Header name mismatch ([`client.py:141`](../../src/integrations/actuator_01/client.py:141)):**  
Fixed. Was sending `X-Quorum-Signatures`, now correctly sends `X-Archytan-Signatures` so it won't fail at the header check before signatures are even verified.

You nailed the root cause — the anonymization pattern (anonymized constant names, wire-load-bearing runtime values per [`constants.py:19`](../../src/integrations/actuator_01/constants.py:19)) leaked into the values themselves. The fix keeps the anonymized names but restores the correct runtime wire-protocol values.

All 110 actuator_01 tests pass, including updated test vectors validating the corrected domain tag and header name.

## KMS IAM Model

[`docs/architecture/actuator_01_kms_iam_model.md`](../architecture/actuator_01_kms_iam_model.md) is committed and up to date. It documents the single shared credential in the current reference implementation and lays out Option B (per-ceremony OIDC downscoping with zero standing IAM, credential lifetime = 30s window).

**Yes to the IAM binding walkthrough.** I'd like to understand the token-exchange flow and the specific `iamcredentials.generateAccessToken` call shape for downscoping to a ceremony-scoped credential. When you have time, let's walk through:

1. The IAM bindings on the operator service accounts (what role grants `iam.serviceAccounts.getAccessToken`?)
2. Whether the ceremony-scoped token is passed via a custom `Credentials` object to the KMS client, or if there's a cleaner seam in the `google-auth` library
3. Any gotchas around token lifetime floor/ceiling (30s is legal for access tokens, right?)

The integration vector is ready on our side — envelope construction, quorum signing, and transport all align with the contract now.

Thanks again,  
Lars
