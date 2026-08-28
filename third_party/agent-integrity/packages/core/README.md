# @agent-integrity/core

Deterministic verification, trusted filesystem/decision collection, canonical hashing, and Ed25519 receipt operations.

Use `verifyTrustedEnvelope` for release decisions. The lower-level structural verifier does not recollect sources or load the trusted decision registry and must not be used as a release boundary.

The trusted context must include `trustedPolicy`, parsed from host-controlled configuration independently of the envelope. Verification rejects any embedded policy mismatch or downgrade.

```js
import { collectSource, verifyTrustedEnvelope } from "@agent-integrity/core";
```

Requires Node.js 22+. See the root Integration Guide for the full trusted context and key-management flow.
