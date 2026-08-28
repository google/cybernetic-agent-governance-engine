# Changelog

All notable changes will be documented here. The project follows Semantic Versioning after 1.0; alpha releases may contain documented breaking changes.

## 0.1.0-alpha.0 - Unreleased

- Added strict runtime envelope validation and bounded canonical JSON.
- Added complete UTF-8 response-byte coverage and claim binding.
- Added trusted source recollection and evidence byte anchors.
- Added trusted decision-registry loading and claim-to-decision references.
- Added Ed25519-signed receipts with issuer, audience, purpose, engine, policy, and expiry binding.
- Added serialized create-once local issuance with crash recovery and exactly-once local receipt consumption through one protected monotonic store.
- Added runnable examples, protocol schema, compatibility/migration guidance, and release checks.
- Added a tag-only npm trusted-publishing workflow that remains fail-closed while publication placeholders or external npm/GitHub configuration are unresolved.
- Moved CLI roots, key trust, clock, and receipt-store authority out of untrusted stdin into host-controlled configuration.
- Added SHA-pinned release actions and integrity-checked, resumable multi-package publication.
- Upgraded package checks to pack real tarballs, reject incremental build state, install all packages in an isolated temporary project, import public exports, and execute the installed CLI.
- Marked the workspace root private to prevent accidental monorepo-root publication.
- Added exact-head pull-request CI and protected-main ancestry validation before npm publication.
- Added a fail-closed public release-status verifier for GitHub workflow approval, npm provenance, versions, and downloaded tarball integrity.

No npm package or public repository release exists yet.
