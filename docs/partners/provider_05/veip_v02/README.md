# CAGE × VEIP v0.2 — Conformance Bundle & Live Sandbox Artifacts

Frozen VEIP v0.2 conformance bundle artifacts (delivery ZIP SHA-256: `47c1ed5fee93a82dbfcd855e1a25fb55dec2c5a795c248f21422c91fa21ea8e4`).

## Live Interoperability Sandbox

- **Base URL:** `https://veip-cage-sandbox.am-43b.workers.dev`
- **Warrant Endpoint:** `https://veip-cage-sandbox.am-43b.workers.dev/v0.2/warrants/confidence.min_trade_confidence[?scenario=...]`
- **Key Manifest:** `https://veip-cage-sandbox.am-43b.workers.dev/.well-known/veip/key-manifest.json`
- **Out-of-Band Root `kid`:** `veip-sandbox-manifest-root-2026-10`
- **Out-of-Band Root Public Key (SPKI Base64):** `MCowBQYDK2VwAyEAGkpGRonrFI0bgcXBOipmZVpjP2KgBczNryMe3mJ10PM=`
- **Out-of-Band Root Fingerprint (Raw 32-byte Ed25519 SHA-256):** `sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85`
- **Issuer Public Key (`veip-sandbox-issuer-2026-10`, SPKI Base64):** `MCowBQYDK2VwAyEAJ4RtpB51zP1atj/1hwsj4on1Hx1aARMEMMgXEWWs6G0=`

## Scenarios & Expected CAGE Outcomes (Reference Clock `2026-10-07T14:00:10Z`)

| Scenario | HTTP | Digest | Ed25519 Signature / `kid` | `verification_status` | `RelianceStatus` | Gateway Verdict |
|---|---|---|---|---|---|---|
| `ACTIVE` | `200` | Valid | Valid (`veip-sandbox-issuer-2026-10`) | `VERIFIED` | `ELIGIBLE` | `ALLOW` (confidence $\ge 0.97$) |
| `REVOKED` | `200` | Valid | Valid (`veip-sandbox-issuer-2026-10`) | `VERIFIED` | `INELIGIBLE_REVOKED` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `SUSPENDED` | `200` | Valid | Valid (`veip-sandbox-issuer-2026-10`) | `VERIFIED` | `INELIGIBLE_UNRESOLVED` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `EXPIRED` | `200` | Valid | Valid (`veip-sandbox-issuer-2026-10`) | `VERIFIED` | `INELIGIBLE_EXPIRED` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `STALE_STATE` | `200` | Valid | Valid (`veip-sandbox-issuer-2026-10`) | `VERIFIED` | `INELIGIBLE_STALE` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `TAMPERED_SIGNATURE` | `200` | Valid | Invalid (`InvalidSignature`) | `UNVERIFIED` | `INELIGIBLE_UNRESOLVED` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `UNKNOWN_KID` | `200` | Mismatch | Unknown `kid` (`unknown-kid`) | `UNVERIFIED` | `INELIGIBLE_UNRESOLVED` | `DEFER` (`WARRANT_INELIGIBLE`) |
| `MISSING` | `404` | — | — | `UNVERIFIED` | `INELIGIBLE_MISSING` | `DEFER` (`WARRANT_INELIGIBLE`) |
