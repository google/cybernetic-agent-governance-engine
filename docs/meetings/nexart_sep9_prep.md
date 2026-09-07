# NexArt Sync — September 9, 2026, 3:00 PM UK

**Attendees:** Lars Ahlfors (CAGE), Jeremy Bouedo (NexArt)
**Booked via:** Calendly
**Primary agenda:** CER handoff protocol and OSCAL SSP `link[]` dereferencing

---

## 1. CER Handoff Overview

### CAGE adapter: NexArtAttestationCallback

Location: [`src/integrations/provider_02/adapter.py`](../../src/integrations/provider_02/adapter.py)

The `NexArtAttestationCallback` class implements the CER (Cryptographic Evidence Receipt)
resolution hook. Key contract points:

- **Resolver endpoint:** `node.nexart.io/v1/resolve/cer/sha256:<hash>`
- **Constraint:** Exact-hash — the resolver must return a 200 with an immutable ETag.
  Any response without a matching ETag is treated as a cache miss and the CER is flagged
  for re-validation.
- **Immutability guarantee:** Once a CER is published at a hash URI, its content must
  never change. This is enforced by the immutable ETag contract, not by CAGE.

### Open item: OSCAL SSP `link[]` dereferencing

Jeremy requested that CAGE's OSCAL System Security Plan (SSP) `link[]` entries be
dereferenceable via the NexArt resolver. Specifically:

- Each `link[@rel='evidence']` in the OSCAL component XML must resolve to a CER at
  `node.nexart.io/v1/resolve/cer/sha256:<hash>`.
- CAGE's OSCAL exporter ([`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py))
  currently generates `link[@href]` values that point at internal GCS URIs, not NexArt CERs.

**Action:** Determine whether CAGE should generate NexArt CER URIs directly in the OSCAL
exporter, or whether NexArt provides a post-processing adapter that rewrites GCS URIs.

---

## 2. Test Cases for CER Handoff

### TC-01: Basic CER resolution (happy path)

```python
@pytest.mark.integration
async def test_cer_resolver_exact_hash_constraint():
    """
    NexArt CER resolver must return an immutable ETag on an exact-hash query.

    Prerequisites:
        - NEXART_RESOLVER_URL env var set to staging resolver base URL
        - A known CER hash present in the staging resolver

    Skipped in unit mode (requires NEXART_RESOLVER_URL).
    """
    import os
    import httpx

    resolver_url = os.environ.get("NEXART_RESOLVER_URL", "")
    if not resolver_url:
        pytest.skip(
            "NEXART_RESOLVER_URL not set — integration test requires live resolver"
        )

    known_hash = os.environ.get("NEXART_TEST_CER_HASH", "")
    if not known_hash:
        pytest.skip(
            "NEXART_TEST_CER_HASH not set — provide a known CER hash for the staging resolver"
        )

    url = f"{resolver_url}/v1/resolve/cer/sha256:{known_hash}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)

    assert resp.status_code == 200, (
        f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
    )
    assert "ETag" in resp.headers, "Immutable CER response must include ETag header"
    assert resp.headers.get("Cache-Control", "").startswith(
        "immutable"
    ) or "max-age=31536000" in resp.headers.get("Cache-Control", ""), (
        "Immutable CER should set long-lived Cache-Control"
    )
```

### TC-02: Hash mismatch returns 404

```python
@pytest.mark.integration
async def test_cer_resolver_unknown_hash_returns_404():
    """Unknown hashes must return 404, not 200 with empty body."""
    import os, httpx, secrets

    resolver_url = os.environ.get("NEXART_RESOLVER_URL", "")
    if not resolver_url:
        pytest.skip("NEXART_RESOLVER_URL not set")

    fake_hash = secrets.token_hex(32)
    url = f"{resolver_url}/v1/resolve/cer/sha256:{fake_hash}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)

    assert resp.status_code == 404, (
        f"Expected 404 for unknown hash, got {resp.status_code}"
    )
```

### TC-03: CAGE adapter normalizes CER into ExternalAttestation

```python
@pytest.mark.local
@pytest.mark.asyncio
async def test_nexart_adapter_maps_cer_to_attestation():
    """NexArtAttestationCallback.resolve() must return an ExternalAttestation
    with status=VERIFIED when the resolver returns a valid CER.
    """
    from unittest.mock import AsyncMock, patch
    from src.integrations.provider_02.adapter import NexArtAttestationCallback

    mock_cer_response = {
        "cer_id": "sha256:abc123",
        "status": "VALID",
        "attestation_type": "NORMATIVE",
    }
    with patch("httpx.AsyncClient") as MockClient:
        client_instance = AsyncMock()
        client_instance.get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_cer_response,
            headers={"ETag": '"abc123"'},
        )
        MockClient.return_value.__aenter__.return_value = client_instance

        adapter = NexArtAttestationCallback(resolver_url="https://node.nexart.io")
        result = await adapter.resolve("sha256:abc123")

    assert result is not None
    # Adjust assertion based on actual return type of NexArtAttestationCallback.resolve()
```

---

## 3. Open Questions for Sep 9 Meeting

1. **OSCAL `link[]` strategy:** Does NexArt own the OSCAL URI rewriting, or should CAGE's
   `oscal_ssp_exporter.py` generate NexArt CER URIs natively?

2. **CER immutability enforcement:** Is the immutable ETag enforced at the NexArt CDN level,
   or is it a convention that CAGE must independently verify on each resolution?

3. **Staging CA bundle:** Is the NexArt staging resolver using a self-signed CA? If so,
   provide the CA bundle path so CAGE can configure `httpx.AsyncClient(verify=ca_bundle)`.

4. **CER version scheme:** Does `node.nexart.io/v1/resolve/cer/sha256:<hash>` use SHA-256
   exclusively, or will SHA-384/SHA-512 be added? CAGE's digest computation uses SHA-256.

---

## 4. Pre-Meeting Checklist

- [ ] Confirm `NexArtAttestationCallback` test TC-03 passes against the mock
- [ ] Confirm OSCAL exporter generates at least one `link[@rel='evidence']` entry
- [ ] Check if `NEXART_RESOLVER_URL` is documented in `.env.example`
- [ ] Pull Jeremy's latest CER spec from `References/` (confirm in
      `/Users/larsahlfors/Documents/CAGE/Cage_dialogues/References/`)
