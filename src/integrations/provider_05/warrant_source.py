# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Provider 05 (Veraxis Execution Integrity Protocol — VEIP) warrant source.

Implements the kernel ``WarrantSource`` seam
(``src.gateway.governance.seams.warrant``) for VEIP-issued institutional
warrants under the CAGE x VEIP Warrant Contract v0.1 and v0.2. The warrant
model, key-manifest verifier, standing verifier and evidence binding live in
the kernel (``src.gateway.governance.warrant``); this adapter supplies
warrants and the independently fetched key manifest.

Transport modes:
  1. Seeded / hermetic: warrants and key manifests populated via ``seed()`` and
     ``seed_key_manifest()`` are served from memory.
  2. Live HTTP (VEIP v0.2): when ``endpoint`` (or
     ``PROVIDER_05_ATTESTATION_ENDPOINT``) is configured, ``fetch(norm_id)``
     requests ``GET {endpoint}/v0.2/warrants/{norm_id}`` (returning ``None`` on
     HTTP 404 -> ``INELIGIBLE_MISSING``) and ``fetch_key_manifest()`` requests
     ``GET {endpoint}/.well-known/veip/key-manifest.json``.

Fault injection (AGENTS.md: a posture-completing data source needs
deterministic fault injection for every fail-closed path). ``inject_fault()``
takes a kernel :class:`~src.gateway.governance.seams.ground_truth.FaultMode`;
each supported mode drives one fail-closed path of the warrant gate:

* ``TIMEOUT`` raises ``TimeoutError`` (what the cache's fetch timeout
  raises), ``CONNECTION_ERROR`` raises ``ConnectionError``: a source fault,
  so the norm is ``INELIGIBLE_UNRESOLVED`` (nothing observed yet) or
  ``INELIGIBLE_STALE`` (the cached state is past the freshness window).
* ``MALFORMED_PAYLOAD`` returns the raw payload (a ``dict``) instead of a
  parsed ``Warrant``: the kernel cache refuses it as a source fault.
* ``UNVERIFIED_SOURCE`` returns the warrant with ``issuing_authority``
  rewritten in transit but the declared digest kept: the verifier's digest
  check makes it ``INELIGIBLE_UNRESOLVED``.

Any other mode is refused at injection (``ValueError``) rather than silently
ignored.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

import httpx

from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.governance.warrant import (
    VerifiedKeyManifest,
    Warrant,
    WarrantTrustAnchor,
)

logger = logging.getLogger("cage.integrations.provider_05.warrant_source")

PROVIDER_NAME = "provider_05_warrant"

#: Default VEIP v0.2 interoperability sandbox endpoint.
VEIP_SANDBOX_BASE_URL = "https://veip-cage-sandbox.am-43b.workers.dev"

#: Out-of-band VEIP v0.2 sandbox root key parameters.
VEIP_SANDBOX_ROOT_KID = "veip-sandbox-manifest-root-2026-10"
VEIP_SANDBOX_ROOT_PUBLIC_KEY_B64 = (
    "MCowBQYDK2VwAyEAGkpGRonrFI0bgcXBOipmZVpjP2KgBczNryMe3mJ10PM="
)
VEIP_SANDBOX_ROOT_FINGERPRINT = (
    "sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85"
)
VEIP_SANDBOX_ISSUER_KID = "veip-sandbox-issuer-2026-10"
VEIP_SANDBOX_ISSUER_PUBLIC_KEY_B64 = (
    "MCowBQYDK2VwAyEAJ4RtpB51zP1atj/1hwsj4on1Hx1aARMEMMgXEWWs6G0="
)

VEIP_SANDBOX_TRUST_ANCHOR = WarrantTrustAnchor(
    root_kid=VEIP_SANDBOX_ROOT_KID,
    public_key_b64=VEIP_SANDBOX_ROOT_PUBLIC_KEY_B64,
    expected_fingerprint=VEIP_SANDBOX_ROOT_FINGERPRINT,
)

#: The fault modes that map onto a warrant-gate fail-closed path.
SUPPORTED_FAULTS: frozenset[FaultMode] = frozenset(
    {
        FaultMode.NONE,
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.MALFORMED_PAYLOAD,
        FaultMode.UNVERIFIED_SOURCE,
    }
)


def _trust_anchor_from_env() -> WarrantTrustAnchor | None:
    pub_b64 = os.environ.get("PROVIDER_05_MANIFEST_ROOT_PUBLIC_KEY", "").strip()
    fp = os.environ.get("PROVIDER_05_MANIFEST_ROOT_FINGERPRINT", "").strip()
    kid = (
        os.environ.get("PROVIDER_05_MANIFEST_ROOT_KID", "").strip()
        or VEIP_SANDBOX_ROOT_KID
    )
    if pub_b64 and fp:
        return WarrantTrustAnchor(
            root_kid=kid,
            public_key_b64=pub_b64,
            expected_fingerprint=fp,
        )
    return None


def _validate_endpoint_scheme(endpoint: str) -> None:
    if not endpoint.startswith(("https://", "http://")):
        raise ValueError(
            f"Unsupported endpoint URL scheme for {endpoint!r}; "
            "must start with 'https://' or 'http://'"
        )


class Provider05WarrantSource:
    """VEIP warrant source implementing the kernel ``WarrantSource`` seam."""

    def __init__(
        self,
        endpoint: str = "",
        *,
        scenario: str = "",
        trust_anchor: WarrantTrustAnchor | None = None,
        timeout: float | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        raw_endpoint = (
            endpoint or os.environ.get("PROVIDER_05_ATTESTATION_ENDPOINT", "")
        ).strip()
        self._endpoint = raw_endpoint.rstrip("/")
        if self._endpoint:
            _validate_endpoint_scheme(self._endpoint)
        self._scenario = (
            scenario or os.environ.get("PROVIDER_05_WARRANT_SCENARIO", "")
        ).strip()
        self._explicit_trust_anchor = trust_anchor or _trust_anchor_from_env()
        env_timeout = float(os.environ.get("PROVIDER_05_TIMEOUT_SECONDS", "5.0"))
        self._timeout = timeout if timeout is not None else env_timeout
        self._http_client = http_client
        self._warrants: dict[str, Warrant] = {}
        self._key_manifest: Mapping[str, Any] | VerifiedKeyManifest | None = None
        self._fault = FaultMode.NONE

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def scenario(self) -> str:
        return self._scenario

    @property
    def trust_anchor(self) -> WarrantTrustAnchor | None:
        """Out-of-band root trust anchor for v0.2 key manifest verification.

        Returns ``None`` only when operating in unconfigured, unsigned v0.1
        seeded mode so existing v0.1 tests run unchanged.
        """
        if self._explicit_trust_anchor is not None:
            return self._explicit_trust_anchor
        if (
            self._key_manifest is not None
            or self._endpoint
            or any(w.is_v02 for w in self._warrants.values())
        ):
            return VEIP_SANDBOX_TRUST_ANCHOR
        return None

    def seed(self, warrant: Warrant) -> None:
        """Seed the issuer's current warrant for its ``norm_id``.

        The warrant is stored exactly as issued, including its declared digest;
        a later seed for the same norm replaces it (e.g. a revocation).
        """
        self._warrants[warrant.norm_id] = warrant

    def seed_key_manifest(
        self, manifest: Mapping[str, Any] | VerifiedKeyManifest | None
    ) -> None:
        """Seed the key manifest for hermetic v0.2 verification tests."""
        self._key_manifest = manifest

    @property
    def fault_mode(self) -> FaultMode:
        return self._fault

    def inject_fault(self, mode: FaultMode | str) -> None:
        """Make every later ``fetch()`` fail in ``mode`` until cleared.

        Raises:
            ValueError: ``mode`` is not a FaultMode, or has no warrant
                meaning (see ``SUPPORTED_FAULTS``).
        """
        fault = FaultMode(mode)
        if fault not in SUPPORTED_FAULTS:
            raise ValueError(
                f"fault mode {fault.value!r} has no warrant-source meaning; "
                f"supported: {sorted(f.value for f in SUPPORTED_FAULTS)}"
            )
        self._fault = fault

    def clear_fault(self) -> None:
        self._fault = FaultMode.NONE

    def _apply_warrant_fault(self, warrant: Warrant) -> Any:
        fault = self._fault
        if fault is FaultMode.MALFORMED_PAYLOAD:
            return warrant.to_dict()
        if fault is FaultMode.UNVERIFIED_SOURCE:
            return Warrant(
                **{
                    **warrant.to_dict(),
                    "issuing_authority": "rewritten in transit",
                }
            )
        return warrant

    async def fetch_key_manifest(
        self,
    ) -> Mapping[str, Any] | VerifiedKeyManifest | None:
        """Fetch the VEIP v0.2 key manifest (seeded or ``/.well-known/veip/key-manifest.json``)."""
        fault = self._fault
        if fault is FaultMode.TIMEOUT:
            raise TimeoutError("simulated VEIP key manifest fetch timeout")
        if fault is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated VEIP key manifest connection error")
        if self._key_manifest is not None:
            return self._key_manifest
        if not self._endpoint:
            return None

        url = f"{self._endpoint}/.well-known/veip/key-manifest.json"
        data = await self._http_get_json(url)
        return data

    async def fetch(self, norm_id: str) -> Any:
        """Return the warrant for ``norm_id``, or ``None`` (MISSING).

        Under an injected fault the answer is the fault's (see module
        docstring), which is why the return type is not narrowed to
        ``Warrant | None``.
        """
        fault = self._fault
        if fault is FaultMode.TIMEOUT:
            raise TimeoutError("simulated VEIP warrant fetch timeout")
        if fault is FaultMode.CONNECTION_ERROR:
            raise ConnectionError("simulated VEIP warrant connection error")
        warrant = self._warrants.get(norm_id)
        if warrant is not None:
            return self._apply_warrant_fault(warrant)
        if not self._endpoint:
            return None

        encoded_norm = quote(norm_id, safe="._-")
        url = f"{self._endpoint}/v0.2/warrants/{encoded_norm}"
        params = {"scenario": self._scenario} if self._scenario else None
        payload = await self._http_get_json(url, params=params)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise ConnectionError("VEIP warrant endpoint returned non-object JSON")
        try:
            fetched = Warrant(**dict(payload))
        except TypeError as exc:
            raise ConnectionError(f"Malformed VEIP warrant payload: {exc}") from exc
        return self._apply_warrant_fault(fetched)

    async def _http_get_json(
        self, url: str, *, params: Mapping[str, str] | None = None
    ) -> dict[str, Any] | None:
        _validate_endpoint_scheme(url)
        try:
            if self._http_client is not None:
                response = await self._http_client.get(
                    url, params=params, timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(url, params=params)
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"VEIP HTTP request timed out for {url}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise ConnectionError(f"VEIP HTTP request failed for {url}: {exc}") from exc

        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ConnectionError(
                f"VEIP endpoint {url} returned HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise ConnectionError(f"VEIP endpoint {url} returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise ConnectionError(f"VEIP endpoint {url} returned non-dict JSON")
        return body
