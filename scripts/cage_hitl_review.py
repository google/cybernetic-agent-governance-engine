#!/usr/bin/env python3
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

"""Human-in-the-Loop (HITL) Deferral Queue Reviewer CLI (POAM-2026-196, F-44).

Provides human operators with an authenticated command-line workflow to list
pending deferred actions, inspect their barrier preview and narrow hints, and
submit OIDC-authenticated dual-control approvals against the Compliance Bridge
over a local ``kubectl port-forward`` tunnel:

    kubectl port-forward -n governance-stack svc/compliance-bridge 3001:3001

Usage examples:
    python scripts/cage_hitl_review.py --bridge-url http://127.0.0.1:3001 list

    python scripts/cage_hitl_review.py --bridge-url http://127.0.0.1:3001 \
        inspect <defer_id>

    python scripts/cage_hitl_review.py \
        --bridge-url http://127.0.0.1:3001 \
        --oidc-token "$CAGE_OPERATOR_OIDC_TOKEN" \
        approve <defer_id> \
        --client-data-json "$WEBAUTHN_CLIENT_DATA_JSON" \
        --challenge-binding "$WEBAUTHN_CHALLENGE_BINDING"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BRIDGE_URL = "http://127.0.0.1:3001"


def validate_http_url(url: str) -> str:
    """Validate that ``url`` uses ``http://`` or ``https://`` (Bandit B310 guard)."""
    candidate = (url or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"Invalid bridge URL {url!r}: scheme must be http:// or https:// with a non-empty host."
        )
    return candidate


def _build_headers(
    *,
    internal_token: str | None = None,
    oidc_token: str | None = None,
    include_internal_token: bool = True,
) -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    eff_internal = (
        (
            internal_token
            or os.environ.get("CAGE_INTERNAL_TOKEN")
            or os.environ.get("COMPLIANCE_BRIDGE_INTERNAL_TOKEN")
            or ""
        ).strip()
        if include_internal_token
        else ""
    )
    if eff_internal:
        headers["X-Cage-Internal-Token"] = eff_internal

    eff_oidc = (oidc_token or os.environ.get("CAGE_OPERATOR_OIDC_TOKEN") or "").strip()
    if eff_oidc:
        if (
            eff_oidc.startswith("spiffe://")
            or ".serviceaccount.identity.linkerd." in eff_oidc
        ):
            raise ValueError(
                "Workload SVIDs cannot be used as HITL operator tokens; provide a human OIDC JWT."
            )
        headers["Authorization"] = f"Bearer {eff_oidc}"
        headers["X-Cage-Operator-Token"] = eff_oidc
    elif eff_internal:
        headers["Authorization"] = f"Bearer {eff_internal}"

    return headers


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, Any]]:
    safe_url = validate_http_url(url)
    parsed = urllib.parse.urlparse(safe_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        safe_url,
        data=data,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(  # nosec B310  # scheme validated to http/https above
            req, timeout=timeout
        ) as resp:
            raw = resp.read().decode("utf-8")
            body = json.loads(raw) if raw else {}
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        raw_err = exc.read().decode("utf-8", errors="replace")
        try:
            err_body = json.loads(raw_err)
        except ValueError:
            err_body = {"detail": raw_err}
        return int(exc.code), err_body


def cmd_list(
    bridge_url: str,
    *,
    internal_token: str | None = None,
    oidc_token: str | None = None,
    limit: int = 50,
) -> tuple[int, dict[str, Any]]:
    """Fetch pending deferred tokens from ``GET /v1/defer/pending``."""
    base = validate_http_url(bridge_url)
    url = f"{base}/v1/defer/pending?limit={int(limit)}"
    headers = _build_headers(internal_token=internal_token, oidc_token=oidc_token)
    return _request_json("GET", url, headers=headers)


def cmd_inspect(
    bridge_url: str,
    defer_id: str,
    *,
    internal_token: str | None = None,
    oidc_token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Inspect a specific deferred token by ``defer_id`` from ``GET /v1/defer/pending``."""
    status, data = cmd_list(
        bridge_url,
        internal_token=internal_token,
        oidc_token=oidc_token,
        limit=200,
    )
    if status != 200:
        return status, data
    for item in data.get("pending", []):
        if isinstance(item, dict) and item.get("defer_id") == defer_id:
            return 200, item
    return 404, {"error": "DEFER_TOKEN_NOT_FOUND", "defer_id": defer_id}


def cmd_approve(
    bridge_url: str,
    defer_id: str,
    *,
    oidc_token: str | None = None,
    internal_token: str | None = None,
    client_data_json: str | None = None,
    challenge_binding: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Submit a human OIDC approval to ``POST /v1/defer/{defer_id}/escalate``."""
    del (
        internal_token
    )  # Human OIDC approval never requires workload CAGE_INTERNAL_TOKEN.
    eff_oidc = (oidc_token or os.environ.get("CAGE_OPERATOR_OIDC_TOKEN") or "").strip()
    if not eff_oidc:
        raise ValueError(
            "Human OIDC JWT is required for approval (--oidc-token or CAGE_OPERATOR_OIDC_TOKEN)."
        )
    base = validate_http_url(bridge_url)
    safe_id = urllib.parse.quote(defer_id.strip(), safe="")
    url = f"{base}/v1/defer/{safe_id}/escalate"
    headers = _build_headers(oidc_token=eff_oidc, include_internal_token=False)
    payload: dict[str, Any] = {}
    if client_data_json is not None:
        payload["client_data_json"] = client_data_json
    if challenge_binding is not None:
        payload["challenge_binding"] = challenge_binding
    return _request_json("POST", url, headers=headers, payload=payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cage_hitl_review",
        description="CAGE Human-in-the-Loop (HITL) Deferral Queue Reviewer CLI",
    )
    parser.add_argument(
        "--bridge-url",
        default=os.environ.get("COMPLIANCE_BRIDGE_URL", DEFAULT_BRIDGE_URL),
        help=f"Compliance Bridge base URL (default: {DEFAULT_BRIDGE_URL})",
    )
    parser.add_argument(
        "--internal-token",
        default=None,
        help="Optional bridge service token for internal read endpoints (not used on approve)",
    )
    parser.add_argument(
        "--oidc-token",
        default=None,
        help="Human operator OIDC JWT (defaults to CAGE_OPERATOR_OIDC_TOKEN env var)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List pending deferred tokens")
    list_p.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of pending tokens to return (default: 50)",
    )

    inspect_p = sub.add_parser(
        "inspect", help="Inspect a pending deferred token by defer_id"
    )
    inspect_p.add_argument("defer_id", help="The defer_id to inspect")

    approve_p = sub.add_parser(
        "approve",
        help="Approve a deferred token as an OIDC-authenticated human operator",
    )
    approve_p.add_argument("defer_id", help="The defer_id to approve")
    approve_p.add_argument(
        "--client-data-json",
        default=os.environ.get("CAGE_WEBAUTHN_CLIENT_DATA_JSON"),
        help="Base64url-encoded W3C CollectedClientData JSON (mandatory in enforcing postures)",
    )
    approve_p.add_argument(
        "--challenge-binding",
        default=os.environ.get("CAGE_WEBAUTHN_CHALLENGE_BINDING"),
        help="Hex-encoded 32-byte SHA-256 challenge digest bound to client_data_json",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "list":
            status, body = cmd_list(
                args.bridge_url,
                internal_token=args.internal_token,
                oidc_token=args.oidc_token,
                limit=args.limit,
            )
        elif args.command == "inspect":
            status, body = cmd_inspect(
                args.bridge_url,
                args.defer_id,
                internal_token=args.internal_token,
                oidc_token=args.oidc_token,
            )
        elif args.command == "approve":
            status, body = cmd_approve(
                args.bridge_url,
                args.defer_id,
                oidc_token=args.oidc_token,
                client_data_json=args.client_data_json,
                challenge_binding=args.challenge_binding,
            )
        else:  # pragma: no cover
            parser.error(f"Unknown command: {args.command}")
            return 2
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2

    print(json.dumps(body, indent=2, sort_keys=True))
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
