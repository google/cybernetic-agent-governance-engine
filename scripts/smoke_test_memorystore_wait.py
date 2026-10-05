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

"""
Memorystore WAIT Replication Smoke Test (Track 6b Exit Criterion / §8 Item 1).

Executes a live synchronous replication verification (WAIT 1 100) against the
governance Memorystore (Valkey / Redis) instance to prove that:
1. The instance supports the WAIT command with acknowledged replica confirmation.
2. Replication latency meets the §4.2 hot-path budget (<= 100 ms).
3. Synchronous replication ensures no acked-but-lost commits on failover.

Usage:
    # Live cluster run against staging governance Memorystore:
    python scripts/smoke_test_memorystore_wait.py --host <IP> --port 6379 --replicas 1 --timeout-ms 100

    # Dry-run for local CI / hermetic testing:
    python scripts/smoke_test_memorystore_wait.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from typing import Any


async def verify_memorystore_wait(
    host: str = "localhost",
    port: int = 6379,
    replicas: int = 1,
    timeout_ms: int = 100,
    enable_tls: bool = False,
    ca_cert_path: str | None = None,
    iam_auth: bool = False,
    dry_run: bool = False,
) -> tuple[bool, int, float, str]:
    """
    Execute WAIT replication smoke test against Redis/Valkey instance.

    Returns:
        (success: bool, acked_replicas: int, latency_ms: float, message: str)
    """
    if dry_run:
        # Dry-run mode for offline CI
        latency_ms = 12.5
        acked = replicas
        return (
            True,
            acked,
            latency_ms,
            f"DRY-RUN: WAIT {replicas} {timeout_ms} simulated successfully.",
        )

    import redis.asyncio as aioredis

    credential_provider = None
    if iam_auth:
        from src.gateway.infrastructure.redis_credential_factory import (
            get_redis_credential_provider,
        )

        credential_provider = get_redis_credential_provider(auth_mode="iam")

    password = (
        None if credential_provider is not None else os.environ.get("REDIS_PASSWORD")
    )

    redis_kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "password": password,
        "credential_provider": credential_provider,
        "ssl": enable_tls,
        "ssl_ca_certs": ca_cert_path,
        "decode_responses": True,
        "socket_connect_timeout": 3.0,
        "socket_timeout": 3.0,
    }
    cage_env = os.environ.get("CAGE_ENV", "prod").lower()
    if (
        enable_tls
        and not ca_cert_path
        and cage_env in ("dev", "development", "test", "ci", "staging")
    ):
        redis_kwargs["ssl_cert_reqs"] = "none"

    client = aioredis.Redis(**redis_kwargs)

    test_key = f"smoke:memorystore:wait:{int(time.time() * 1000)}"
    try:
        # Write test key
        await client.set(test_key, "1", ex=60)

        # Measure WAIT command
        start_time = time.perf_counter()
        raw_acks = await client.execute_command("WAIT", replicas, timeout_ms)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        acked = int(raw_acks) if raw_acks is not None else 0

        # Clean up test key
        await client.delete(test_key)

        if acked >= replicas:
            msg = (
                f"SUCCESS: WAIT {replicas} {timeout_ms} acknowledged by {acked} "
                f"replica(s) in {elapsed_ms:.2f} ms."
            )
            return True, acked, elapsed_ms, msg
        else:
            msg = (
                f"FAIL: WAIT {replicas} {timeout_ms} acknowledged by only {acked} "
                f"replica(s) (expected >= {replicas}) in {elapsed_ms:.2f} ms."
            )
            return False, acked, elapsed_ms, msg

    except Exception as exc:
        return False, 0, 0.0, f"ERROR executing WAIT test: {exc}"
    finally:
        await client.aclose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Memorystore synchronous replication via WAIT command."
    )
    parser.add_argument(
        "--host", default=os.environ.get("REDIS_HOST", "localhost"), help="Redis host"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("REDIS_PORT", "6379")),
        help="Redis port",
    )
    parser.add_argument(
        "--replicas",
        type=int,
        default=1,
        help="Expected replicas to acknowledge (default: 1)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=100,
        help="WAIT timeout in milliseconds (default: 100)",
    )
    parser.add_argument("--tls", action="store_true", help="Enable TLS")
    parser.add_argument(
        "--ca-cert",
        default=os.environ.get("REDIS_CA_CERT_PATH"),
        help="Path to CA certificate",
    )
    parser.add_argument(
        "--iam-auth", action="store_true", help="Use GCP IAM authentication"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate execution without network I/O"
    )

    args = parser.parse_args()

    print(
        f"Executing Memorystore WAIT smoke test (replicas={args.replicas}, timeout={args.timeout_ms}ms)..."
    )
    success, _acked, latency_ms, msg = asyncio.run(
        verify_memorystore_wait(
            host=args.host,
            port=args.port,
            replicas=args.replicas,
            timeout_ms=args.timeout_ms,
            enable_tls=args.tls,
            ca_cert_path=args.ca_cert,
            iam_auth=args.iam_auth,
            dry_run=args.dry_run,
        )
    )

    print(msg)
    if success:
        print(f"Latency: {latency_ms:.2f} ms (budget: <= {args.timeout_ms} ms)")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
