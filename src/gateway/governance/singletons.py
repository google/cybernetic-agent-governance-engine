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

import logging
import os
from src.gateway.core.policy import OPAClient
from src.gateway.governance.consensus import consensus_engine
from src.gateway.governance.cbf import safety_filter
from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator as STPAValidator
from src.gateway.governance.symbolic_governor import SymbolicGovernor
from src.gateway.governance.fiscal_limit_guard import FiscalLimitGuard

logger = logging.getLogger("Gateway.Governance.Singletons")

# Singleton Instances
opa_client = OPAClient()
stpa_validator = STPAValidator()

# FiscalLimitGuard requires a synchronous redis.Redis client (uses WATCH/MULTI/EXEC
# optimistic locking via redis-py's sync pipeline API).  We construct it here from
# the same REDIS_URL / REDIS_HOST / REDIS_PORT environment variables used by the
# async gateway Redis client so that both clients target the same Redis instance.
fiscal_limit_guard: FiscalLimitGuard | None = None
try:
    import redis as _sync_redis  # type: ignore[import]

    _redis_url = os.environ.get("REDIS_URL", "")
    if _redis_url:
        _sync_redis_client = _sync_redis.from_url(_redis_url, decode_responses=True)
    else:
        _redis_host = os.environ.get("REDIS_HOST", "localhost")
        _redis_port = int(os.environ.get("REDIS_PORT", "6379"))
        _redis_db = int(os.environ.get("REDIS_DB", "0"))
        _redis_password = os.environ.get("REDIS_PASSWORD") or None
        _sync_redis_client = _sync_redis.Redis(
            host=_redis_host,
            port=_redis_port,
            db=_redis_db,
            password=_redis_password,
            decode_responses=True,
            socket_connect_timeout=3.0,
            socket_timeout=3.0,
        )

    _daily_cap_usd = float(os.environ.get("FISCAL_DAILY_CAP_USD", "500000"))
    fiscal_limit_guard = FiscalLimitGuard(
        redis_client=_sync_redis_client,
        daily_cap_usd=_daily_cap_usd,
    )
    logger.info(
        "✅ FiscalLimitGuard initialised (daily_cap=%.0f USD).", _daily_cap_usd
    )
except ImportError:
    logger.warning(
        "⚠️ redis-py (sync) not installed — FiscalLimitGuard disabled. "
        "Install with: pip install redis"
    )
except Exception as _flg_exc:
    logger.warning(
        "⚠️ FiscalLimitGuard could not be initialised (%s) — fiscal limit "
        "pre-reservation will be skipped.",
        _flg_exc,
    )

symbolic_governor = SymbolicGovernor(
    opa_client=opa_client,
    safety_filter=safety_filter,
    consensus_engine=consensus_engine,
    stpa_validator=stpa_validator,
    fiscal_limit_guard=fiscal_limit_guard,
)

logger.info("✅ Governance Singletons Initialized.")
