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

"""Keep ``GATEWAY_URL`` unset across every hermetic test session.

Hermetic suites (including the ``us_fed``, ``eu_ecb``, and ``apac_mas``
regional posture suites) must never target a live or port-forwarded gateway.
If ``GATEWAY_URL`` is present in the environment—either exported in the caller's
shell or populated as a default by ``tests/conftest.py``—the first hermetic test
that reads ``GATEWAY_URL`` reaches whatever listens on that endpoint (such as a
``kubectl port-forward`` tunnel on ``localhost:8080``) and lands unmarked
synthetic traffic in the deployed evidence chain and Lula counts.

Two rules hold hermetic runs closed by construction:

1. Session startup (:func:`refusal`): a hermetic session (none of
   :data:`~tests.fixtures.dotenv_guard.LIVE_RUN_OPTIONS` passed) refuses to
   start if ``GATEWAY_URL`` is set in ``os.environ``.
2. Per-test invariant (``assert_hermetic_gateway_url_unset`` in
   ``tests/conftest.py``): every test in a hermetic session asserts
   ``"GATEWAY_URL" not in os.environ`` before running and after fixture
   teardown, so any test that mutates ``GATEWAY_URL`` without ``monkeypatch``
   fails closed immediately.

Live sessions (:func:`is_live_session`) are exempt and keep the
``http://localhost:8080`` port-forward default when ``GATEWAY_URL`` is unset or
holds a cluster-internal placeholder.
"""

from __future__ import annotations

import pytest

from tests.fixtures.dotenv_guard import LIVE_RUN_OPTIONS

GATEWAY_URL_ENV_VAR = "GATEWAY_URL"


def is_live_session(config: pytest.Config) -> bool:
    """Return ``True`` when any live-target CLI flag is enabled on ``config``."""
    return any(
        bool(config.getoption(option, default=False)) for option in LIVE_RUN_OPTIONS
    )


def refusal(gateway_url: str | None, *, live_run: bool) -> str | None:
    """Return why a session must not start, or ``None`` when allowed."""
    if live_run or gateway_url is None:
        return None
    flags = ", ".join(LIVE_RUN_OPTIONS)
    return (
        "Refusing to start a hermetic test session with "
        f"{GATEWAY_URL_ENV_VAR}={gateway_url!r} set in the environment.\n"
        "Hermetic and regional posture tests must run with GATEWAY_URL unset so\n"
        "no test can reach a live or port-forwarded gateway (e.g. localhost:8080)\n"
        "and record synthetic traffic in a deployed evidence chain.\n"
        "Unset it for hermetic runs:\n"
        "  env -u GATEWAY_URL uv run pytest ...\n"
        f"Or pass a live-run flag ({flags}) when targeting a deployed stack."
    )
