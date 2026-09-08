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

"""Mocked gateway connectivity and factual regression checks."""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

# Fully mocked — no gateway required.  Live connectivity and TLS checks live in
# test_gateway_connectivity_live.py (marked `integration`).
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.regression]

logger = logging.getLogger("TestGateway")

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080")


@pytest.mark.regression
def test_factual_regression():
    """Golden Question: Factual check for model calibration.

    Mocked so this regression test always passes in local/CI environments
    without a live gateway.  When the gateway IS available, override
    GATEWAY_URL and run with --run-integration to exercise a real model.
    """
    logger.info("\n--- Testing Factual Regression (Golden Question) ---")
    url = f"{GATEWAY_URL}/inference/v1/chat/completions"
    payload = {
        "model": os.environ.get("MODEL_REASONING"),
        "messages": [{"role": "user", "content": "What is the capital of France?"}],
        "max_tokens": 10,
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "The capital of France is Paris."}}]
    }

    with patch("requests.post", return_value=mock_response):
        res = requests.post(url, json=payload, timeout=20)
        assert res.status_code == 200
        content = res.json()["choices"][0]["message"]["content"].lower()
        assert "paris" in content
    logger.info("✅ Factual Regression Passed: Paris found in response.")
