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

import os
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

pytestmark = pytest.mark.unit
from src.governed_financial_advisor.infrastructure.redis_client import RedisClient

class TestRedisConfig(unittest.TestCase):
    @patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379", "REDIS_PORT": "tcp://10.0.0.1:6379", "REDIS_HOST": "localhost"})
    def test_k8s_port_collision(self):
        """Test that K8s service port collision (tcp:// string) is ignored."""
        client = RedisClient()
        self.assertEqual(client.redis_port, 6379)
        self.assertEqual(client.redis_host, "localhost")

    @patch.dict(os.environ, {"REDIS_URL": "redis://myredis:1234", "REDIS_PORT": "tcp://10.10.10.10:1234"})
    def test_url_precedence(self):
        """Test that REDIS_URL parsing works even with collision."""
        # Note: In my implementation, I specifically use default if collision happens.
        # But if REDIS_URL is present, I also parse it.
        # Let's verify what happens.
        # My code uses os.getenv("REDIS_HOST", default_host) where default_host comes from URL.
        client = RedisClient()
        self.assertEqual(client.redis_port, 1234)
        self.assertEqual(client.redis_host, "myredis")

    @patch.dict(os.environ, {"REDIS_PORT": "9999"})
    def test_normal_port(self):
        """Test that normal integer port works."""
        client = RedisClient()
        self.assertEqual(client.redis_port, 9999)

if __name__ == "__main__":
    unittest.main()
