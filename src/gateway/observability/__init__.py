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
"""Gateway observability package (OTel span attributes, Langfuse helpers, and Prometheus loop-lag monitor)."""

from src.gateway.observability.loop_monitor import (
    DEFAULT_LOOP_LAG_INTERVAL_SECONDS,
    DEFAULT_METRICS_PORT,
    EVENT_LOOP_LAG_SECONDS,
    MetricsServerHandle,
    record_loop_lag,
    run_loop_lag_monitor,
    start_metrics_http_server,
)

__all__ = [
    "DEFAULT_LOOP_LAG_INTERVAL_SECONDS",
    "DEFAULT_METRICS_PORT",
    "EVENT_LOOP_LAG_SECONDS",
    "MetricsServerHandle",
    "record_loop_lag",
    "run_loop_lag_monitor",
    "start_metrics_http_server",
]
