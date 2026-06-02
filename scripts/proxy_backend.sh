#!/bin/bash
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

PORT=${PORT:-8081}
NAMESPACE="governance-stack"

SERVICE="service/governed-financial-advisor"

# Ensure kubectl is in path
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl could not be found. Please install it."
    exit 1
fi

echo "🚀 Starting Proxy to Backend Service on GKE..."
echo "🔗 Local URL: http://localhost:$PORT"
echo "ℹ️  Press Ctrl+C to stop."

# Port forward to service port 80 relative to the service 
# (The service maps 80 -> 8080 on container, so we forward to service port 80)
kubectl port-forward -n $NAMESPACE $SERVICE $PORT:80
