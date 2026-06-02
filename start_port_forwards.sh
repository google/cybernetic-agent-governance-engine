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

source .env

pkill -f "kubectl port-forward" 2>/dev/null
sleep 2

# Check if K8S_NAMESPACE was set
if [ -z "$K8S_NAMESPACE" ]; then
  echo "⚠️ K8S_NAMESPACE not found in .env, defaulting to 'governance-stack'"
  K8S_NAMESPACE="governance-stack"
fi

echo "Using namespace: $K8S_NAMESPACE"

# governed-financial-advisor: svc port 8080 → local 8081 (matches BACKEND_URL default)
kubectl port-forward svc/governed-financial-advisor 8081:8080 -n "$K8S_NAMESPACE" >/tmp/pf_backend.log 2>&1 </dev/null &
# OPA: 8181:8181 (correct service name: opa-service)
kubectl port-forward svc/opa-service 8181:8181 -n "$K8S_NAMESPACE" >/tmp/pf_opa.log 2>&1 </dev/null &
# Redis: 6379:6379 (correct service name: redis)
kubectl port-forward svc/redis 6379:6379 -n "$K8S_NAMESPACE" >/tmp/pf_redis.log 2>&1 </dev/null &
# vLLM reasoning (judge LLM for langfuse eval test): 8000:8000
kubectl port-forward svc/vllm-reasoning 8000:8000 -n "$K8S_NAMESPACE" >/tmp/pf_vllm.log 2>&1 </dev/null &
# Gateway: 8080:8080
kubectl port-forward svc/gateway 8080:8080 -n "$K8S_NAMESPACE" >/tmp/pf_gateway.log 2>&1 </dev/null &
# Langfuse: 3001:3000
kubectl port-forward svc/langfuse-web 3001:3000 -n "$K8S_NAMESPACE" >/tmp/pf_langfuse.log 2>&1 </dev/null &

echo "Port-forwards started. Waiting for services to be ready..."
sleep 8
curl -sf http://localhost:8081/health && echo "✓ Backend OK" || echo "✗ Backend health check failed (pod may be in CrashLoopBackOff)"
curl -sf http://localhost:8181/health && echo "✓ OPA OK" || echo "✗ OPA health check failed"
redis-cli -p 6379 ping 2>/dev/null && echo "✓ Redis OK" || echo "✗ Redis check skipped"
curl -sf http://localhost:8000/health 2>/dev/null && echo "✓ vLLM-reasoning OK" || echo "✗ vLLM-reasoning not responding"
curl -sf http://localhost:8080/health 2>/dev/null && echo "✓ Gateway OK" || echo "✗ Gateway not responding"
curl -sf http://localhost:3001 2>/dev/null >/dev/null && echo "✓ Langfuse OK" || echo "✗ Langfuse not responding"
