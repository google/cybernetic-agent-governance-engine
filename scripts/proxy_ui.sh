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

echo "🔍 Finding UI Service in namespace 'governance-stack'..."
POD=$(kubectl get pod -n governance-stack -l app=financial-advisor-ui -o jsonpath="{.items[0].metadata.name}")

if [ -z "$POD" ]; then
    echo "❌ UI Pod not found! Is it deployed?"
    exit 1
fi

echo "✅ Found UI Pod: $POD"
echo "🚀 Port-forwarding to http://localhost:8080..."
echo "Press Ctrl+C to stop."

kubectl port-forward -n governance-stack pod/$POD 8080:8501
