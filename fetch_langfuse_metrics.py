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
import sys
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

PK = os.getenv("LANGFUSE_PUBLIC_KEY")
SK = os.getenv("LANGFUSE_SECRET_KEY")
HOST = os.getenv("LANGFUSE_HOST", "http://localhost:3000")

if not PK or not SK:
    print("ERROR: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set in the environment.")
    sys.exit(1)

auth = HTTPBasicAuth(PK, SK)

def fetch_data():
    try:
        # Fetch generations
        print("Fetching GENERATION observations...")
        url = f"{HOST}/api/public/observations"
        res = requests.get(url, auth=auth, params={"type": "GENERATION", "public": "false", "limit": 100})
        res.raise_for_status()
        obs_data = res.json().get('data', [])
        
        ttfts = []
        for obs in obs_data:
            start = obs.get('startTime')
            comp = obs.get('completionStartTime')
            name = obs.get('name', 'unknown')
            trace_id = obs.get('traceId')
            
            if start and comp:
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                comp_dt = datetime.fromisoformat(comp.replace("Z", "+00:00"))
                ttft_ms = (comp_dt - start_dt).total_seconds() * 1000
                ttfts.append(ttft_ms)
                print(f"Generation [Trace: {trace_id}] -> TTFT: {ttft_ms:.2f}ms | Latency: {obs.get('latency')}s")
        
        if ttfts:
            avg_ttft = sum(ttfts) / len(ttfts)
            print(f"---\nAverage TTFT: {avg_ttft:.2f}ms")
        else:
            print("No TTFT data found in GENERATION observations.")

        print("\nFetching SPAN observations for overhead analysis...")
        res = requests.get(url, auth=auth, params={"type": "SPAN", "public": "false", "limit": 100})
        res.raise_for_status()
        span_data = res.json().get('data', [])
        for span in span_data[:20]:
            name = span.get('name', '').lower()
            if 'injection' in name or 'identity-tag' in name or 'financial-advisor-sa' in name:
                 print(f"Overhead Span: {name} | Latency: {span.get('latency')}s")
                 
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fetch_data()
