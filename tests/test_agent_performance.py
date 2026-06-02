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
from unittest.mock import MagicMock, patch, AsyncMock
import pytest
from dotenv import load_dotenv

pytestmark = pytest.mark.integration

# Load env vars
load_dotenv()

# Configuration Defaults
DEFAULT_AGENT_URL = os.getenv("BACKEND_URL", "http://localhost:8080")

class AgentBenchmark:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.endpoint = f"{self.base_url}/agent/query"
        print(f"🔧 Initialized Benchmark for Agent @ {self.endpoint}")

    def run_inference(self, prompt: str):
        user_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4()) # Assuming a session_id is needed for the new query_agent signature
        
        # The provided "Code Edit" seems to be trying to replace the body of run_inference
        # with a new function's logic, but it's malformed.
        # I will interpret this as replacing the existing run_inference logic
        # with a new structure that aligns with the provided snippet's intent,
        # while making it syntactically correct and functional within the class.
        
        # The snippet uses 'BACKEND_URL' which is not directly available here,
        # but self.endpoint is already set to the correct URL.
        # It also introduces 'session_id' and 'user_id' as 'perf_user'.
        
        payload = {
            "prompt": prompt,
            "user_id": "perf_user", # Hardcoded as per snippet
            "thread_id": session_id # New field from snippet
        }
        
        try:
            start_time = time.time()
            response = requests.post(self.endpoint, json=payload, timeout=120) # Use self.endpoint and original timeout
            response.raise_for_status() # Keep original error handling
            data = response.json()
            end_time = time.time()
            latency = end_time - start_time
            
            content = data.get("response", "")
            
            # Estimate tokens (approx 4 chars per token)
            completion_tokens = len(content) / 4
            prompt_tokens = len(prompt) / 4
            total_tokens = completion_tokens + prompt_tokens
            
            return {
                "latency": latency,
                "completion_tokens": completion_tokens,
                "prompt_tokens": prompt_tokens,
                "total_tokens": total_tokens,
                "throughput": completion_tokens / latency if latency > 0 else 0,
                "content": content
            }
        except Exception as e:
            print(f"❌ Error during inference: {e}")
            return None

def run_benchmark(benchmark, prompt, iterations):
    print(f"\n🚀 Running Agent Benchmark ({iterations} iterations)...")
    print(f"📝 Prompt: {prompt[:50]}...")
    
    results = []
    
    # Warmup
    print("🔥 Warming up (1 request)...")
    benchmark.run_inference(prompt)

    for i in range(iterations):
        print(f"  Iteration {i+1}/{iterations}...", end="", flush=True)
        stats = benchmark.run_inference(prompt)
        if stats:
            results.append(stats)
            print(f" {stats['latency']:.3f}s | ~{int(stats['completion_tokens'])} tok | {stats['throughput']:.1f} tok/s")
        else:
            print(" Failed")

    if not results:
        print("❌ No successful results.")
        return

    # Calculate aggregate metrics
    latencies = [r["latency"] for r in results]
    throughputs = [r["throughput"] for r in results]
    
    avg_latency = statistics.mean(latencies)
    if len(latencies) > 1:
        metrics_p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    else:
        metrics_p95 = latencies[0]

    avg_throughput = statistics.mean(throughputs)
    
    print("\n🏆 Benchmark Results")
    print("-" * 50)
    print(f"Target:             {benchmark.endpoint}")
    print(f"Successful Requests: {len(results)}/{iterations}")
    print(f"Avg Latency:        {avg_latency:.3f} s")
    print(f"P95 Latency:        {metrics_p95:.3f} s")
    print(f"Avg Throughput:     {avg_throughput:.1f} tokens/s (estimated)")
    print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="Agent Performance Benchmark")
    parser.add_argument("--url", default=DEFAULT_AGENT_URL, help="Agent Base URL")
    parser.add_argument("--iterations", type=int, default=5, help="Number of requests")
    parser.add_argument("--prompt", default="Analyze the stock performance of AAPL.", help="Prompt to use")
    
    args = parser.parse_args()
    
    benchmark = AgentBenchmark(args.url)
    run_benchmark(benchmark, args.prompt, args.iterations)

if __name__ == "__main__":
    main()
