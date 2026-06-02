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
import time
import argparse
import statistics
from dotenv import load_dotenv
from openai import OpenAI

# Load env vars
load_dotenv()

# Configuration Defaults
DEFAULT_VLLM_API_BASE = os.getenv("VLLM_API_BASE", "http://localhost:8000/v1")
DEFAULT_MODEL_NAME = os.getenv("MODEL_FAST")

class VLLMBenchmark:
    def __init__(self, base_url, model_name, api_key="EMPTY"):
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model_name = model_name
        print(f"🔧 Initialized Benchmark for Model: {self.model_name} @ {base_url}")

    def run_inference(self, prompt: str, max_tokens: int = 256):
        start_time = time.time()
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.7
            )
            end_time = time.time()
            latency = end_time - start_time
            
            # Extract token usage
            usage = response.usage
            completion_tokens = usage.completion_tokens if usage else 0
            prompt_tokens = usage.prompt_tokens if usage else 0
            total_tokens = usage.total_tokens if usage else 0
            
            return {
                "latency": latency,
                "completion_tokens": completion_tokens,
                "prompt_tokens": prompt_tokens,
                "total_tokens": total_tokens,
                "throughput": completion_tokens / latency if latency > 0 else 0,
                "content": response.choices[0].message.content
            }
        except Exception as e:
            print(f"❌ Error during inference: {e}")
            return None

def run_benchmark(benchmark, prompt, iterations):
    print(f"\n🚀 Running Benchmark ({iterations} iterations)...")
    print(f"📝 Prompt: {prompt[:50]}...")
    
    results = []
    
    # Warmup
    print("🔥 Warming up (1 request)...")
    benchmark.run_inference(prompt, max_tokens=10)

    for i in range(iterations):
        print(f"  Iteration {i+1}/{iterations}...", end="", flush=True)
        stats = benchmark.run_inference(prompt)
        if stats:
            results.append(stats)
            print(f" {stats['latency']:.3f}s | {stats['completion_tokens']} tok | {stats['throughput']:.1f} tok/s")
        else:
            print(" Failed")

    if not results:
        print("❌ No successful results.")
        return

    # Calculate aggregate metrics
    latencies = [r["latency"] for r in results]
    throughputs = [r["throughput"] for r in results]
    
    avg_latency = statistics.mean(latencies)
    # Handle single sample case for median/p95
    if len(latencies) > 1:
        metrics_p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    else:
        metrics_p95 = latencies[0]

    avg_throughput = statistics.mean(throughputs)
    
    print("\n🏆 Benchmark Results")
    print("-" * 50)
    print(f"Model:              {benchmark.model_name}")
    print(f"Successful Requests: {len(results)}/{iterations}")
    print(f"Avg Latency:        {avg_latency:.3f} s")
    print(f"P95 Latency:        {metrics_p95:.3f} s")
    print(f"Avg Throughput:     {avg_throughput:.1f} tokens/s")
    print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="vLLM Performance Benchmark")
    parser.add_argument("--url", default=DEFAULT_VLLM_API_BASE, help="vLLM API Base URL")
    parser.add_argument("--model", default=DEFAULT_MODEL_NAME, help="Model Name")
    parser.add_argument("--iterations", type=int, default=5, help="Number of requests")
    parser.add_argument("--prompt", default="Explain the theory of relativity in simple terms.", help="Prompt to use")
    parser.add_argument("--max-tokens", type=int, default=256, help="Max tokens to generate")
    
    args = parser.parse_args()
    
    benchmark = VLLMBenchmark(args.url, args.model)
    run_benchmark(benchmark, args.prompt, args.iterations)

if __name__ == "__main__":
    main()
