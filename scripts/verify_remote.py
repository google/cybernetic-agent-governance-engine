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

import requests
import sys

BASE_URL = "https://governed-financial-advisor-bhsafl7fda-uc.a.run.app"

def verify_deployment():
    print(f"🔍 Verifying deployment at {BASE_URL}...")
    endpoints = ["/", "/health", "/v1/models"]
    success = False
    
    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        try:
            print(f"Testing {url}...")
            resp = requests.get(url, timeout=10)
            print(f"Status: {resp.status_code}")
            if resp.status_code < 500:
                print("✅ Service is reachable.")
                success = True
            else:
                print("⚠️ Service returned server error.")
        except Exception as e:
            print(f"❌ Failed to request {url}: {e}")
            
    if success:
        print("🚀 Deployment verification PASSED (Service is reachable).")
        return 0
    else:
        print("❌ Deployment verification FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(verify_deployment())
