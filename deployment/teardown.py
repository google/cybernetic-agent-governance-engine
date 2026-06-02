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

import argparse
import subprocess
import sys

def run_command(command, check=True):
    print(f"🚀 Running: {' '.join(command)}")
    try:
        subprocess.run(command, check=check)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        if check:
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Teardown Cybernetic Governance Engine Resources")
    parser.add_argument("--project-id", required=True, help="Google Cloud Project ID")
    parser.add_argument("--region", default="us-central1", help="GCP Region")
    parser.add_argument("--zone", help="GCP Zone (optional, overrides region for GKE)")
    parser.add_argument("--cluster-name", default="governance-cluster", help="GKE Cluster Name")
    parser.add_argument("--service-name", default="financial-advisor-ui", help="Cloud Run UI Service Name")
    
    args = parser.parse_args()
    
    print("⚠️  STARTING TEARDOWN ⚠️")
    print("This will delete the GKE cluster, Cloud Run service, and Secret Manager secrets.")
    
    # 1. Delete Cloud Run Service
    print("\n--- 🗑️ Deleting Cloud Run Services ---")
    services = [args.service_name, "governed-financial-advisor"]
    for svc in services:
        run_command([
            "gcloud", "run", "services", "delete", svc,
            "--region", args.region,
            "--project", args.project_id,
            "--quiet"
        ], check=False)

    # 2. Delete GKE Cluster
    print("\n--- 🗑️ Deleting GKE Cluster ---")
    location_flag = "--zone" if args.zone else "--region"
    location_value = args.zone if args.zone else args.region
    run_command([
        "gcloud", "container", "clusters", "delete", args.cluster_name,
        location_flag, location_value,
        "--project", args.project_id,
        "--quiet"
    ], check=False)

    # 3. Delete Secrets
    print("\n--- 🗑️ Deleting Secrets ---")
    secrets = ["opa-auth-token", "system-authz-policy", "finance-policy-rego", "opa-configuration", "hf-token-secret"]
    for s in secrets:
        run_command([
            "gcloud", "secrets", "delete", s,
            "--project", args.project_id,
            "--quiet"
        ], check=False)

    # 4. Delete Network Resources
    print("\n--- 🗑️ Deleting Network Resources (NAT/Router) ---")
    router_name = f"nat-router-{args.region}"
    nat_name = f"nat-config-{args.region}"
    
    run_command([
        "gcloud", "compute", "routers", "nats", "delete", nat_name,
        "--router", router_name,
        "--region", args.region,
        "--project", args.project_id,
        "--quiet"
    ], check=False)
    
    run_command([
        "gcloud", "compute", "routers", "delete", router_name,
        "--region", args.region,
        "--project", args.project_id,
        "--quiet"
    ], check=False)

    # 5. Delete Redis Instance
    print("\n--- 🗑️ Deleting Redis Instance ---")
    run_command([
        "gcloud", "redis", "instances", "delete", "financial-advisor-redis",
        "--region", args.region,
        "--project", args.project_id,
        "--quiet"
    ], check=False)

    print("\n✅ Teardown Complete. Verify in Cloud Console.")

if __name__ == "__main__":
    main()
