#!/usr/bin/env python3
import requests
import uuid
import time
import sys

BASE_URL = "http://localhost:3002"

_OSCAL_PASS_TEMPLATE = """\
assessment-results:
  uuid: "live-pass-{uid}"
  metadata:
    last-modified: "2026-05-21T00:00:00Z"
    version: "1.0"
  results:
    - uuid: "live-result-pass-{uid}"
      findings:
        - uuid: "live-f1-{uid}"
          title: "A.5.2 Social Impact Assessment"
          target:
            type: objective-id
            target-id: "A.5.2"
            status:
              state: "satisfied"
        - uuid: "live-f2-{uid}"
          title: "A.5.3 Logging and Monitoring"
          target:
            type: objective-id
            target-id: "A.5.3"
            status:
              state: "satisfied"
"""

_OSCAL_FAIL_TEMPLATE = """\
assessment-results:
  uuid: "live-fail-{uid}"
  metadata:
    last-modified: "2026-05-21T00:00:00Z"
    version: "1.0"
  results:
    - uuid: "live-result-fail-{uid}"
      findings:
        - uuid: "live-f1-{uid}"
          title: "A.9.2 Data Transfer to Suppliers"
          target:
            type: objective-id
            target-id: "A.9.2"
            status:
              state: "not-satisfied"
        - uuid: "live-f2-{uid}"
          title: "SC-4 Fiscal Limits and RBAC"
          target:
            type: objective-id
            target-id: "SC-4"
            status:
              state: "not-satisfied"
"""

def generate_uid():
    return uuid.uuid4().hex[:10]

def check_health():
    print(f"🔍 Checking health of compliance-bridge at {BASE_URL}...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code == 200:
            print(f"✅ compliance-bridge is healthy: {r.json()}")
            return True
        else:
            print(f"❌ compliance-bridge returned status {r.status_code}: {r.text}")
            return False
    except Exception as e:
        print(f"❌ Failed to connect to compliance-bridge: {e}")
        return False

def ingest_audit(oscal_yaml, audit_id):
    url = f"{BASE_URL}/v1/audit/ingest"
    payload = {
        "oscal_yaml": oscal_yaml,
        "audit_id": audit_id
    }
    headers = {"Content-Type": "application/json"}
    
    print(f"📤 Ingesting audit '{audit_id}'...")
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        if r.status_code == 200:
            print(f"✅ Ingestion successful: {r.json()}")
        else:
            print(f"❌ Ingestion failed with status {r.status_code}: {r.text}")
    except Exception as e:
        print(f"❌ Error sending request: {e}")

def main():
    if not check_health():
        print("\n⚠️ Please ensure port-forwarding is active on port 3002:")
        print("  kubectl port-forward svc/compliance-bridge 3002:80 -n governance-stack")
        sys.exit(1)
        
    print("\n🚀 Starting Live Trace Generation Stream...")
    
    # 1. Ingest a PASS audit
    uid1 = generate_uid()
    audit_id1 = f"inttest-f1-{uid1}"
    ingest_audit(_OSCAL_PASS_TEMPLATE.format(uid=uid1), audit_id1)
    
    print("⏳ Waiting 3 seconds for the dashboard to receive the PASS stream...")
    time.sleep(3)
    
    # 2. Ingest a FAIL audit (triggers a critical alert popup)
    uid2 = generate_uid()
    audit_id2 = f"inttest-f2-{uid2}"
    ingest_audit(_OSCAL_FAIL_TEMPLATE.format(uid=uid2), audit_id2)
    
    print("⏳ Waiting 3 seconds for the dashboard to receive the FAIL stream...")
    time.sleep(3)
    
    # 3. Ingest another PASS audit
    uid3 = generate_uid()
    audit_id3 = f"inttest-f1-{uid3}"
    ingest_audit(_OSCAL_PASS_TEMPLATE.format(uid=uid3), audit_id3)
    
    print("⏳ Waiting 3 seconds for another PASS stream...")
    time.sleep(3)
    
    # 4. Ingest another FAIL audit
    uid4 = generate_uid()
    audit_id4 = f"inttest-f2-{uid4}"
    ingest_audit(_OSCAL_FAIL_TEMPLATE.format(uid=uid4), audit_id4)
    
    print("\n🎉 Live traces generated successfully! Check your dashboard at http://localhost:3000")

if __name__ == "__main__":
    main()
