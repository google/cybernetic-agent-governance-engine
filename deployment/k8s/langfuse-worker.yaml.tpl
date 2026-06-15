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
#
# Template: deployment/k8s/langfuse-worker.yaml.tpl
#
# Region-aware template for the Langfuse worker deployment.
# Converts the static langfuse-worker.yaml to a region-parameterised template
# to satisfy DEP-07 / PATTERN-3 from docs/JURISDICTIONAL_SEPARATION_ANALYSIS.md.
#
# Variables substituted at deploy time by deploy_all.sh via envsubst:
#   ${GOOGLE_CLOUD_LOCATION}   — GCP region (us-central1 | europe-west1 | asia-southeast1)
#   ${CAGE_DEPLOYMENT_REGION}  — Logical jurisdiction (US_FED | EU_ECB | APAC_MAS)
#   ${AWS_S3_REGION}           — S3-compatible region string for GCS HMAC access
#
# Data residency:
#   US_FED  : LANGFUSE_S3_EVENT_UPLOAD_REGION = us-central1   (NIST SP 800-53 SC-28)
#   EU_ECB  : LANGFUSE_S3_EVENT_UPLOAD_REGION = europe-west1  (GDPR Art. 44)
#   APAC_MAS: LANGFUSE_S3_EVENT_UPLOAD_REGION = asia-southeast1 (MAS TRM §4.2)
#
# See docs/JURISDICTIONAL_SEPARATION_ANALYSIS.md DEP-07, PATTERN-3.

apiVersion: apps/v1
kind: Deployment
metadata:
  name: langfuse-worker
  namespace: governance-stack
  labels:
    app: langfuse-worker
    cage.io/iso42001-control: "A.9.2"
    cage.io/deployment-region: "${CAGE_DEPLOYMENT_REGION}"
spec:
  replicas: 2 # Managed by HPA but matching the live baseline
  selector:
    matchLabels:
      app: langfuse-worker
  template:
    metadata:
      labels:
        app: langfuse-worker
    spec:
      serviceAccountName: "financial-advisor-sa"
      securityContext:
        fsGroup: 65532
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      # Cost Optimization: Prefer Spot nodes (soft affinity allows fallback to on-demand)
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 50
              preference:
                matchExpressions:
                  - key: cloud.google.com/gke-spot
                    operator: In
                    values:
                      - "true"
      # Required for GKE Spot node scheduling
      tolerations:
        - key: "cloud.google.com/gke-spot"
          operator: "Equal"
          value: "true"
          effect: "NoSchedule"
        - key: "nvidia.com/gpu"
          operator: "Equal"
          value: "present"
          effect: "NoSchedule"
      terminationGracePeriodSeconds: 120 # Time for async traces to finish
      containers:
        - name: worker
          image: langfuse/langfuse-worker:3
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "sleep 60"]
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: langfuse-db-secrets
                  key: database-url
            - name: CLICKHOUSE_URL
              value: "http://clickhouse.governance-stack.svc.cluster.local:8123"
            - name: CLICKHOUSE_USER
              value: "default"
            - name: CLICKHOUSE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: langfuse-db-secrets
                  key: clickhouse-password
            - name: CLICKHOUSE_PORT
              value: "8123"
            - name: LANGFUSE_INGESTION_CLICKHOUSE_WRITE_INTERVAL_MS
              value: "1000"
            - name: LANGFUSE_INGESTION_CLICKHOUSE_WRITE_BATCH_SIZE
              value: "1"
            - name: REDIS_CONNECTION_STRING
              valueFrom:
                secretKeyRef:
                  name: langfuse-db-secrets
                  key: redis-connection-string
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: langfuse-db-secrets
                  key: redis-connection-string
            - name: REDIS_HOST
              value: "redis.governance-stack.svc.cluster.local"
            - name: REDIS_PORT
              value: "6379"
            - name: LOG_LEVEL
              value: "debug"
            - name: LANGFUSE_LOG_LEVEL
              value: "debug"
            - name: CLICKHOUSE_CLUSTER_ENABLED
              value: "false"
            - name: LANGFUSE_S3_EVENT_UPLOAD_ENABLED
              value: "true"
            - name: LANGFUSE_S3_EVENT_UPLOAD_BUCKET
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: bucket-name
            # Region-parameterised: substituted from CAGE_DEPLOYMENT_REGION at deploy time.
            # US_FED → us-central1, EU_ECB → europe-west1, APAC_MAS → asia-southeast1.
            # "auto" is NOT permitted — it delegates bucket location to GCS defaults and
            # may violate GDPR Art. 44 (EU_ECB) or MAS TRM §4.2 (APAC_MAS).
            - name: LANGFUSE_S3_EVENT_UPLOAD_REGION
              value: "${GOOGLE_CLOUD_LOCATION}"
            - name: LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT
              value: "https://storage.googleapis.com"
            - name: AWS_ENDPOINT_URL_S3
              value: "https://storage.googleapis.com"
            # AWS_REGION must match the GCS bucket's actual location for HMAC key routing.
            # Derived from CAGE_DEPLOYMENT_REGION by deploy_all.sh.
            - name: AWS_REGION
              value: "${AWS_S3_REGION}"
            - name: AWS_S3_PATH_STYLE_ACCESS
              value: "true"
            - name: LANGFUSE_S3_EVENT_UPLOAD_FORCE_PATH_STYLE
              value: "true"
            - name: LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-access-key
            - name: LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-secret-key
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-access-key
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-secret-key
            - name: SALT
              valueFrom:
                secretKeyRef:
                  name: langfuse-secrets
                  key: salt
            - name: ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: langfuse-secrets
                  key: encryption-key
            # Injected so the Langfuse worker pod can emit jurisdiction-tagged telemetry.
            - name: CAGE_DEPLOYMENT_REGION
              value: "${CAGE_DEPLOYMENT_REGION}"
          livenessProbe:
            httpGet:
              path: /api/public/health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 20
            failureThreshold: 3
            timeoutSeconds: 5
          readinessProbe:
            httpGet:
              path: /api/public/health
              port: 3000
            initialDelaySeconds: 15
            periodSeconds: 10
            failureThreshold: 3
            timeoutSeconds: 5
          resources:
            requests:
              cpu: "50m"
              memory: "256Mi"
            limits:
              cpu: "1"
              memory: "2Gi"
# NOTE: HPA is defined in the standalone langfuse-worker-hpa.yaml.
# The duplicate HPA that was previously inlined here has been removed
# to avoid conflicting maxReplicas (8 vs 10) and CPU thresholds (60% vs 70%).
