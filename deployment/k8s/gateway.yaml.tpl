apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
  namespace: governance-stack
  labels:
    app: gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gateway
  template:
    metadata:
      labels:
        app: gateway
    spec:
      serviceAccountName: cage-gateway-sa
      containers:
        - name: gateway
          image: gcr.io/YOUR_PROJECT_ID/gateway:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 50051
              name: grpc
          envFrom:
            - secretRef:
                name: advisor-secrets
                optional: false
          env:
            - name: PORT
              value: "8080"
            - name: GATEWAY_GRPC_PORT
              value: "50051"
            - name: GOOGLE_CLOUD_PROJECT
              value: ""  # Set to your GCP project ID
            # DEP-04: GOOGLE_CLOUD_LOCATION is substituted at deploy time from
            # CAGE_DEPLOYMENT_REGION via deploy_all.sh / envsubst.
            # US_FED → us-central1, EU_ECB → europe-west1, APAC_MAS → asia-southeast1
            - name: GOOGLE_CLOUD_LOCATION
              value: "${GOOGLE_CLOUD_LOCATION}"
            - name: ENABLE_LOGGING
              value: "true"
            - name: OTEL_TRACES_EXPORTER
              value: "otlp"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              # Langfuse v3 native OTLP ingestion — no separate OTel Collector deployed.
              value: "http://langfuse-web.governance-stack.svc.cluster.local:3000/api/public/otel/v1/traces"
            - name: OTEL_EXPORTER_OTLP_PROTOCOL
              value: "http/protobuf"
            - name: OTEL_EXPORTER_OTLP_HEADERS
              valueFrom:
                secretKeyRef:
                  name: advisor-secrets
                  key: LANGFUSE_BASIC_AUTH_B64
                  optional: false
            - name: OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY
              value: "true"
            - name: OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY
              value: "true"
            - name: OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT
              value: "true"
            - name: OTEL_PYTHON_EXCLUDED_URLS
              value: "healthz,readiness,liveness,metrics,huggingface.co/api/resolve"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST
              value: "content-type,accept,user-agent,x-request-id,x-goog-authenticated-user-email"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE
              value: "content-type,content-length"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS
              value: ".*session.*,.*token.*,authorization,set-cookie,cookie,x-api-key,proxy-authorization"
            - name: REDIS_PORT
              value: "6379"
            - name: REDIS_HOST
              value: "redis.governance-stack.svc.cluster.local"
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: redis-secret
                  key: redis-password
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: redis-credentials
                  key: REDIS_URL
            - name: VLLM_BASE_URL
              value: "http://vllm-service.governance-stack.svc.cluster.local:8000/v1"
            - name: VLLM_REASONING_API_BASE
              value: "http://vllm-reasoning.governance-stack.svc.cluster.local:8000/v1"
            - name: VLLM_FAST_API_BASE
              value: "http://vllm-service.governance-stack.svc.cluster.local:8000/v1"
            - name: GUARDRAILS_MODEL_NAME
              value: ""  # Set to your model artifact path, e.g. gs://your-bucket/models--Qwen--Qwen2.5-7B-Instruct/snapshots/<sha>
            - name: SERVICE_NAME
              value: "hybrid-gateway"
            # DEP-04: CAGE_ENV is substituted at deploy time from the --env flag
            # passed to deploy_all.sh (dev → "dev", prod → "production").
            # Causal-tier telemetry (CTRL_TEL_003). The kernel reads only the
            # vendor-neutral TELEMETRY_* names; they map the Langfuse project keys
            # already held in advisor-secrets. Enforcing postures require
            # CAGE_TELEMETRY_PROVIDER to be set explicitly.
            - name: CAGE_TELEMETRY_PROVIDER
              value: "remote"
            - name: TELEMETRY_HOST
              value: "http://langfuse-web.governance-stack.svc.cluster.local:3000"
            - name: TELEMETRY_PUBLIC_KEY
              valueFrom:
                secretKeyRef:
                  name: advisor-secrets
                  key: LANGFUSE_PUBLIC_KEY
            - name: TELEMETRY_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: advisor-secrets
                  key: LANGFUSE_SECRET_KEY
            - name: CAGE_DOMAIN  # exactly one domain per process
              value: "${CAGE_DOMAIN:-finance}"
            - name: CAGE_ENV
              value: "${CAGE_ENV}"
            - name: ENVIRONMENT
              value: "${CAGE_ENV}"
            - name: CAGE_TRUSTED_CLIENT_IDENTITIES
              # POAM-2026-080: deny by default. Every path except the open list
              # in workload_identity.py requires this Linkerd identity in
              # l5d-client-id; outside dev/test the gateway refuses to start
              # without it. Needs the Linkerd proxy (linkerd-mtls-policy.yaml).
              value: "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
            - name: EVIDENCE_STREAM_ENABLED
              value: "true"
            # Evidence producer only: custody (chain re-verification, batch
            # signing with EVIDENCE_KMS_KEY, WORM writes) runs in the compliance
            # bridge. URL/db/key must match compliance-bridge exactly.
            - name: EVIDENCE_CHAIN_BLOCKING
              value: "true"
            - name: EVIDENCE_STREAM_REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: redis-credentials
                  key: REDIS_URL
            - name: EVIDENCE_STREAM_REDIS_DB
              value: "1"
            - name: EVIDENCE_STREAM_KEY
              value: "cage:evidence:stream"
            # BLOCKER-06: the startup posture check refuses production when
            # RECONCILIATION_PROVIDER is unset or "stub". The reconciler runs the
            # simulated Tier 2 provider (the ledger providers were removed), so the
            # value names that provider; it is a label, not a selector.
            - name: RECONCILIATION_PROVIDER
              value: "simulated"
            # Signing-key references come from gateway-secrets, never from the
            # shared advisor-secrets: the advisor loads advisor-secrets via
            # envFrom and refuses to start if either key is present
            # (POAM-2026-079, identity_guard.py). Create it out of band:
            #   kubectl create secret generic gateway-secrets -n governance-stack \
            #     --from-literal=KMS_GOVERNANCE_KEY=<gateway-seal key version> \
            #     --from-literal=RECONCILER_KMS_KEY=<reconciler-snapshot key version>
            # CTRL_KMS_001: KMS asymmetric governance signer (H-05).
            # assert_kms_active_in_production() raises RuntimeError at startup
            # if this env var is absent when CAGE_ENV=production.
            - name: KMS_GOVERNANCE_KEY
              valueFrom:
                secretKeyRef:
                  name: gateway-secrets
                  key: KMS_GOVERNANCE_KEY
                  optional: true
            # G8: the reconciler's snapshot-signing key (verify only; the
            # gateway needs cloudkms.publicKeyViewer on it). The CBF trusts
            # ground truth only when signed by this key's kid. The
            # reconciler_trust_anchor posture check refuses an enforcing
            # startup if it is unset, equals KMS_GOVERNANCE_KEY, or resolves
            # to no public key.
            - name: RECONCILER_KMS_KEY
              valueFrom:
                secretKeyRef:
                  name: gateway-secrets
                  key: RECONCILER_KMS_KEY
                  optional: true
            - name: OPA_URL
              value: "http://opa.governance-stack.svc.cluster.local:8181"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 20
            failureThreshold: 3
            timeoutSeconds: 5

          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
            failureThreshold: 3
            timeoutSeconds: 5

          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: "1000m"
              memory: "2Gi"
            limits:
              cpu: "2000m"
              memory: "4Gi"
---
apiVersion: v1
kind: Service
metadata:
  name: gateway
  namespace: governance-stack
spec:
  selector:
    app: gateway
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
    - name: grpc
      protocol: TCP
      port: 50051
      targetPort: 50051
  type: ClusterIP
