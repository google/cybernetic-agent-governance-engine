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
      serviceAccountName: financial-advisor-sa
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
            # SC-12 / AC-3 / POAM-012: HMAC routing seal enforcement.
            # CAGE_ENV=production activates RuntimeError at import time if
            # CAGE_ROUTING_SEAL_SECRET is absent or shorter than 32 chars.
            # DEP-04: CAGE_ENV is substituted at deploy time from the --env flag
            # passed to deploy_all.sh (dev → "dev", prod → "production").
            - name: CAGE_ENV
              value: "${CAGE_ENV}"
            - name: ENVIRONMENT
              value: "${CAGE_ENV}"
            - name: CAGE_ROUTING_SEAL_SECRET
              valueFrom:
                secretKeyRef:
                  name: cage-routing-seal
                  key: secret
            # BLOCKER-06: RECONCILIATION_PROVIDER must not be "stub" in production.
            # The stub provider fabricates a static $100k balance; CBF would evaluate
            # against fake data. "gcs" routes to the GCS-backed WORM ledger.
            - name: RECONCILIATION_PROVIDER
              value: "gcs"
            # CTRL_KMS_001: KMS asymmetric governance signer (H-05).
            # assert_kms_active_in_production() raises RuntimeError at startup
            # if this env var is absent when CAGE_ENV=production.
            - name: KMS_GOVERNANCE_KEY
              valueFrom:
                secretKeyRef:
                  name: advisor-secrets
                  key: KMS_GOVERNANCE_KEY
                  optional: true
            - name: OPA_URL
              value: "http://opa.governance-stack.svc.cluster.local:8181/v1/data/trade/governance"
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
