apiVersion: apps/v1
kind: Deployment
metadata:
  name: governed-financial-advisor
  namespace: ${NAMESPACE}
  labels:
    app: governed-financial-advisor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: governed-financial-advisor
  template:
    metadata:
      labels:
        app: governed-financial-advisor
    spec:
      serviceAccountName: financial-advisor-sa
      volumes:
        # policy-volume and opa-config-volume removed — OPA sidecar removed.
        # governed-financial-advisor uses OPA_URL env var to reach the shared
        # opa-service Deployment (see deployment/k8s/opa.yaml).
      containers:
        # Main Agent Container
        - name: ingress-agent
          image: ${REGISTRY_URL}/governed-financial-advisor:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
          envFrom:
            - secretRef:
                name: advisor-secrets
          env:
            # --- Service Configuration ---
            - name: PORT
              value: "${PORT}"
            - name: DEPLOY_TIMESTAMP
              value: "${DEPLOY_TIMESTAMP}"

            # --- Infrastructure ---
            - name: GOOGLE_CLOUD_PROJECT
              value: "${GOOGLE_CLOUD_PROJECT}"
            - name: GOOGLE_CLOUD_LOCATION
              value: "${GOOGLE_CLOUD_LOCATION}"
            - name: ENABLE_LOGGING
              value: "${ENABLE_LOGGING}"

            # --- Redis Session Management ---
            - name: REDIS_HOST
              value: "${REDIS_HOST}"
            - name: REDIS_PORT
              value: "${REDIS_PORT}"
            - name: REDIS_URL
              value: "redis://${REDIS_HOST}:${REDIS_PORT}"

            # --- Model Configuration (Tiered) ---
            - name: MODEL_FAST
              value: "${MODEL_FAST}"
            - name: MODEL_REASONING
              value: "${MODEL_REASONING}"
            - name: MODEL_CONSENSUS
              value: "${MODEL_CONSENSUS}"

            # --- vLLM Inference Endpoints ---
            - name: VLLM_BASE_URL
              value: "${VLLM_BASE_URL}"
            - name: VLLM_API_KEY
              value: "${VLLM_API_KEY}"
            - name: OPENAI_API_BASE
              value: "${VLLM_BASE_URL}"
            - name: OPENAI_API_KEY
              value: "${VLLM_API_KEY}"
            - name: VLLM_FAST_API_BASE
              value: "${VLLM_FAST_API_BASE}"
            - name: VLLM_REASONING_API_BASE
              value: "${VLLM_REASONING_API_BASE}"
            - name: VLLM_GATEWAY_URL
              value: "${VLLM_GATEWAY_URL}"

            # --- Policy Engine ---
            - name: OPA_URL
              value: "${OPA_URL}"

            # --- Observability: Langfuse (hot tier) — LangSmith/LangChain tracing disabled ---
            - name: LANGCHAIN_TRACING_V2
              value: "false"
            - name: LANGSMITH_TRACING
              value: "false"
            - name: LANGFUSE_HOST
              value: "${LANGFUSE_HOST}"

            # --- OpenTelemetry (Cold Tier) ---
            - name: OTEL_TRACES_EXPORTER
              value: "otlp"
            - name: OTEL_METRICS_EXPORTER
              value: "none"
            - name: OTEL_LOGS_EXPORTER
              value: "none"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://otel-collector.governance-stack:4318/v1/traces"
            - name: OTEL_EXPORTER_OTLP_HEADERS
              value: "${OTEL_EXPORTER_OTLP_HEADERS}"
            - name: TRACE_SAMPLING_RATE
              value: "${TRACE_SAMPLING_RATE}"
            - name: OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY
              value: "true"
            - name: OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY
              value: "true"
            - name: OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT
              value: "true"
            - name: OTEL_PYTHON_EXCLUDED_URLS
              value: "${OTEL_PYTHON_EXCLUDED_URLS}"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST
              value: "content-type,accept,user-agent,x-request-id,x-goog-authenticated-user-email"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE
              value: "content-type,content-length"
            - name: OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS
              value: ".*session.*,.*token.*,authorization,set-cookie,cookie,x-api-key,proxy-authorization"

            # --- Cold Tier Storage ---
            - name: COLD_TIER_GCS_BUCKET
              value: "${COLD_TIER_GCS_BUCKET}"
            - name: COLD_TIER_GCS_PREFIX
              value: "${COLD_TIER_GCS_PREFIX}"

            # --- Gateway Configuration ---
            - name: GATEWAY_HOST
              value: "${GATEWAY_HOST}"
            - name: GATEWAY_GRPC_PORT
              value: "${GATEWAY_GRPC_PORT}"
            - name: GATEWAY_URL
              value: "${GATEWAY_URL}"
            - name: MCP_SERVER_SSE_URL
              value: "http://gateway:8080/mcp/sse"
            - name: GOVERNANCE_SALT
              value: "${GOVERNANCE_SALT}"




            # --- MCP Configuration ---
            - name: MCP_MODE
              value: "${MCP_MODE}"
            - name: ALPHAVANTAGE_API_KEY
              value: "${ALPHAVANTAGE_API_KEY}"

            # --- Secrets (from K8s Secrets) ---
            - name: HUGGING_FACE_HUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hf-token-secret
                  key: token

          resources:
            requests:
              cpu: "100m"
              memory: "1Gi"
            limits:
              cpu: "500m"
              memory: "2Gi"



        # OPA sidecar removed — governed-financial-advisor uses OPA_URL env var
        # (http://opa-service:8181) to reach the shared opa-service Deployment.
        # The sidecar listened on localhost:8181, which was unreachable from the
        # main container, and required finance-policy-rego / opa-configuration
        # secrets that cause CreateContainerConfigError when absent.
---
apiVersion: v1
kind: Service
metadata:
  name: governed-financial-advisor
  namespace: ${NAMESPACE}
spec:
  type: ClusterIP
  selector:
    app: governed-financial-advisor
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080

