apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
  namespace: ${NAMESPACE}
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
          image: ${REGISTRY_URL}/gateway:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 50051
              name: grpc
          envFrom:
            - secretRef:
                name: advisor-secrets
          env:
            - name: PORT
              value: "8080"
            - name: GATEWAY_GRPC_PORT
              value: "50051"
            - name: GOOGLE_CLOUD_PROJECT
              value: "${GOOGLE_CLOUD_PROJECT}"
            - name: GOOGLE_CLOUD_LOCATION
              value: "${GOOGLE_CLOUD_LOCATION}"
            - name: ENABLE_LOGGING
              value: "${ENABLE_LOGGING}"
            - name: OTEL_TRACES_EXPORTER
              value: "otlp"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://otel-collector.governance-stack:4318/v1/traces"
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
            - name: REDIS_PORT
              value: "${REDIS_PORT}"
            - name: REDIS_HOST
              value: "${REDIS_HOST}"
            - name: REDIS_URL
              value: "redis://${REDIS_HOST}:${REDIS_PORT}"
            - name: VLLM_BASE_URL
              value: "${VLLM_BASE_URL}"
            - name: VLLM_GATEWAY_URL
              value: "${VLLM_GATEWAY_URL}"
            - name: VLLM_REASONING_API_BASE
              value: "${VLLM_REASONING_API_BASE}"
            - name: VLLM_FAST_API_BASE
              value: "${VLLM_FAST_API_BASE}"
            - name: GUARDRAILS_MODEL_NAME
              value: "${GUARDRAILS_MODEL_NAME}"
            - name: SERVICE_NAME
              value: "hybrid-gateway"
            # Dev-mode bypass: disables CAGE_ROUTING_SEAL_SECRET enforcement (POAM-012)
            # In production, set CAGE_ENV=production and provide a 32+ char secret.
            - name: CAGE_ENV
              value: "${CAGE_ENV:-development}"
            - name: ENVIRONMENT
              value: "${CAGE_ENV:-development}"
            # OPA Configuration
            - name: OPA_URL
              value: "http://opa-service:8181/v1/data/trade/governance"
            - name: SLM_BASE_URL
              value: "http://governed-financial-advisor-slm:5000"
          resources:
            requests:
              cpu: "1000m"
              memory: "2Gi"
            limits:
              cpu: "2000m"
              memory: "4Gi"

        # OPA sidecar removed — gateway talks to the standalone opa-service
        # Deployment (OPA_URL=http://opa-service:8181/v1/data/trade/governance).
        # The sidecar listened on localhost:8181 which was unreachable from the
        # main container, caused pod CrashLoopBackOff when its secrets were
        # missing, and duplicated policy evaluation work already done by the
        # shared opa-service. See: deployment/k8s/opa.yaml.
---
apiVersion: v1
kind: Service
metadata:
  name: gateway
  namespace: ${NAMESPACE}
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
