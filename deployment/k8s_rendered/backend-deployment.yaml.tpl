apiVersion: apps/v1
kind: Deployment
metadata:
  name: governed-financial-advisor
  namespace: governance-stack
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
        - name: policy-volume
          secret:
            secretName: finance-policy-rego
        - name: opa-config-volume
          secret:
            secretName: opa-configuration
      containers:
        # Main Agent Container
        - name: ingress-agent
          image: ${REGISTRY_URL}/governed-financial-advisor:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"
            # Agent Session Management (K8s Redis for GKE, Memorystore for Cloud Run)
            - name: REDIS_HOST
              value: "${REDIS_HOST}" # Set by deploy script: redis-master for GKE, Memorystore IP for Cloud Run
            - name: REDIS_PORT
              value: "6379"
            - name: GOOGLE_CLOUD_PROJECT
              value: "${PROJECT_ID}"
            - name: GOOGLE_CLOUD_LOCATION
              value: "${REGION}"
            - name: GOOG-REDACTED
              value: "${GOOG-REDACTED}"
            - name: MODEL_FAST
              value: "${MODEL_FAST}"
            - name: MODEL_REASONING
              value: "${MODEL_REASONING}"
            - name: VLLM_BASE_URL
              value: "http://vllm-service.governance-stack.svc.cluster.local:8000/v1"
            - name: OPA_URL
              value: "http://opa-service:8181/v1/data/trade/governance"
            - name: DEPLOY_TIMESTAMP
              value: "${DEPLOY_TIMESTAMP}"
            # OpenTelemetry (OTLP)
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "${OTEL_EXPORTER_OTLP_ENDPOINT}"
            - name: OTEL_EXPORTER_OTLP_HEADERS
              value: "${OTEL_EXPORTER_OTLP_HEADERS}"
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "1000m"
              memory: "2Gi"

        # OPA Sidecar
        - name: opa
          image: openpolicyagent/opa:latest-static
          ports:
            - containerPort: 8181
          args:
            - "run"
            - "--server"
            - "--addr=localhost:8181"
            - "--config-file=/config/opa_config.yaml"
            - "/policies/finance_policy.rego"
          volumeMounts:
            - name: policy-volume
              mountPath: /policies/finance_policy.rego
              subPath: finance_policy.rego
              readOnly: true
            - name: opa-config-volume
              mountPath: /config
              readOnly: true
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "250m"
              memory: "256Mi"

---
apiVersion: v1
kind: Service
metadata:
  name: governed-financial-advisor
  namespace: governance-stack
spec:
  type: ClusterIP
  selector:
    app: governed-financial-advisor
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
