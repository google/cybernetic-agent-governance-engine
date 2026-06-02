apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-bridge
  namespace: ${NAMESPACE}
  labels:
    app: compliance-bridge
    app.kubernetes.io/version: "2.0.0"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: compliance-bridge
  template:
    metadata:
      labels:
        app: compliance-bridge
    spec:
      serviceAccountName: financial-advisor-sa
      containers:
        - name: compliance-bridge
          image: ${REGISTRY_URL}/compliance-bridge:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 3001
              name: http
          env:
            - name: PORT
              value: "3001"
            - name: LANGFUSE_PUBLIC_KEY
              valueFrom:
                secretKeyRef:
                  name: langfuse-secrets
                  key: public-key
            - name: LANGFUSE_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: langfuse-secrets
                  key: secret-key
            - name: LANGFUSE_COMPLIANCE_PUBLIC_KEY
              valueFrom:
                secretKeyRef:
                  name: langfuse-compliance-secrets
                  key: public-key
                  optional: true
            - name: LANGFUSE_COMPLIANCE_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: langfuse-compliance-secrets
                  key: secret-key
                  optional: true
            - name: LANGFUSE_HOST
              value: "${LANGFUSE_HOST}"
            # Remediation Advisor (Step 5) — LLM-based root cause analysis
            - name: REMEDIATION_MODEL
              value: "${REMEDIATION_MODEL}"
            - name: REMEDIATION_MAX_TOKENS
              value: "${REMEDIATION_MAX_TOKENS}"
            - name: REMEDIATION_TIMEOUT_MS
              value: "${REMEDIATION_TIMEOUT_MS}"
            # vLLM inference endpoint (shared with governed_financial_advisor)
            - name: VLLM_BASE_URL
              value: "${VLLM_BASE_URL}"
            - name: VLLM_API_KEY
              value: "${VLLM_API_KEY}"
            # Alert channel: "slack" | "console" (default)
            - name: ALERT_CHANNEL
              value: "${ALERT_CHANNEL}"
            - name: COMPLIANCE_ALERT_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: compliance-alert-secrets
                  key: webhook-url
                  optional: true
            - name: OSCAL_S3_ENDPOINT
              value: "https://storage.googleapis.com"
            - name: OSCAL_S3_BUCKET
              value: "${OSCAL_S3_BUCKET}"
            - name: OSCAL_S3_REGION
              value: "${OSCAL_S3_REGION}"
            - name: OSCAL_S3_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-access-key
                  optional: true
            - name: OSCAL_S3_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: oscal-artifact-secrets
                  key: hmac-secret-key
                  optional: true
          livenessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 5
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 5
            periodSeconds: 10
          # Reduced vs. Node.js — Python FastAPI + uvicorn is lighter
          resources:
            requests:
              cpu: "50m"
              memory: "128Mi"
            limits:
              cpu: "200m"
              memory: "256Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: compliance-bridge
  namespace: ${NAMESPACE}
spec:
  selector:
    app: compliance-bridge
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 3001
  type: ClusterIP
