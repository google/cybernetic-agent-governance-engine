apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-inference
  namespace: governance-stack
  labels:
    app: vllm-inference
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-inference
  template:
    metadata:
      labels:
        app: vllm-inference
    spec:
      volumes:
        - name: dshm
          emptyDir:
            medium: Memory
            sizeLimit: "16Gi"  # vLLM requires large shared memory
        - name: model-cache
          emptyDir: {}
      containers:
        - name: vllm
          image: ${IMAGE_NAME}
          imagePullPolicy: IfNotPresent
          resources:
            limits:
${RESOURCE_LIMITS}
              memory: "64Gi"
              cpu: "16"
            requests:
${RESOURCE_REQUESTS}
              memory: "10Gi"
              cpu: "3"
          volumeMounts:
            - mountPath: /dev/shm
              name: dshm
            - mountPath: /root/.cache/huggingface
              name: model-cache
          env:
            - name: HUGGING_FACE_HUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hf-token-secret
                  key: token
${ENV_VARS}
          ports:
            - containerPort: 8000
              name: http
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 120
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 600
            periodSeconds: 15
          command:
            - "python3"
            - "-m"
            - "vllm.entrypoints.openai.api_server"
            - "--port"
            - "8000"
${ARGS}
      nodeSelector:
${NODE_SELECTOR}
      tolerations:
${TOLERATIONS}
