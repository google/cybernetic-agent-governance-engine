# Deployed to vllm-inference namespace (PSA: baseline) — requires root for GPU access
# governance-stack (PSA: restricted) is incompatible with GPU workloads.
# Cross-namespace service discovery is handled by ExternalName Services in
# deployment/k8s/vllm-services.yaml (governance-stack → vllm-inference).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-reasoning
  namespace: vllm-inference
  labels:
    app: vllm-reasoning
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-reasoning
  strategy:
    type: RollingUpdate
    rollingUpdate:
      # maxUnavailable:1 / maxSurge:0 prevents GPU scheduling deadlocks on single-GPU nodes.
      # Default (maxUnavailable:0, maxSurge:1) waits for the new pod to become Ready before
      # evicting the old one — impossible when both pods need the same GPU node.
      maxSurge: 0
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app: vllm-reasoning
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: financial-advisor-sa
      tolerations:
        - key: "nvidia.com/gpu"
          operator: "Equal"
          value: "present"
          effect: "NoSchedule"
        - key: "cloud.google.com/gke-spot"
          operator: "Equal"
          value: "true"
          effect: "NoSchedule"
        - key: "node.kubernetes.io/lifecycle"
          operator: "Equal"
          value: "spot"
          effect: "NoSchedule"
        - key: "nvidia.com/gpu"
          operator: "Exists"
          effect: "NoSchedule"
${TOLERATIONS}
      # nodeSelector targets L4 GPU nodes explicitly. GPU resource requests alone are
      # insufficient to guarantee placement on accelerator nodes in mixed node-pool clusters.
      # The GKE accelerator label (cloud.google.com/gke-accelerator) is present on all L4
      # nodes (Spot and on-demand). Do NOT use nvidia.com/gpu.product or
      # node.kubernetes.io/lifecycle — those labels are not applied by GKE.
      nodeSelector:
        cloud.google.com/gke-accelerator: nvidia-l4
      affinity:
        # Prefer Spot GPU nodes; allow on-demand GPU fallback when Spot is exhausted
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 80
              preference:
                matchExpressions:
                  - key: cloud.google.com/gke-spot
                    operator: In
                    values:
                      - "true"
            - weight: 100
              preference:
                matchExpressions:
                  - key: cloud.google.com/gke-accelerator
                    operator: In
                    values:
                      - nvidia-l4
        # HARD: vllm-reasoning (DeepSeek-R1 14B AWQ) and vllm-inference (Qwen 7B)
        # each require the full 24GB L4 GPU VRAM — co-scheduling causes OOM.
        # The multi-zone node pool (us-central1-a/b/c) provides the necessary
        # node diversity without relaxing this safety constraint.
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - vllm-inference
              topologyKey: "kubernetes.io/hostname"
      volumes:
        - name: dshm
          emptyDir:
            medium: Memory
            sizeLimit: "16Gi"
        # GCSFuse CSI volume: streams model weights directly from GCS bucket.
        # Requires gcsfuse-csi-driver to be installed on the cluster.
        - name: model-cache
          csi:
            driver: gcsfuse.csi.storage.gke.io
            readOnly: true
            volumeAttributes:
              bucketName: laah-cybernetics-models
              mountOptions: "implicit-dirs,uid=1000,gid=1000"
      containers:
        - name: vllm
          # vllm-streamer: standard vLLM image with runai_streamer installed for
          # direct GCS weight streaming via S3-compatible HMAC keys.
          # Build: Dockerfile.vllm in repo root.
          image: gcr.io/laah-cybernetics/vllm-streamer:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          command: ["/bin/bash", "-c"]
          args:
            - |
              ARGS=(--host 0.0.0.0 --port 8000)
              TARGET_MODEL="${MODEL_REASONING}"
              # MODEL_REASONING from ConfigMap now uses GCS path for streaming
              ARGS+=(--model "$TARGET_MODEL" --served-model-name "$TARGET_MODEL")
              ARGS+=(--quantization awq_marlin)
              ARGS+=(--enable-auto-tool-choice --tool-call-parser hermes --enforce-eager)
              # Stream weights directly from GCS via S3-compatible HMAC API.
              # Falls back to HuggingFace Hub download when MODEL_REASONING is a HF model ID.
              if [[ "$TARGET_MODEL" == gs://* ]] || [[ "$TARGET_MODEL" == s3://* ]]; then
                ARGS+=(--load-format runai_streamer --model-loader-extra-config '{"concurrency": 16}')
              fi
              ARGS+=(--max-model-len "16384")
              ARGS+=(--gpu-memory-utilization "0.88")
              ARGS+=(--dtype half)
              exec vllm serve "${ARGS[@]}" "$@"
          envFrom:
            - configMapRef:
                name: advisor-config
            # GCS S3-compatible credentials (HMAC keys) — same as vllm-inference
            - secretRef:
                name: gcs-credentials-secret
          env:
            - name: HUGGING_FACE_HUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hf-token-secret
                  key: token
            - name: AWS_EC2_METADATA_DISABLED
              value: "true"
            # GCS HMAC S3-compatible endpoint
            - name: AWS_ENDPOINT_URL_S3
              value: "https://storage.googleapis.com"
            - name: RUNAI_STREAMER_S3_USE_VIRTUAL_ADDRESSING
              value: "0"
            - name: AC_LOG_VERBOSITY
              value: "info"
            - name: AWS_RESPONSE_CHECKSUM_VALIDATION
              value: "OFF"
          ports:
            - containerPort: 8000
              name: http
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            # Extended delay for large model load from GCS (~5min on spot nodes)
            initialDelaySeconds: 300
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 6
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 300
            periodSeconds: 15
            timeoutSeconds: 5
            failureThreshold: 5
          resources:
            limits:
              nvidia.com/gpu: "1"
              memory: "64Gi"
              cpu: "16"
            requests:
              nvidia.com/gpu: "1"
              memory: "12Gi"
              cpu: "3"
          volumeMounts:
            - name: dshm
              mountPath: /dev/shm
            - name: model-cache
              mountPath: /model-cache/deepseek-ai--DeepSeek-R1-Distill-Qwen-32B
              readOnly: true
---
apiVersion: v1
kind: Service
metadata:
  name: vllm-reasoning
  namespace: vllm-inference
spec:
  selector:
    app: vllm-reasoning
  ports:
    - port: 8000
      targetPort: 8000
      protocol: TCP
      name: http
  type: ClusterIP
