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
# Template: deployment/k8s/vllm-inference-spot.yaml.tpl
#
# Region-aware template for the vLLM inference (fast/spot) deployment.
# Converts the static vllm-inference-spot.yaml to a region-parameterised template
# to satisfy PATTERN-3 from docs/JURISDICTIONAL_SEPARATION_ANALYSIS.md.
#
# Variables substituted at deploy time by deploy_all.sh via envsubst:
#   ${CAGE_DEPLOYMENT_REGION}  — Logical jurisdiction (US_FED | EU_ECB | APAC_MAS)
#   ${GOOGLE_CLOUD_LOCATION}   — GCP region (us-central1 | europe-west1 | asia-southeast1)
#   ${AWS_S3_REGION}           — S3-compatible region string for GCS HMAC access
#
# Deployed to vllm-inference namespace (PSA: baseline) — requires root for GPU access.
# governance-stack (PSA: restricted) is incompatible with GPU workloads.
# Cross-namespace service discovery is handled by ExternalName Services in
# deployment/k8s/vllm-services.yaml (governance-stack → vllm-inference).

apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-inference
  namespace: vllm-inference
  labels:
    app: vllm-inference
    cage.io/iso42001-control: "A.8.4"
    cage.io/deployment-region: "${CAGE_DEPLOYMENT_REGION}"
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
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      # GCS HMAC keys provide S3-compatible access to GCS buckets without
      # requiring GCP-specific CSI drivers or Workload Identity bindings.
      # This approach is portable across cloud providers that support S3 protocol.
      affinity:
        # Prefer Spot GPU nodes; allow on-demand fallback when Spot is exhausted
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
        # SOFT: Prefer not to co-locate with vllm-reasoning to spread GPU load
        # Changed from requiredDuringSchedulingIgnoredDuringExecution to avoid
        # blocking deployment when only one node is available
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - vllm-reasoning
                topologyKey: "kubernetes.io/hostname"
      volumes:
        - name: dshm
          emptyDir:
            medium: Memory
            sizeLimit: "16Gi"
        - name: model-cache
          emptyDir: {}
      containers:
        - name: vllm
          # Standard vLLM OpenAI-compatible image with runai_streamer support for
          # streaming model weights from S3-compatible storage (GCS HMAC or AWS S3)
          image: gcr.io/YOUR_GCP_PROJECT_ID/vllm-streamer:latest
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              memory: "64Gi"
              cpu: "16"
              nvidia.com/gpu: "1"
            requests:
              memory: "10Gi"
              cpu: "3"
              nvidia.com/gpu: "1"
          volumeMounts:
            - mountPath: /dev/shm
              name: dshm
            - mountPath: /root/.cache/huggingface
              name: model-cache
          envFrom:
            - configMapRef:
                name: advisor-config
            # ── GCS S3-compatible credentials (HMAC keys) ────────────────────
            # Provides standard S3 API access to GCS. Compatible with any S3 client.
            # To use AWS S3 instead: update gcs-credentials-secret with AWS keys
            # and set AWS_ENDPOINT_URL to https://s3.amazonaws.com (or remove it).
            - secretRef:
                name: gcs-credentials-secret
          env:
            - name: AWS_EC2_METADATA_DISABLED
              value: "true"
            # GCS HMAC S3-compatible endpoint — portable to AWS S3 by changing this value
            - name: AWS_ENDPOINT_URL_S3
              value: "https://storage.googleapis.com"
            # AWS_REGION must match the GCS bucket's actual location for HMAC key routing.
            # Derived from CAGE_DEPLOYMENT_REGION by deploy_all.sh.
            # US_FED → us-central1, EU_ECB → europe-west1, APAC_MAS → asia-southeast1.
            - name: AWS_REGION
              value: "${AWS_S3_REGION}"
            - name: RUNAI_STREAMER_S3_USE_VIRTUAL_ADDRESSING
              value: "0"
            - name: AC_LOG_VERBOSITY
              value: "info"
            - name: HUGGING_FACE_HUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hf-token-secret
                  key: token
                  optional: true
            # Injected so the vLLM inference pod can emit jurisdiction-tagged telemetry
            # and apply region-specific model governance policies at runtime.
            - name: CAGE_DEPLOYMENT_REGION
              value: "${CAGE_DEPLOYMENT_REGION}"
            - name: GOOGLE_CLOUD_LOCATION
              value: "${GOOGLE_CLOUD_LOCATION}"
          ports:
            - containerPort: 8000
              name: http
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 300  # 5 min for AWQ model download + init
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 600  # 10 min
            periodSeconds: 15
            timeoutSeconds: 5
            failureThreshold: 10
          command: ["/bin/bash", "-c"]
          args:
            - |
              ARGS=(--host 0.0.0.0 --port 8000)
              TARGET_MODEL="${MODEL_FAST}"
              ARGS+=(--model "$TARGET_MODEL" --served-model-name "Qwen/Qwen2.5-7B-Instruct")
              ARGS+=(--enable-auto-tool-choice --tool-call-parser hermes --enforce-eager)

              # Enable trust_remote_code for AWQ models (required for custom kernels)
              ARGS+=(--trust-remote-code)

              # Stream model weights from GCS via S3-compatible HMAC API (only for GCS/S3 paths)
              # Works with any S3-compatible store: GCS, AWS S3, MinIO, Ceph, etc.
              if [[ "$TARGET_MODEL" == gs://* ]] || [[ "$TARGET_MODEL" == s3://* ]]; then
                ARGS+=(--load-format runai_streamer --model-loader-extra-config '{"concurrency": 8}')
              fi

              # T4-optimized settings (15GB usable VRAM, compute capability 7.5)
              # Using AWQ quantized model (~5.5GB) leaves plenty of room for KV cache
              ARGS+=(--max-model-len "2048")  # Reasonable for quantized model on T4
              ARGS+=(--gpu-memory-utilization "0.85")  # Quantized model has headroom
              ARGS+=(--max-num-seqs "64")  # Good batch size for quantized model
              ARGS+=(--dtype auto)  # Auto-detect from model
              # AWQ quantization (4-bit) significantly reduces memory usage
              ARGS+=(--quantization awq)

              # Set PyTorch memory allocator to reduce fragmentation
              export PYTORCH_CUDA_ALLOC_CONF="expandable_segments:True"

              exec vllm serve "${ARGS[@]}" "$@"
      # nodeSelector targets L4 GPU nodes explicitly; the GPU resource request alone
      # is insufficient to guarantee scheduling on accelerator nodes when mixed node
      # pools exist. Preferred node affinity (above) handles Spot vs on-demand preference.
      nodeSelector:
        cloud.google.com/gke-accelerator: nvidia-l4
      tolerations:
        - key: "cloud.google.com/gke-spot"
          operator: "Equal"
          value: "true"
          effect: "NoSchedule"
        - key: "nvidia.com/gpu"
          operator: "Equal"
          value: "present"
          effect: "NoSchedule"
      serviceAccountName: financial-advisor-sa
