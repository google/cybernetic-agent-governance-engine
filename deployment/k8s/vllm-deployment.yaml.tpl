# NOTE: This manifest contains GKE-specific node selectors for GPU and spot instance scheduling.
# For other Kubernetes distributions, replace the GKE-specific nodeSelector labels with the
# platform-equivalent labels documented inline. The GPU resource requests (nvidia.com/gpu)
# are standard Kubernetes and work on any cluster with the NVIDIA device plugin installed.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}
  namespace: ${NAMESPACE}
  labels:
    app: ${APP_NAME}
  annotations:
    # GCS Fuse CSI — only active when MODEL_VOLUME_TYPE=gcs_fuse.
    # Harmless on non-GCS clusters (annotation is ignored if driver absent).
    gke-gcsfuse/volumes: "true"
spec:
  replicas: 1
  # Recreate strategy: GPU pods require the full VRAM of the node. With only one
  # GPU node per model, a RollingUpdate would attempt to start a 2nd pod before
  # terminating the 1st, which is impossible — the new pod would stay Pending
  # indefinitely. Recreate terminates the old pod first, then starts the new one.
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: ${APP_NAME}
  template:
    metadata:
      labels:
        app: ${APP_NAME}
      annotations:
        gke-gcsfuse/volumes: "true"
    spec:
      serviceAccountName: financial-advisor-sa
      affinity:
        podAntiAffinity:
          # requiredDuringScheduling: enforces that each vllm-inference replica
          # lands on a separate node, protecting VRAM on each L4 GPU.
          # Requires the Spot L4 node pool to have >= 2 nodes.
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - ${APP_NAME}
            topologyKey: "kubernetes.io/hostname"
      volumes:
        - name: dshm
          emptyDir:
            medium: Memory
            sizeLimit: "16Gi"  # vLLM requires large shared memory
        # ── Vendor-neutral model volume ────────────────────────────────────
        # Rendered by deploy_sw.py._render_model_volume() based on
        # MODEL_VOLUME_TYPE env var:
        #   gcs_fuse      → GCS Fuse CSI (gcsfuse.csi.storage.gke.io)
        #   mountpoint_s3 → AWS Mountpoint-S3 CSI (s3.csi.aws.com)
        #   pvc           → PersistentVolumeClaim
        #   empty_dir     → ephemeral emptyDir (default/fallback)
${MODEL_VOLUME_SPEC}
      containers:
        - name: vllm
          # Standard vLLM image — no runai extras required (tensorizer is built-in)
          image: ${IMAGE_NAME}
          imagePullPolicy: IfNotPresent
          resources:
            limits:
${RESOURCE_LIMITS}
              memory: "64Gi"
              cpu: "16"
              nvidia.com/gpu: "1"
            requests:
${RESOURCE_REQUESTS}
              memory: "10Gi"
              cpu: "3"
          volumeMounts:
            - mountPath: /dev/shm
              name: dshm
            # ── Vendor-neutral model volume mount ──────────────────────────
            # Rendered by deploy_sw.py._render_model_volume() to match the
            # volume spec above.  Empty string when MODEL_VOLUME_TYPE=empty_dir
            # and model is fetched at runtime (e.g. HuggingFace Hub).
${MODEL_VOLUME_MOUNT}
          # ── Object-store credentials (vendor-neutral) ──────────────────
          # S3_ENDPOINT_URL selects the backend:
          #   https://storage.googleapis.com  → GCS via S3-compat API
          #   http://minio:9000               → in-cluster MinIO
          #   (empty)                         → AWS S3 (boto3 default)
          env:
            - name: S3_ENDPOINT_URL
              value: "${S3_ENDPOINT_URL}"
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: minio-credentials
                  key: access-key
                  optional: true
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: minio-credentials
                  key: secret-key
                  optional: true
            - name: AWS_EC2_METADATA_DISABLED
              value: "true"
            # ── Model loading configuration ────────────────────────────────
            - name: VLLM_LOAD_FORMAT
              value: "${VLLM_LOAD_FORMAT}"
            - name: MODEL_PATH
              value: "${MODEL_PATH}"
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
          command: ["/bin/bash", "-c"]
          args:
            - |
${ARGS}
      nodeSelector:
        # Use the standard GKE GPU node label — nvidia.com/gpu.product is NOT
        # applied by GKE and will prevent scheduling on all node types.
        # GPU node selector — platform equivalents:
        #   GKE:       cloud.google.com/gke-gpu: "true"
        #   EKS:       (no direct equivalent; use k8s.amazonaws.com/accelerator instead)
        #   AKS:       (no direct equivalent; use accelerator label instead)
        #   On-prem:   (remove; rely on nvidia.com/gpu resource request)
        cloud.google.com/gke-gpu: "true"
${NODE_SELECTOR}
      tolerations:
        - key: "nvidia.com/gpu"
          operator: "Equal"
          value: "present"
          effect: "NoSchedule"
        # Spot/preemptible node toleration — platform equivalents:
        #   GKE:    cloud.google.com/gke-spot: "true"
        #   EKS:    eks.amazonaws.com/capacityType: SPOT
        #   AKS:    kubernetes.azure.com/scalesetpriority: spot
        #   On-prem: Remove this toleration; use PriorityClass instead
        - key: "cloud.google.com/gke-spot"
          operator: "Equal"
          value: "true"
          effect: "NoSchedule"
${TOLERATIONS}
