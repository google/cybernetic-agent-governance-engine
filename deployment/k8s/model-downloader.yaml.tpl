apiVersion: batch/v1
kind: Job
metadata:
  name: model-downloader-${MODEL_NAME_SANITIZED}
  namespace: governance-stack
spec:
  ttlSecondsAfterFinished: 600 # Clean up job after checks
  template:
    spec:
      containers:
      - name: downloader
        image: python:3.9-slim
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -e
          pip install --upgrade huggingface_hub
          echo "⬇️ Downloading/Verifying model: ${MODEL_ID}"
          python3 -c "from huggingface_hub import snapshot_download; import os; snapshot_download(repo_id='${MODEL_ID}', cache_dir='/model-cache', token=os.environ.get('HF_TOKEN'))"
          echo "✅ Download complete."
        volumeMounts:
        - name: model-cache
          mountPath: /model-cache
        env:
        - name: HF_TOKEN
          valueFrom:
            secretKeyRef:
              name: hf-token-secret
              key: token
      restartPolicy: OnFailure
      volumes:
      - name: model-cache
        persistentVolumeClaim:
          claimName: model-cache-pvc
