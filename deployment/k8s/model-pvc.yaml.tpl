apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: model-cache-${MODEL_KEY}-pvc
  namespace: governance-stack
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  storageClassName: standard-rwo
