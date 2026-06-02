apiVersion: apps/v1
kind: Deployment
metadata:
  name: financial-advisor-ui
  namespace: governance-stack
  labels:
    app: financial-advisor-ui
spec:
  replicas: 1
  selector:
    matchLabels:
      app: financial-advisor-ui
  template:
    metadata:
      labels:
        app: financial-advisor-ui
    spec:
      serviceAccountName: financial-advisor-sa
      containers:
        - name: ui
          image: ${REGISTRY_URL}/financial-advisor-ui:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"
            - name: BACKEND_URL
              value: "http://governed-financial-advisor.governance-stack.svc.cluster.local:80"
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: financial-advisor-ui
  namespace: governance-stack
spec:
  type: ClusterIP
  selector:
    app: financial-advisor-ui
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
