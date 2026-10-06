# Single source of the CAGE deployment jurisdiction for the static-manifest path.
#
# Every CAGE workload reads CAGE_DEPLOYMENT_REGION from this ConfigMap via
# configMapKeyRef (optional: false), so the gateway, advisor, compliance
# bridge, reconciliation worker and Lula audit cron can never disagree about
# the jurisdiction. Integration tests discover their region from it too.
# The Terraform path creates the same object via infra/modules/deployment_config.
#
# Render with:
#   CAGE_DEPLOYMENT_REGION=EU_ECB envsubst '${CAGE_DEPLOYMENT_REGION}' \
#     < deployment/k8s/cage-deployment-configmap.yaml.tpl | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: cage-deployment
  namespace: governance-stack
  labels:
    app.kubernetes.io/part-of: cage
data:
  # US_FED | EU_ECB | APAC_MAS
  CAGE_DEPLOYMENT_REGION: "${CAGE_DEPLOYMENT_REGION}"
