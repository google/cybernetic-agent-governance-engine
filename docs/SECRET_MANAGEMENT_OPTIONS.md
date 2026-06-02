# Secret Management Options

> **ADR: Google Secret Manager was removed in favour of Kubernetes-native secret
> injection (env vars from `Secret` objects). No runtime dependency on
> `google-cloud-secret-manager`.**
>
> **Document scope:** Describes the current state of secret management in the
> Cybernetic Governance Engine. Secrets are provided exclusively via environment
> variables or Kubernetes `Secret` objects mounted as env vars. GCP Secret
> Manager is **not** an active runtime path.

---

## 1. Current State

### Where secrets live

Secrets are provided via **Kubernetes `Secret` objects** whose values are
injected into pods as environment variables via `envFrom` / `secretRef`.
There is no runtime dependency on GCP Secret Manager or any other external
secret store API.

| Secret store                         | Contents                        | How populated              |
| ------------------------------------ | ------------------------------- | -------------------------- |
| **Kubernetes `Secret` objects**      | Runtime values consumed by pods | `kubectl` / CI / Terraform |
| **Environment variables (local/CI)** | Dev/test values                 | `.env` files or CI secrets |

### K8s secrets affected

| K8s Secret name          | Namespace          | Contents                                                                             |
| ------------------------ | ------------------ | ------------------------------------------------------------------------------------ |
| `oscal-artifact-secrets` | `governance-stack` | OSCAL HMAC access key, HMAC secret key, storage bucket name                          |
| `advisor-secrets`        | `governance-stack` | Langfuse host/public/secret keys, S3-compatible storage HMAC creds, cold-tier bucket |
| `minio-credentials`      | `governance-stack` | MinIO root user / root password                                                      |

### Gap: no automated sync

There is **no automated mechanism** to pull from the external secret store and apply
values into Kubernetes Secrets. The project has **no** `SecretProviderClass`
(CSI driver) and **no** External Secrets Operator (ESO) resources.

Secrets are currently created via one of:

1. **Manual `kubectl` invocation** — operators run `kubectl create secret …`
   by hand using values copied from the secret store.
2. **`deployment/scripts/create_secret_manual.py`** — a helper script that
   reads secret values and applies them with `kubectl`.
3. **CI pipelines** — GitHub Actions workflows that have both secret-store and
   K8s access inject secrets at deploy time.

Any rotation in the external secret store requires a **separate manual step** to
re-apply the new values to the K8s Secret. This is the primary operational risk.

---

## 2. Option A — External Secrets Operator (ESO)

### How it works

The [External Secrets Operator](https://external-secrets.io/) runs as a
controller in the cluster and reconciles `ExternalSecret` CRDs with the
external secret store on a configurable interval, writing the values into
standard K8s `Secret` objects automatically.

ESO supports many backends out of the box — GCP Secret Manager (`gcpsm`),
AWS Secrets Manager (`aws`), Azure Key Vault (`azurekv`), HashiCorp Vault
(`vault`), and more. See the
[ESO provider docs](https://external-secrets.io/latest/provider/aws-secrets-manager/)
for the full list.

### Installation

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets \
  --create-namespace
```

### Required IAM / permissions

The `financial-advisor-sa` Kubernetes Service Account (or a dedicated ESO SA)
must have read access to the secret store. The exact permission depends on the
provider:

| Provider            | Required permission                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------- |
| GCP Secret Manager  | `roles/secretmanager.secretAccessor` on the GCP Service Account bound via Workload Identity |
| AWS Secrets Manager | `secretsmanager:GetSecretValue` in an IAM policy attached to the pod's IRSA role            |
| HashiCorp Vault     | A Vault policy granting `read` on the relevant secret paths                                 |

For the GCP reference deployment, the binding can be added to
`deployment/terraform/iam.tf`.

### ClusterSecretStore — GCP example (reference deployment)

```yaml
# GCP Secret Manager example — swap provider for your cloud:
# AWS: provider.aws.service: SecretsManager, region: YOUR_REGION, auth: jwt/irsa
# Vault: provider.vault.server: https://vault.example.com, path: secret, ...
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: external-secret-store
spec:
  provider:
    gcpsm: # ← GCP-specific; change to aws/azurekv/vault etc.
      projectID: YOUR_GCP_PROJECT_ID
      auth:
        workloadIdentity:
          clusterLocation: YOUR_GKE_REGION
          clusterName: YOUR_GKE_CLUSTER
          serviceAccountRef:
            name: financial-advisor-sa
            namespace: governance-stack
```

### Example ExternalSecret for `oscal-artifact-secrets`

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: oscal-artifact-secrets
  namespace: governance-stack
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: external-secret-store
    kind: ClusterSecretStore
  target:
    name: oscal-artifact-secrets
    creationPolicy: Owner
  data:
    - secretKey: bucket-name
      remoteRef:
        key: oscal-artifact-bucket-name # secret ID in your store
    - secretKey: hmac-access-key
      remoteRef:
        key: oscal-hmac-access-key
    - secretKey: hmac-secret-key
      remoteRef:
        key: oscal-hmac-secret-key
```

### Pros

- **GitOps-native**: `ExternalSecret` manifests live in the repo alongside
  other K8s manifests.
- **Automatic rotation sync**: once the external store is rotated, ESO
  re-syncs on the next `refreshInterval` with no manual intervention.
- **Widely adopted**: large community, well-documented, CNCF Sandbox project.
- **Works with existing secrets**: the K8s `Secret` objects that pods already
  reference do not need to change.
- **Cloud-portable**: change only the `ClusterSecretStore` provider spec to
  switch secret backends.

### Cons

- Additional operator to install, upgrade, and monitor.
- Requires IAM/RBAC binding appropriate to the chosen provider.
- Adds a reconciliation delay of up to `refreshInterval` after a rotation
  (mitigated with short intervals or forced reconcile).

---

## 3. Option B — Direct Secret Store API (historical reference only)

> ⚠️ **This option is no longer active.** The `google-cloud-secret-manager`
> SDK dependency has been removed from the application. `ConfigManager` now
> resolves secrets exclusively via env vars → default (two-tier).
> See module docstring ADR in
> `src/governed_financial_advisor/infrastructure/config_manager.py`.

This option previously described calling the GCP Secret Manager SDK directly
from application code. It was removed because:

- It tightly coupled the application to a GCP-specific API.
- Kubernetes-native secret injection (env vars from `Secret` objects) achieves
  the same result without a runtime cloud API dependency.
- It complicated local development and non-GKE deployments.

For reference: secrets are now injected at pod startup via `envFrom` and are
available as standard environment variables. The `ConfigManager.get()` method
reads these with `os.getenv(key)` and falls back to the supplied `default`.

---

## 4. Option C — CI/CD Secret Injection (improved current approach)

### How it works

Keep standard Kubernetes `Secret` objects but automate their creation inside
CI. On every deployment, the CI pipeline:

1. Authenticates to the secret store with Workload Identity / OIDC.
2. Reads the current secret values.
3. Creates or updates K8s Secrets using the idempotent
   `--dry-run=client -o yaml | kubectl apply -f -` pattern.

### Example GitHub Actions step — GCP Secret Manager

```yaml
# GCP example — for AWS substitute:
#   aws secretsmanager get-secret-value --secret-id <name> --query SecretString --output text
- name: Sync advisor-secrets from secret store
  run: |
    LANGFUSE_HOST=$(gcloud secrets versions access latest \
      --secret="advisor-langfuse-host" --project="${{ env.GCP_PROJECT }}")
    LANGFUSE_PUBLIC_KEY=$(gcloud secrets versions access latest \
      --secret="advisor-langfuse-public-key" --project="${{ env.GCP_PROJECT }}")
    LANGFUSE_SECRET_KEY=$(gcloud secrets versions access latest \
      --secret="advisor-langfuse-secret-key" --project="${{ env.GCP_PROJECT }}")
    COLD_TIER_BUCKET=$(gcloud secrets versions access latest \
      --secret="advisor-cold-tier-bucket" --project="${{ env.GCP_PROJECT }}")

    kubectl create secret generic advisor-secrets \
      --namespace=governance-stack \
      --from-literal=LANGFUSE_HOST="$LANGFUSE_HOST" \
      --from-literal=LANGFUSE_PUBLIC_KEY="$LANGFUSE_PUBLIC_KEY" \
      --from-literal=LANGFUSE_SECRET_KEY="$LANGFUSE_SECRET_KEY" \
      --from-literal=cold-tier-bucket="$COLD_TIER_BUCKET" \
      --dry-run=client -o yaml | kubectl apply -f -
```

> **Security note:** Use `::add-mask::` in GitHub Actions to redact secrets
> from logs:
>
> ```yaml
> echo "::add-mask::$LANGFUSE_SECRET_KEY"
> ```

The `deployment/scripts/create_secret_manual.py` script already implements a
local variant of this pattern and can serve as a reference.

### Pros

- No new operators or CRDs — works with the existing cluster setup.
- Already partially implemented (`create_secret_manual.py`, existing CI).
- Simple to understand and audit.

### Cons

- Secret values are briefly present in CI environment variables — must use
  masking and least-privilege CI credentials.
- CI must hold both secret-store credentials and K8s credentials simultaneously.
- Still a manual step for out-of-band rotations that happen outside a
  deployment event.

---

## 5. Recommendation

| Horizon                | Recommendation                                                                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Immediate (days)**   | Option C — add a CI step per the example above. Improves on the current manual process with no infra changes.                                     |
| **Short-term (weeks)** | Option A — install ESO and migrate secrets to `ExternalSecret` manifests. Configure the `ClusterSecretStore` for your chosen provider.            |
| **Long-term**          | Consider Option B selectively for new services that can use Workload Identity / IRSA natively; do not apply retroactively to `compliance-bridge`. |

For the reference deployment, Terraform in `deployment/terraform/secrets.tf`
manages `kubernetes_secret` resources directly. ESO adoption with any supported
backend (Vault, AWS Secrets Manager, Azure Key Vault, etc.) would reference
those same K8s Secret names — no GCP Secret Manager dependency is required.

---

## 6. Storage Backend Decision

The `governed-financial-advisor` service supports three storage backends,
controlled by the `STORAGE_BACKEND` environment variable:

| `STORAGE_BACKEND` value | Implementation                                                               | Use case                                       |
| ----------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------- |
| `gcs`                   | GCS-native SDK (`google-cloud-storage`), authenticated via Workload Identity | Production on GKE with GCP; no long-lived keys |
| `s3`                    | boto3, S3-compatible                                                         | AWS S3, GCS HMAC S3-compat API, or MinIO       |
| `local`                 | Filesystem                                                                   | Local development and testing                  |

**Source:** [`src/governed_financial_advisor/infrastructure/storage.py`](../src/governed_financial_advisor/infrastructure/storage.py)

The `compliance-bridge` service uses a **separate** S3-compatible storage
implementation:

**Source:** [`src/compliance_bridge/storage.py`](../src/compliance_bridge/storage.py)

This implementation uses boto3 with HMAC keys to archive OSCAL artifacts
for ISO 42001 A.7.5 durable evidence retention. It is intentionally
**independent** of the financial advisor storage layer and is not expected to
migrate to a native cloud SDK in the near term, because HMAC keys allow the same
code path to work with MinIO (local) and any S3-compatible endpoint (GCS HMAC,
AWS S3) without changes.
