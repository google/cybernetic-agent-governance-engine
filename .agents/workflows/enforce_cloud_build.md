---
description: How to build container images for the Cybernetic Governance Engine
---

# Enforce Google Cloud Build

When modifying or deploying container images for this project, you **MUST NEVER** use the local Docker daemon (`docker build`). 

Due to architecture mismatch issues (building ARM64 images on macOS that crash on x86 GKE nodes), this repository strictly uses **Google Cloud Build** for all container packaging.

## Instructions for the Agent

1. **Never use `docker build`**.
2. **Never configure `--platform linux/amd64` locally** using Docker or BuildKit.
3. **Always use `gcloud builds submit`** to build images remotely.
4. **When editing deployment scripts** (like `deploy_sw.py`), ensure all build pipelines invoke `gcloud builds submit` and pass the context to GCP, rather than wrapping local Docker API calls.
5. **If the user explicitly asks to build an image**, draft a `cloudbuild.yaml` file (or use inline `--config` with `gcloud`) to submit the build to the cloud.
