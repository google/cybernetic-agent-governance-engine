# Maintainer Runbook: Argolis / Altostrat DNS Policy & Delegation

> **Internal Maintainer Note:** This runbook documents internal DNS policies and procedures for open-source maintainers developing, testing, and demonstrating CAGE within Google's **Argolis (`altostrat.com`)** sandbox environment. It applies **exclusively to internal maintainer `dev` and `staging` postures** and is deliberately gitignored to prevent confusing general adopters of CAGE.

---

## 1. Altostrat DNS Use Policy

According to Google's Altostrat DNS policies:
- **No External Registrars or Purchases**: You are **not allowed to use an external DNS registrar or purchase new domains** for your `altostrat.com` (Argolis) projects.
- **Strictly Prohibited**: Bringing personally-owned vanity domains, using external registrars, or purchasing domains via Cloud Domains (which is backed by Squarespace) is strictly prohibited.
- **Mandatory Cloud DNS**: Your DNS records must be observable, auditable, and managed exclusively within **Google Cloud DNS** under your assigned Argolis subdomain (`{username}.demo.altostrat.com`).
- **No External Delegation**: Do not configure NS or CNAME records to delegate name management to any external domain registrar.

---

## 2. Step-by-Step Configuration Workflow

### Step 1: Register a Persistent Managed Zone in Cloud DNS
You must scope your DNS delegation to your specific Argolis subdomain (e.g., `{username}.demo.altostrat.com`):

1. Navigate to **Cloud DNS** in your Google Cloud Console within your Argolis project.
2. Click **Create Zone** and configure:
   - **Zone type:** Public
   - **DNS name:** Must exactly match your assigned subdomain: `{username}.demo.altostrat.com.` (or `{username}-{n}.demo.altostrat.com.` if recreating an environment).
   - **DNSSEC:** **Off** (Mandatory limitation: global external HTTPS load balancers on `altostrat.com` can experience resolution failures when DNSSEC is enabled).
3. Click **Create** and take note of the **name server shard** provided under "Registrar Setup" (e.g., `ns-cloud-d1.googledomains.com` indicates shard **`d`**).

Alternatively via `gcloud`:
```bash
gcloud dns managed-zones create argolis-demo-zone \
  --dns-name="USERNAME.demo.altostrat.com." \
  --description="Argolis maintainer persistent demo zone" \
  --visibility=public \
  --dnssec-state=off \
  --project=YOUR_PROJECT_ID
```

### Step 2: Mandatory 24-Hour Wait Period
Before proceeding to delegation:
> **You must wait 24 hours** from when the DNS Zone was created so that Cloud Asset Inventory (CAI) can report it properly to the Argolis verification backend. Submitting premature delegation requests will fail or be rejected.

### Step 3: Submit DNS Delegation Request in Argolis Portal
Once the zone is created and the 24-hour waiting period has passed:
1. Navigate to the Argolis self-service portal at [go/argolis](http://go/argolis).
2. Expand your environment card and select **Request DNS managed zone**.
3. In the dialog box, specify:
   - **Org name:** `{username}.altostrat.com`
   - **DNS shard:** The letter representing your name server shard (e.g., `d`).
   - **Project ID:** Select the project where you created the DNS managed zone.
   - **Zone name:** Select the managed zone you just created (e.g., `argolis-demo-zone`).
4. Acknowledge the confirmation and click **Request**.

### Step 4: Configure Cloud Run Dev/Staging Posture
Once delegated, point your ephemeral Cloud Run application stack to the persistent zone via `terraform.auto.tfvars`:
```hcl
enable_load_balancer = true
gateway_domain       = "gateway.USERNAME.demo.altostrat.com"
enable_cloud_dns     = true
dns_zone_name        = "argolis-demo-zone"
```

Terraform automatically provisions the managed SSL certificate and creates the `A` record pointing to the external load balancer IP (`load_balancer_ip`).

---

## 3. Critical Security Notice: Subdomain Takeover & Orphaned Zones

> [!CAUTION]
> **Avoid Orphaned DNS Managed Zones:**
> Do not delete your foundational DNS managed zone or its hosting project once configured. Because your delegation in `go/argolis` remains tied to your assigned name server shard, deleting a managed zone creates an **orphaned DNS zone** vulnerability, allowing another user allocated the same shard to recreate the zone and hijack your subdomain.
>
> When tearing down demos or running `terraform destroy`:
> - The ephemeral `A` record set (`google_dns_record_set.gateway`) is safely deleted by Terraform.
> - **NEVER delete the Cloud DNS managed zone itself** or cancel the Argolis portal delegation during routine teardowns.

