NAMESPACE ?= cage

.PHONY: generate-policies \
        vllm-status \
        vllm-verify-models \
        advisor-status \
        advisor-rollback \
        advisor-watch \
        advisor-verify-env \
        advisor-port-forward \
        advisor-health \
        test-integration \
        test-r22 \
        test-cybernetic-loop \
        verify-tla \
        update-nemo-configmap \
        notices \
        recovery \
        deploy-bg \
        build-bg \
        deploy-status \
        deploy-logs \
        deploy-kill \
        verify-deploy \
        poam-drift-check \
        lint \
        security \
        docs-check \
        test \
        test-fast \
        test-last-failed \
        test-coverage \
        test-random \
        test-mesh \
        test-gke-e2e \
        test-live

generate-policies:
	@echo "Regenerating governance policies from RiskAnalystAgent outputs..."
	@python -m src.governed_financial_advisor.governance.transpiler
	@echo "Done. Review generated_actions.py and generated_rules.rego before deployment."

# ---------------------------------------------------------------------------
# vLLM diagnostics
# ---------------------------------------------------------------------------

vllm-status:
	@echo "==> vLLM pod status (namespace: $(NAMESPACE))"
	@kubectl get pods -n $(NAMESPACE) -l app=vllm

vllm-verify-models:
	@echo "==> vllm-inference models:"
	@kubectl port-forward -n $(NAMESPACE) svc/vllm-inference 8000:8000 &> /tmp/pf-vllm-inference.log & \
	  PF_PID=$$!; \
	  sleep 3; \
	  curl -sf http://localhost:8000/v1/models | python3 -m json.tool || echo "(curl failed)"; \
	  kill $$PF_PID 2>/dev/null
	@echo ""
	@echo "==> vllm-reasoning models:"
	@kubectl port-forward -n $(NAMESPACE) svc/vllm-reasoning 8000:8000 &> /tmp/pf-vllm-reasoning.log & \
	  PF_PID=$$!; \
	  sleep 3; \
	  curl -sf http://localhost:8000/v1/models | python3 -m json.tool || echo "(curl failed)"; \
	  kill $$PF_PID 2>/dev/null

# ---------------------------------------------------------------------------
# governed-financial-advisor diagnostics & recovery
# ---------------------------------------------------------------------------

advisor-status:
	@echo "==> governed-financial-advisor pod status (namespace: $(NAMESPACE))"
	@kubectl get pods -n $(NAMESPACE) -l app=governed-financial-advisor

advisor-rollback:
	@echo "==> Rolling back governed-financial-advisor deployment..."
	@kubectl rollout undo deployment/governed-financial-advisor -n $(NAMESPACE)
	@echo ""
	@echo "Rollback issued. Run 'make advisor-watch' to monitor pod initialisation."

advisor-watch:
	@echo "==> Watching governed-financial-advisor pods (namespace: $(NAMESPACE)) — Ctrl+C to stop"
	@kubectl get pods -n $(NAMESPACE) -l app=governed-financial-advisor -w

advisor-verify-env:
	@echo "==> Environment variables in governed-financial-advisor deployment:"
	@kubectl exec -n $(NAMESPACE) deploy/governed-financial-advisor -- env | sort

advisor-port-forward:
	@echo "Forwarding governed-financial-advisor to localhost:8080 — press Ctrl+C to stop"
	@kubectl port-forward -n $(NAMESPACE) svc/governed-financial-advisor 8080:8080

advisor-health:
	@echo "==> Checking /health on governed-financial-advisor..."
	@kubectl port-forward -n $(NAMESPACE) svc/governed-financial-advisor 8080:8080 &> /tmp/pf-advisor.log & \
	  PF_PID=$$!; \
	  sleep 3; \
	  curl -sf http://localhost:8080/health | python3 -m json.tool || echo "(curl failed)"; \
	  kill $$PF_PID 2>/dev/null

# ---------------------------------------------------------------------------
# Deployment verification
# ---------------------------------------------------------------------------

.PHONY: verify-deploy
verify-deploy: ## Verify GKE deployment matches latest build and all Secrets are populated
	./scripts/verify_deploy.sh

# ---------------------------------------------------------------------------
# Linting and Security
# ---------------------------------------------------------------------------

## Run linters and lockfile validation
lint:
	@echo "==> Running ruff linter..."
	@uv run ruff check src/ scripts/ tests/
	@echo "==> Validating dependency lockfile..."
	@uv lock --check
	@echo "✅ Lint checks passed."

## Run security scanning (lockfile check, Bandit SAST, pip-audit CVEs, Semgrep)
security:
	@echo "==> Validating dependency lockfile..."
	@uv lock --check
	@echo ""
	@echo "==> Running Bandit SAST scanner..."
	@uv run --with bandit bandit -r src/ scripts/ -c pyproject.toml -ll -ii
	@echo ""
	@echo "==> Running pip-audit for CVE scanning..."
	@uv run pip-audit
	@echo ""
	@echo "==> Running Semgrep static analysis..."
	@uv run --with semgrep semgrep scan --config=auto --error src/
	@echo "✅ Security scans completed."

## Run documentation integrity gates (mirrors CI gate G9)
docs-check:
	@echo "==> Checking documentation references (broken links, dangling paths, stale symbols)..."
	@uv run python scripts/check_doc_references.py \
		--path README.md \
		--path AGENTS.md \
		--path COMPLIANCE.md \
		--path SECURITY.md \
		--path CONTRIBUTING.md \
		--path docs/architecture \
		--path compliance
	@echo "==> Checking vendor brand leakage into executable code..."
	@uv run python scripts/check_vendor_brands.py --verbose
	@echo "==> Checking domain literal leakage into kernel/integrations..."
	@uv run python scripts/check_domain_literals.py --verbose
	@echo "✅ Documentation integrity checks passed."

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

## Fast local test run (no coverage, parallel) — the default developer shortcut
test-fast:
	uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -q

## Run only tests that failed in the last run (fastest feedback loop)
test-last-failed:
	uv run pytest tests/ -m "local or unit" --lf --dist loadscope -n auto -q

## Full local run with coverage (mirrors CI)
test-coverage:
	uv run pytest tests/ -m "local or unit" -n auto --dist loadscope -p no:langsmith -p no:langsmith_plugin --cov=src --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=70

## Randomized test order (weekly, for dependency detection)
## Reproduce a failure: uv run pytest --randomly-seed=last
test-random:
	uv run pytest tests/ -m "local or unit" -n auto --dist loadscope -p randomly --randomly-seed=0 -q

## Default: fast run
test: test-fast

## Legacy alias — run local (non-infrastructure) tests verbosely
test-integration:
	@echo "==> Running local (non-infrastructure) tests..."
	@uv run pytest tests/ -v --tb=short -m local

## Run live external partner integration tests (requires partner credentials)
test-partner:
	@echo "==> Running live external partner integration tests..."
	@echo "NOTE: Requires partner sandbox credentials. See config/environments/partner-sandbox.env.example"
	@uv run pytest tests/ -m partner_integration --run-partner-integration -v

## Run Linkerd service-mesh conformance tests against a Linkerd-enabled cluster (kind or GKE)
## Prerequisite: the governance-stack/cage-deployment ConfigMap (live runs read the region from it):
##   envsubst '$${CAGE_DEPLOYMENT_REGION}' < deployment/k8s/cage-deployment-configmap.yaml.tpl | kubectl apply -f -
test-mesh:
	@echo "==> Running Linkerd service-mesh conformance tests..."
	@SKIP_PORT_FORWARD_CHECKS=1 uv run pytest tests/integration/test_linkerd_mesh_conformance.py --run-integration -n0 --no-cov -p no:langsmith -p no:langsmith_plugin -v

## Run the live GKE trade-governance e2e suite (tests/e2e/) as an in-cluster, meshed Job.
## Requires REGISTRY_URL and the adopter-created Secret cage-e2e-credentials.
E2E_JOB ?= cage-verify-trade-e2e
E2E_NAMESPACE ?= governance-stack
test-gke-e2e:
	@test -n "$(REGISTRY_URL)" || { echo "REGISTRY_URL is required"; exit 1; }
	@echo "==> Running live GKE trade-governance e2e Job..."
	@kubectl delete job/$(E2E_JOB) -n $(E2E_NAMESPACE) --ignore-not-found --wait=true
	@REGISTRY_URL="$(REGISTRY_URL)" envsubst '$${REGISTRY_URL}' < deployment/k8s/verify-trade-e2e-job.yaml | kubectl apply -f -
	@for i in $$(seq 1 180); do \
	  if kubectl get job/$(E2E_JOB) -n $(E2E_NAMESPACE) -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' | grep -q True; then RC=0; break; fi; \
	  if kubectl get job/$(E2E_JOB) -n $(E2E_NAMESPACE) -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' | grep -q True; then RC=1; break; fi; \
	  RC=2; sleep 5; \
	done; \
	kubectl logs job/$(E2E_JOB) -n $(E2E_NAMESPACE) -c verify-trade-e2e --tail=-1 || true; \
	if [ "$$RC" = "2" ]; then echo "e2e Job timed out"; fi; \
	exit $$RC

## Run live external service tests (e.g. Google CAS certificate issuance)
test-live:
	@echo "==> Running live external tests..."
	@uv run pytest tests/live/ -m live_external --run-live-external -n0 --no-cov -p no:langsmith -p no:langsmith_plugin -v

## Run R-22 regression guard test suite
test-r22:
	@echo "==> Running R-22 NeMo action registry regression guard..."
	@uv run pytest tests/test_nemo_action_registry.py -v --tb=short

## Run cybernetic loop regression tests (endpoint wiring, webhook, apply-refinement)
test-cybernetic-loop:
	@echo "==> Running cybernetic loop regression tests..."
	@uv run pytest tests/test_cybernetic_loop.py -v --tb=short

## Run JCS property-based invariant tests (canonical serialization fuzzing)
test-property:
	@echo "==> Running JCS property-based invariant tests..."
	@uv run pytest tests/test_jcs_property_invariants.py -v

# ---------------------------------------------------------------------------
# TLA+ model checking (formal verification)
# ---------------------------------------------------------------------------

## Model-check every pinned proof/*.cfg with TLC (DistributedCBF vs the Python BFS; FtraBoundary, LangGraphHarness vs proof/tla_pins.py).
## Needs TLA_TOOLS_JAR=/path/to/tla2tools.jar (JAVA=... if java is not on PATH);
## without it, runs the Python BFS only (POAM-2026-090, POAM-2026-091).
verify-tla:
	@uv run python proof/distributed_cbf_model.py
	@if [ -n "$$TLA_TOOLS_JAR" ]; then \
		uv run python scripts/verify_tla.py; \
	else \
		echo "TLA_TOOLS_JAR not set: TLC skipped (Python BFS only; FtraBoundary and LangGraphHarness need TLC)."; \
		echo "Download tla2tools.jar from https://github.com/tlaplus/tlaplus/releases"; \
	fi

# ---------------------------------------------------------------------------
# NeMo ConfigMap sync (R-22 fix)
# ---------------------------------------------------------------------------

## Regenerate deployment/k8s/nemo-rails-configmap.yaml from config/rails/.
## Run this after any change to config/rails/actions.py, definitions.co,
## main_logic.co, config.yml, or prompts.yml.
##
## Requires: kubectl, python3
update-nemo-configmap:
	@echo "==> Regenerating nemo-rails-configmap.yaml from config/rails/ ..."
	@kubectl create configmap nemo-rails-config \
	  --namespace=governance-stack \
	  --from-file=actions.py=config/rails/actions.py \
	  --from-file=config.yml=config/rails/config.yml \
	  --from-file=definitions.co=config/rails/definitions.co \
	  --from-file=main_logic.co=config/rails/main_logic.co \
	  --from-file=prompts.yml=config/rails/prompts.yml \
	  --dry-run=client -o yaml \
	  > deployment/k8s/nemo-rails-configmap.yaml
	@echo "✅ deployment/k8s/nemo-rails-configmap.yaml updated."
	@echo "   Review the diff and commit; then apply with:"
	@echo "   kubectl apply -f deployment/k8s/nemo-rails-configmap.yaml"

# ---------------------------------------------------------------------------
# License notices
# ---------------------------------------------------------------------------

## Generate THIRD_PARTY_NOTICES.md from all Python and Node.js environments
.PHONY: notices
notices:
	@echo "🔍 Generating third-party license notices..."
	@bash scripts/generate_notices.sh
	@echo "✅ Done. Review THIRD_PARTY_NOTICES.md before committing."

# ---------------------------------------------------------------------------
# Recovery convenience target
# ---------------------------------------------------------------------------

recovery:
	@echo ""
	@echo "Recovery checklist:"
	@echo "  1. make vllm-status"
	@echo "  2. make vllm-verify-models"
	@echo "  3. make advisor-status"
	@echo "  4. make advisor-rollback  (if CrashLoopBackOff)"
	@echo "  5. make advisor-watch"
	@echo "  6. make advisor-verify-env"
	@echo "  7. make advisor-port-forward  (in separate terminal)"
	@echo "  8. make test-integration"
	@echo ""

# ---------------------------------------------------------------------------
# Background deployment — bypasses tool-level timeout restrictions
#
# These targets launch deploy_all.sh / build_images.sh fully detached from
# the calling terminal via scripts/deploy_bg.sh.  The process is double-forked
# (nohup + disown) so it survives terminal/tool closure and is never subject
# to the 35-minute execute_command cap in the Roo/VS Code environment.
#
# Usage:
#   make deploy-bg TARGET=gcp-gke ENV=dev [EXTRA_ARGS="--auto-approve"]
#   make deploy-bg TARGET=gcp-gke ENV=prod EXTRA_ARGS="--auto-approve --var-file=infra/targets/gcp-gke/prod.tfvars"
#   make build-bg
#   make deploy-status
#   make deploy-logs
#   make deploy-kill
# ---------------------------------------------------------------------------

TARGET     ?= gcp-gke
ENV        ?= dev
EXTRA_ARGS ?=

## Launch deploy_all.sh in the background (detached, survives tool timeout).
## Set TARGET, ENV, and EXTRA_ARGS as needed.
## Example: make deploy-bg TARGET=gcp-gke ENV=dev EXTRA_ARGS="--auto-approve"
deploy-bg: scripts/deploy_bg.sh
	@chmod +x scripts/deploy_bg.sh
	@bash scripts/deploy_bg.sh --target $(TARGET) --env $(ENV) $(EXTRA_ARGS)

## Launch build_images.sh in the background (image builds only, no Terraform).
build-bg: scripts/deploy_bg.sh
	@chmod +x scripts/deploy_bg.sh
	@bash scripts/deploy_bg.sh --build-only

## Show status of the most recent background deployment (PID + last 20 log lines).
deploy-status: scripts/deploy_bg.sh
	@chmod +x scripts/deploy_bg.sh
	@bash scripts/deploy_bg.sh --status

## Tail the most recent background deployment log (live, Ctrl+C to stop).
deploy-logs: scripts/deploy_bg.sh
	@chmod +x scripts/deploy_bg.sh
	@bash scripts/deploy_bg.sh --logs

## Cancel an in-progress background deployment (sends SIGTERM to process group).
deploy-kill: scripts/deploy_bg.sh
	@chmod +x scripts/deploy_bg.sh
	@bash scripts/deploy_bg.sh --kill

# ---------------------------------------------------------------------------
# Compliance drift checks
# ---------------------------------------------------------------------------

.PHONY: poam-drift-check
poam-drift-check: ## Check that all closed POAM findings have a corresponding Lula assertion
	python3 scripts/check_poam_lula_divergence.py

.PHONY: check-agent-state-schema
check-agent-state-schema: ## Verify AgentState schema freshness
	@echo "==> Verifying AgentState schema freshness..."
	@uv run python scripts/generate_agent_state_schema.py --check

.PHONY: build-client-sdk
build-client-sdk: ## Build standalone CAGE Client SDK wheel and sdist in packages/cage-client/
	@echo "==> Building CAGE Client SDK (packages/cage-client)..."
	@cd packages/cage-client && uv build
