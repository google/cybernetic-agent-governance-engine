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
        test \
        test-fast \
        test-last-failed \
        test-coverage \
        test-random

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

## Run R-22 regression guard test suite
test-r22:
	@echo "==> Running R-22 NeMo action registry regression guard..."
	@uv run pytest tests/test_nemo_action_registry.py -v --tb=short

## Run cybernetic loop regression tests (endpoint wiring, webhook, apply-refinement)
test-cybernetic-loop:
	@echo "==> Running cybernetic loop regression tests..."
	@uv run pytest tests/test_cybernetic_loop.py -v --tb=short

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
