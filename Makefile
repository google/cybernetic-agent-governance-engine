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
        recovery

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
# Testing
# ---------------------------------------------------------------------------

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
