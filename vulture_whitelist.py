# vulture_whitelist.py
# Allowlist for intentional Protocol stubs and forward-compatible parameters.

window_days  # src/cage_finance/safety/bounding/providers.py
asset  # src/cage_finance/rails/actions.py - NeMo Guardrails action signature
principal_id  # src/gateway/governance/contracts.py - protocol parameter
__context  # src/gateway/governance/defer_queue.py, pause_primitive.py - exception context
secret_id  # src/gateway/infrastructure/config_manager.py - forward-compatible
trace_state  # src/gateway/infrastructure/telemetry_client.py - OTel Sampler protocol
parent_run_id  # src/gateway/observability/langfuse_utils.py - Langfuse API compatibility
strategy_name  # src/governed_financial_advisor/demo/pipeline_manager.py - demo parameter
x_protocol_version  # src/integrations/provider_06/mock_endpoint.py - wire protocol header
