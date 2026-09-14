# vulture_whitelist.py
# Allowlist for intentional Protocol stubs and forward-compatible parameters.

window_days  # noqa: B018 - src/cage_finance/safety/bounding/providers.py
asset  # noqa: B018 - src/cage_finance/rails/actions.py - NeMo Guardrails action signature
principal_id  # noqa: B018 - src/gateway/governance/contracts.py - protocol parameter
__context  # noqa: B018 - src/gateway/governance/defer_queue.py, pause_primitive.py - exception context
secret_id  # noqa: B018 - src/gateway/infrastructure/config_manager.py - forward-compatible
trace_state  # noqa: B018 - src/gateway/infrastructure/telemetry_client.py - OTel Sampler protocol
parent_run_id  # noqa: B018 - src/gateway/observability/langfuse_utils.py - Langfuse API compatibility
strategy_name  # noqa: B018 - src/governed_financial_advisor/demo/pipeline_manager.py - demo parameter
x_protocol_version  # noqa: B018 - src/integrations/provider_06/mock_endpoint.py - wire protocol header
