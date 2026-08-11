# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
NeMo Guardrails gRPC Sidecar Server
=====================================
Date documented: 2026-03-10

This module implements a standalone gRPC server that exposes NeMo Guardrails
validation over the network via the ``governance.NeMoGuardrails`` service
defined in ``src/gateway/protos/nemo.proto``. The service exposes a single
RPC: ``Verify(VerifyRequest) -> VerifyResponse``.

It is run as an independent OS process — either in its own container or as a
sidecar pod — and must be started explicitly (e.g. ``python -m
src.gateway.governance.nemo.server``).

RELATIONSHIP TO THE IN-PROCESS SINGLETON (manager.py)
-------------------------------------------------------
The LangGraph graph nodes that enforce NeMo Guardrails at the edges of the
inference pipeline are:

  - ``nemo_guardrail_node``  (entry rail — validates user input)
  - ``nemo_output_rail_node`` (exit rail  — validates / masks LLM output)

**Both nodes call NeMo Guardrails in-process** via functions exported from
``src/gateway/governance/nemo/manager.py``:

  - ``validate_with_nemo(user_input, rails)``
  - ``verify_input(rails, text)``
  - ``verify_and_mask_output(rails, text)``

The ``LLMRails`` instance those functions operate on is created by
``create_nemo_manager()`` (also in ``manager.py``) and held in memory within
the same Python process as the graph runner.  **Graph nodes do NOT contact
this gRPC sidecar at runtime.**

THE IN-PROCESS PATH IS AUTHORITATIVE FOR PRODUCTION
----------------------------------------------------
Three properties make the in-process path the correct one for graph nodes:

1. **No network hop** — NeMo executes in the same process as the graph,
   avoiding 10-100 ms+ of added latency on every request.

2. **No network availability dependency** — a NeMo failure raises a Python
   exception inside the graph node, which is caught and converted to
   ``guardrail_blocked=True`` (fail-closed).  There is no gRPC connection
   error that could silently fail-open.

3. **Simpler deployment** — the LangGraph host does not need to reach any
   sidecar endpoint; the graph functions correctly whether or not this sidecar
   process is running.

WHAT THIS SIDECAR IS USED FOR
------------------------------
The gRPC sidecar is intended for **external callers** — services, CLI tools,
audit harnesses, or integration tests — that need to invoke NeMo Guardrails
validation outside the LangGraph process boundary.  Examples include:

  - Standalone compliance-bridge validations that run independently of the
    graph (e.g., ``src/compliance_bridge/``).
  - Red-team / adversarial test harnesses (``tests/red_team/``) that exercise
    the NeMo pipeline without spinning up the full graph.
  - Future external microservices that want to reuse the same Colang rail
    configuration over the network.

The sidecar itself calls ``create_nemo_manager()`` to build its own
``LLMRails`` instance — it does **not** share the in-process singleton held by
the graph runner.  Both code paths ultimately use the same config directory
(``config/rails``), vLLM client (``vllm_client.py``), and action registry
(``nemo_action_registry.py``).

WARNING FOR CONTRIBUTORS
--------------------------
**Do NOT route LangGraph graph nodes through this gRPC sidecar.**

The graph entry node (``nemo_guardrail_node``) and exit node
(``nemo_output_rail_node``) must always call ``manager.py`` functions
directly.  Introducing a ``grpc.Channel`` call into the graph's critical path
would:

  - Add network latency on every request (10-100 ms+ per rail check)
  - Create a hard network availability dependency for every inference request
  - Risk fail-open behavior on gRPC connection errors (``UNAVAILABLE``,
    ``DEADLINE_EXCEEDED``) unless defensive logic is added in every caller
  - Reduce audit-trail determinism (network timeouts vs. in-process exceptions
    produce different trace shapes in Langfuse / OTel)

See ``plans/nemo_guardrails_architectural_analysis.md`` for the full
architectural rationale and decision record.
See ``src/gateway/governance/nemo/README.md`` for an architecture diagram.
"""

import asyncio
import logging
import os

# Adjust path so we can import from src if running as script
import sys
from concurrent import futures

import grpc

sys.path.append(".")

from src.gateway.governance.nemo.manager import create_nemo_manager
from src.gateway.protos import nemo_pb2, nemo_pb2_grpc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NeMoSidecar")

# Load Rails Config
# Config is located in config/rails relative to project root (from src/gateway/governance/nemo)
RAILS_CONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../../config/rails")
)


class NeMoService(nemo_pb2_grpc.NeMoGuardrailsServicer):
    def __init__(self):  # type: ignore[no-untyped-def]
        self.rails = None
        self._load_rails()

    def _load_rails(self):  # type: ignore[no-untyped-def]
        try:
            # Use create_nemo_manager to ensure actions and LLM providers are registered
            if os.path.exists(RAILS_CONFIG_PATH):
                self.rails = create_nemo_manager(RAILS_CONFIG_PATH)
                logger.info(f"✅ NeMo Guardrails loaded from {RAILS_CONFIG_PATH}")
            else:
                logger.warning(f"⚠️ Rails config not found at {RAILS_CONFIG_PATH}")
                # Fallback? No.
        except Exception as e:
            logger.error(f"❌ Failed to load NeMo Guardrails: {e}")
            self.rails = None

    async def Verify(self, request, context):  # type: ignore[no-untyped-def]
        if not self.rails:
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details("NeMo Rails not initialized")
            return nemo_pb2.VerifyResponse(status="ERROR")  # type: ignore[attr-defined]

        try:
            # Generate response using NeMo (Colang flows)
            messages = [{"role": "user", "content": request.input}]

            response = await self.rails.generate_async(messages=messages)

            content = response.response[0]["content"] if response.response else ""

            return nemo_pb2.VerifyResponse(response=content, status="SUCCESS")  # type: ignore[attr-defined]

        except Exception as e:
            logger.error(f"Guardrail execution failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return nemo_pb2.VerifyResponse(status="ERROR")  # type: ignore[attr-defined]


async def serve():  # type: ignore[no-untyped-def]
    port = os.getenv("PORT", "8000")
    # For gRPC we often use a different port or share if using multiplexing (harder in python)
    # Let's assume standard gRPC port 50052 for NeMo internal to avoid conflict with HTTP legacy if any?
    # But manifest says 8000. Let's switch NeMo to 50052 in manifest, or reuse 8000 for gRPC.
    # Reusing 8000 for gRPC is fine if we update Client.

    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    nemo_pb2_grpc.add_NeMoGuardrailsServicer_to_server(NeMoService(), server)

    server.add_insecure_port(f"[::]:{port}")
    logger.info(f"🚀 NeMo Guardrails gRPC Server starting on port {port}...")

    await server.start()
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(serve())
