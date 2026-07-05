# Third-Party Notices

This file lists the third-party open-source software incorporated into the
Cybernetic Agent Governance Engine (CAGE). It exists to satisfy the attribution
requirements of the licenses under which those packages are distributed and to
give operators a single place to audit the project's dependency obligations.

Entries are grouped by runtime context and listed alphabetically within each
section. Versions shown reflect the ranges declared in `pyproject.toml` or
`package.json`; exact pinned versions are in `uv.lock` / `package-lock.json`.

Last reviewed: 2026-07-02

---

## Python Runtime Dependencies

Packages used by one or more of the Python services (`src/gateway`,
`src/governed_financial_advisor`, `src/compliance_bridge`,
`src/gateway/slm`). Declared in `pyproject.toml`.

### aiohttp ≥3.9
- **License:** Apache-2.0 AND MIT
- **Homepage:** https://github.com/aio-libs/aiohttp
- **Usage:** Async HTTP client used by LangChain community integrations and NeMo Guardrails.

### anyio ≥4.0
- **License:** MIT
- **Homepage:** https://anyio.readthedocs.io/en/stable/
- **Usage:** Async concurrency abstraction layer used by FastAPI and httpx.

### boto3 ≥1.35
- **License:** Apache-2.0
- **Homepage:** https://github.com/boto/boto3
- **Usage:** AWS SDK used as an S3-compatible storage fallback (activated via `STORAGE_BACKEND=s3`).

### cachetools ≥5.5
- **License:** MIT
- **Homepage:** https://github.com/tkem/cachetools/
- **Usage:** In-process TTL and LRU caches for token-quota and query-cache layers.

### certifi
- **License:** MPL-2.0
- **Homepage:** https://github.com/certifi/python-certifi
- **Usage:** Mozilla CA bundle used by requests and httpx for TLS verification.

### click ≥8.0
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/pallets/click/
- **Usage:** CLI framework used transitively by uvicorn and typer.

### cryptography ≥48.0
- **License:** Apache-2.0 OR BSD-3-Clause
- **Homepage:** https://github.com/pyca/cryptography
- **Usage:** KMS signing, CMEK guard, and JWT verification across gateway and compliance-bridge.

### dataclasses-json ≥0.6
- **License:** MIT
- **Homepage:** https://github.com/lidatong/dataclasses-json
- **Usage:** JSON serialisation for LangChain message types.

### dowhy ≥0.12
- **License:** MIT
- **Homepage:** https://github.com/py-why/dowhy
- **Usage:** Causal inference library used by the Tier-6 causal gatekeeper in the compliance-bridge defer queue.

### en-core-web-sm 3.8.0
- **License:** MIT
- **Homepage:** https://spacy.io/models/en
- **Usage:** spaCy English NLP model used by the PII sanitiser for named-entity recognition.

### fastapi ≥0.110
- **License:** MIT
- **Homepage:** https://github.com/fastapi/fastapi
- **Usage:** ASGI web framework serving the gateway, compliance-bridge, and NeMo Guardrails HTTP APIs.

### flask ≥3.0
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/pallets/flask
- **Usage:** Lightweight HTTP server for the SLM similarity-scoring sidecar (`src/gateway/slm`).

### frozenlist ≥1.4
- **License:** Apache-2.0
- **Homepage:** https://github.com/aio-libs/frozenlist
- **Usage:** Immutable list type used by aiohttp internals.

### google-cloud-storage ≥2.0
- **License:** Apache-2.0
- **Homepage:** https://github.com/googleapis/python-storage
- **Usage:** Native GCS SDK for evidence-stream and OSCAL artefact storage in GCP/GKE deployments (ADC / Workload Identity).

### googleapis-common-protos ≥1.72
- **License:** Apache-2.0
- **Homepage:** https://github.com/googleapis/google-cloud-python/tree/main/packages/googleapis-common-protos
- **Usage:** Shared Google API protobuf definitions used by gRPC and OpenTelemetry exporters.

### grpcio ≥1.78
- **License:** Apache-2.0
- **Homepage:** https://grpc.io
- **Usage:** gRPC runtime for the NeMo Guardrails bidirectional streaming interface.

### httpx ≥0.27
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/encode/httpx
- **Usage:** Async HTTP client used by the gateway inference proxy, compliance-bridge, and LangChain adapters.

### httpx-sse ≥0.4
- **License:** MIT
- **Homepage:** https://github.com/florimondmanca/httpx-sse
- **Usage:** Server-Sent Events client used by the governed financial advisor to stream gateway responses.

### huggingface-hub ≥1.4
- **License:** Apache-2.0
- **Homepage:** https://github.com/huggingface/huggingface_hub
- **Usage:** Model-card and weight download utilities used by fastembed and sentence-transformers.

### Jinja2 ≥3.1
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/pallets/jinja/
- **Usage:** Template engine used by NeMo Guardrails for Colang prompt rendering.

### jsonpatch ≥1.33
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/stefankoegl/python-json-patch
- **Usage:** JSON Patch operations used by LangChain state merging.

### jsonschema ≥4.20
- **License:** MIT
- **Homepage:** https://github.com/python-jsonschema/jsonschema
- **Usage:** JSON Schema validation used by the MCP tool server and OSCAL parser.

### langchain ≥1.3.9
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langchain
- **Usage:** Core LLM orchestration framework for the governed financial advisor agent graph.

### langchain-core ≥1.1
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langchain
- **Usage:** Base abstractions (runnables, messages, tools) shared across all LangChain packages.

### langchain-mcp-adapters ≥0.2
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langchain-mcp-adapters
- **Usage:** Bridges MCP tool servers into LangChain tool-calling format.

### langchain-openai ≥0.1
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langchain
- **Usage:** LangChain integration for OpenAI-compatible LLM endpoints (including vLLM).

### langchain-text-splitters ≥1.1
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langchain
- **Usage:** Text chunking utilities used by document ingestion in the advisor pipeline.

### langgraph ≥1.1
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langgraph
- **Usage:** Graph-based agent orchestration framework for the multi-agent financial advisor workflow.

### langgraph-checkpoint ≥4.0
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint
- **Usage:** Checkpoint persistence interface for LangGraph state snapshots.

### langgraph-checkpoint-redis ≥0.3
- **License:** MIT
- **Homepage:** https://github.com/redis-developer/langgraph-redis
- **Usage:** Redis-backed LangGraph checkpoint store for durable agent state across restarts.

### langgraph-prebuilt ≥1.0
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langgraph/tree/main/libs/prebuilt
- **Usage:** Pre-built LangGraph node types (ReAct agent, tool node) used by advisor subgraphs.

### langgraph-sdk ≥0.3
- **License:** MIT
- **Homepage:** https://github.com/langchain-ai/langgraph/tree/main/libs/sdk-py
- **Usage:** Python client SDK for interacting with the LangGraph server API.

### langfuse ≥2.0
- **License:** MIT
- **Homepage:** https://langfuse.com
- **Usage:** LLM observability platform used for trace collection, prompt management, and evaluation datasets.

### langsmith ≥0.7
- **License:** MIT
- **Homepage:** https://smith.langchain.com/
- **Usage:** LangChain tracing and evaluation backend; used transitively by langchain-core.

### litellm ≥1.0
- **License:** MIT
- **Homepage:** https://litellm.ai
- **Usage:** Unified LLM proxy client providing a single interface to OpenAI, Vertex AI, and other providers.

### loguru ≥0.7
- **License:** MIT
- **Homepage:** https://github.com/Delgan/loguru
- **Usage:** Structured logging library used by NeMo Guardrails and the SLM sidecar.

### lark ≥1.3
- **License:** MIT
- **Homepage:** https://github.com/lark-parser/lark
- **Usage:** Parser toolkit used by NeMo Guardrails to parse Colang rail definitions.

### mcp ≥0.9
- **License:** MIT
- **Homepage:** https://modelcontextprotocol.io
- **Usage:** Model Context Protocol SDK used by the gateway MCP tool server and infrastructure MCP server.

### nemoguardrails ≥0.20,<1.0
- **License:** Apache-2.0
- **Homepage:** https://github.com/NVIDIA/NeMo-Guardrails
- **Usage:** NVIDIA NeMo Guardrails runtime for Colang-based rail enforcement in the gateway.

### nest-asyncio ≥1.6
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/erdewit/nest_asyncio
- **Usage:** Allows nested asyncio event loops; required by LangGraph in Jupyter-style environments.

### networkx
- **License:** BSD-3-Clause
- **Homepage:** https://networkx.org
- **Usage:** Graph data structures used by the STPA compiler and causal gatekeeper dependency analysis.

### numpy ≥1.26
- **License:** BSD-3-Clause
- **Homepage:** https://numpy.org
- **Usage:** Numerical array operations used by scikit-learn, scipy, and the SLM similarity scorer.

### openai ≥1.0
- **License:** Apache-2.0
- **Homepage:** https://github.com/openai/openai-python
- **Usage:** OpenAI Python client used by the gateway inference proxy and LangChain-OpenAI integration.

### opentelemetry-api ≥1.38
- **License:** Apache-2.0
- **Homepage:** https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api
- **Usage:** OpenTelemetry instrumentation API used across all services for distributed tracing.

### opentelemetry-exporter-gcp-trace
- **License:** Apache-2.0
- **Homepage:** https://github.com/GoogleCloudPlatform/opentelemetry-operations-python
- **Usage:** Exports OpenTelemetry traces to Google Cloud Trace in GKE deployments.

### opentelemetry-exporter-otlp ≥1.38
- **License:** Apache-2.0
- **Homepage:** https://github.com/open-telemetry/opentelemetry-python/tree/main/exporter/opentelemetry-exporter-otlp
- **Usage:** OTLP trace exporter used to send spans to Langfuse's native OTLP endpoint.

### opentelemetry-instrumentation-fastapi ≥0.58b0
- **License:** Apache-2.0
- **Homepage:** https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation/opentelemetry-instrumentation-fastapi
- **Usage:** Auto-instruments FastAPI request/response spans in the gateway and compliance-bridge.

### opentelemetry-instrumentation-langchain ≥0.52
- **License:** Apache-2.0
- **Homepage:** https://github.com/traceloop/openllmetry/tree/main/packages/opentelemetry-instrumentation-langchain
- **Usage:** Auto-instruments LangChain LLM calls with OpenTelemetry spans.

### opentelemetry-instrumentation-requests ≥0.58b0
- **License:** Apache-2.0
- **Homepage:** https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation/opentelemetry-instrumentation-requests
- **Usage:** Auto-instruments outbound HTTP requests made via the `requests` library.

### opentelemetry-sdk ≥1.38
- **License:** Apache-2.0
- **Homepage:** https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-sdk
- **Usage:** OpenTelemetry SDK providing tracer providers, span processors, and exporters.

### opentelemetry-semantic-conventions-ai ≥0.4
- **License:** Apache-2.0
- **Homepage:** https://github.com/traceloop/openllmetry/tree/main/packages/opentelemetry-semantic-conventions-ai
- **Usage:** AI-specific OpenTelemetry semantic conventions for LLM span attributes.

### orjson ≥3.9
- **License:** Apache-2.0 OR MIT
- **Homepage:** https://github.com/ijl/orjson
- **Usage:** High-performance JSON serialisation used by FastAPI response encoding.

### pandas ≥2.2
- **License:** BSD-3-Clause
- **Homepage:** https://pandas.pydata.org
- **Usage:** DataFrame operations used by the data-analyst agent and evaluation trace analysis.

### phonenumbers ≥9.0
- **License:** Apache-2.0
- **Homepage:** https://github.com/daviddrysdale/python-phonenumbers
- **Usage:** Phone number parsing used by the Presidio PII analyser for phone-number entity detection.

### pillow ≥11.0
- **License:** MIT-CMU
- **Homepage:** https://python-pillow.github.io
- **Usage:** Image processing library used transitively by fastembed and ONNX Runtime.

### presidio-analyzer ≥2.2.361
- **License:** MIT
- **Homepage:** https://github.com/Microsoft/presidio
- **Usage:** PII detection engine used by the gateway PII sanitiser to identify sensitive entities.

### presidio-anonymizer ≥2.2.361
- **License:** MIT
- **Homepage:** https://github.com/Microsoft/presidio
- **Usage:** PII anonymisation engine used by the gateway PII sanitiser to redact detected entities.

### protobuf ≥5.26,<7.0
- **License:** BSD-3-Clause
- **Homepage:** https://developers.google.com/protocol-buffers/
- **Usage:** Protocol Buffers runtime for the gateway/NeMo gRPC interface and OTLP serialisation.

### pydantic ≥2.10
- **License:** MIT
- **Homepage:** https://github.com/pydantic/pydantic
- **Usage:** Data validation and settings management used throughout all Python services.

### pydantic-settings ≥2.0
- **License:** MIT
- **Homepage:** https://github.com/pydantic/pydantic-settings
- **Usage:** Environment-variable-based configuration management for all services.

### PyJWT ≥2.0
- **License:** MIT
- **Homepage:** https://github.com/jpadilla/pyjwt
- **Usage:** JWT encoding and verification used by the compliance-bridge authentication layer.

### python-dotenv ≥1.0
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/theskumar/python-dotenv
- **Usage:** Loads `.env` files into environment variables for local development.

### python-json-logger ≥2.0
- **License:** BSD-3-Clause
- **Homepage:** https://nhairs.github.io/python-json-logger
- **Usage:** Structured JSON log formatter used across all Python services.

### python-multipart ≥0.0.20
- **License:** Apache-2.0
- **Homepage:** https://github.com/Kludex/python-multipart
- **Usage:** Multipart form-data parsing used by FastAPI file upload endpoints.

### python-ulid ≥3.0
- **License:** MIT
- **Homepage:** https://github.com/mdomke/python-ulid
- **Usage:** ULID generation for audit event and provenance chain identifiers.

### PyYAML ≥6.0
- **License:** MIT
- **Homepage:** https://pyyaml.org/
- **Usage:** YAML parsing for OSCAL documents, Lula validation files, and NeMo Guardrails config.

### redis ≥5.0
- **License:** MIT
- **Homepage:** https://github.com/redis/redis-py
- **Usage:** Redis client used for token-quota state, defer queue, and LangGraph checkpoint storage.

### redisvl ≥0.14
- **License:** MIT
- **Homepage:** https://github.com/redis/redis-vl-python
- **Usage:** Redis Vector Library used for semantic search in the query cache layer.

### regex ≥2026.1
- **License:** Apache-2.0
- **Homepage:** https://github.com/mrabarnett/mrab-regex
- **Usage:** Extended regular expression library used by tiktoken and NeMo Guardrails.

### requests ≥2.32
- **License:** Apache-2.0
- **Homepage:** https://requests.readthedocs.io
- **Usage:** Synchronous HTTP client used by yfinance and some LangChain community tools.

### scikit-learn ≥1.4
- **License:** BSD-3-Clause
- **Homepage:** https://scikit-learn.org
- **Usage:** Machine learning utilities used by the confabulation scorer and evaluation pipeline.

### sentence-transformers ≥3.0
- **License:** Apache-2.0
- **Homepage:** https://www.sbert.net
- **Usage:** Sentence embedding models used by the SLM sidecar for semantic similarity scoring (Tier-2 symbolic governor).

### simpleeval ≥1.0
- **License:** MIT
- **Homepage:** https://github.com/danthedeckie/simpleeval
- **Usage:** Safe expression evaluator used by NeMo Guardrails for Colang condition evaluation.

### sniffio ≥1.3
- **License:** MIT AND Apache-2.0
- **Homepage:** https://github.com/python-trio/sniffio
- **Usage:** Async library detection used by anyio.

### spacy ≥3.8
- **License:** MIT
- **Homepage:** https://spacy.io
- **Usage:** NLP pipeline used by the gateway PII sanitiser for named-entity recognition.

### SQLAlchemy ≥2.0
- **License:** MIT
- **Homepage:** https://www.sqlalchemy.org
- **Usage:** ORM used by LangGraph checkpoint backends and NeMo Guardrails conversation history.

### sse-starlette ≥1.0
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/sysid/sse-starlette
- **Usage:** Server-Sent Events support for the compliance-bridge evidence stream and gateway streaming endpoints.

### starlette ≥0.37
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/encode/starlette
- **Usage:** ASGI toolkit underlying FastAPI; used directly for middleware and routing.

### tenacity ≥9.0
- **License:** Apache-2.0
- **Homepage:** https://github.com/jd/tenacity
- **Usage:** Retry logic with exponential back-off used by LangChain LLM calls and gateway HTTP clients.

### tiktoken ≥0.12
- **License:** MIT
- **Homepage:** https://github.com/openai/tiktoken
- **Usage:** OpenAI BPE tokeniser used for token counting in the token-quota proxy.

### tqdm ≥4.66
- **License:** MPL-2.0 AND MIT
- **Homepage:** https://tqdm.github.io
- **Usage:** Progress bars used by huggingface-hub and fastembed during model downloads.

### typer ≥0.21
- **License:** MIT
- **Homepage:** https://github.com/fastapi/typer
- **Usage:** CLI framework used by NeMo Guardrails command-line tooling.

### typing-extensions ≥4.12
- **License:** PSF-2.0
- **Homepage:** https://github.com/python/typing_extensions
- **Usage:** Backports of newer Python typing constructs used across all packages.

### urllib3 ≥2.2
- **License:** MIT
- **Homepage:** https://github.com/urllib3/urllib3
- **Usage:** HTTP connection pooling used by requests and boto3.

### uvicorn ≥0.29
- **License:** BSD-3-Clause
- **Homepage:** https://uvicorn.dev/
- **Usage:** ASGI server used to run FastAPI applications in all Python services.

### uvloop ≥0.21
- **License:** MIT AND Apache-2.0
- **Homepage:** https://github.com/MagicStack/uvloop
- **Usage:** High-performance asyncio event loop used by uvicorn in the compliance-bridge container.

### websockets ≥13.0
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/python-websockets/websockets
- **Usage:** WebSocket support used by uvicorn and the MCP server transport layer.

### yfinance ≥0.2
- **License:** Apache-2.0
- **Homepage:** https://github.com/ranaroussi/yfinance
- **Usage:** Yahoo Finance market data client used by the data-analyst agent's market data tool.

---

## JavaScript / TypeScript Dependencies

Packages from [`src/agentsight-ui/package.json`](src/agentsight-ui/package.json).

### ai ^4.0 (Vercel AI SDK)
- **License:** Apache-2.0
- **Homepage:** https://sdk.vercel.ai
- **Usage:** Streaming AI response utilities used by the AgentSight UI to consume gateway SSE streams.

### react ^19.2
- **License:** MIT
- **Homepage:** https://react.dev
- **Usage:** UI component library for the AgentSight monitoring dashboard.

### react-dom ^19.2
- **License:** MIT
- **Homepage:** https://react.dev
- **Usage:** React DOM renderer for mounting the AgentSight UI into the browser.

### zod ^4.3
- **License:** MIT
- **Homepage:** https://zod.dev
- **Usage:** TypeScript-first schema validation used for governance contract types in the UI.

---

## Tooling & Build-time Dependencies

Packages used only during development, testing, linting, or container image
builds. Not present in production runtime images.

### @vitejs/plugin-react ^5.1 (devDependency)
- **License:** MIT
- **Homepage:** https://github.com/vitejs/vite-plugin-react
- **Usage:** Vite plugin providing React Fast Refresh and JSX transform for the AgentSight UI build.

### bcrypt ≥5.0 (dev)
- **License:** Apache-2.0
- **Homepage:** https://github.com/pyca/bcrypt
- **Usage:** Password hashing library used in authentication integration tests.

### codespell ≥2.2 (lint)
- **License:** GPL-2.0-only
- **Homepage:** https://github.com/codespell-project/codespell
- **Usage:** Spell-checker run in CI to catch typos in source files and documentation.

### eslint ^9.39 (devDependency)
- **License:** MIT
- **Homepage:** https://eslint.org
- **Usage:** JavaScript/TypeScript linter for the AgentSight UI source.

### fakeredis ≥2.35 (dev)
- **License:** BSD-3-Clause
- **Homepage:** https://github.com/cunla/fakeredis-py
- **Usage:** In-process Redis mock used in unit and integration tests to avoid a live Redis dependency.

### grpcio-tools (build-time)
- **License:** Apache-2.0
- **Homepage:** https://grpc.io
- **Usage:** Protobuf/gRPC code generator used in `Dockerfile.nemo` to compile `nemo.proto` into Python stubs.

### kfp ≥2.0,<3.0 (dev)
- **License:** Apache-2.0
- **Homepage:** https://github.com/kubeflow/pipelines
- **Usage:** Kubeflow Pipelines SDK used in pipeline compilation tests.

### mypy ≥1.15 (lint)
- **License:** MIT
- **Homepage:** https://mypy-lang.org
- **Usage:** Static type checker run in CI against all Python source files.

### pip-audit ≥2.10 (dev)
- **License:** Apache-2.0
- **Homepage:** https://github.com/pypa/pip-audit
- **Usage:** Vulnerability scanner for Python dependencies run in CI.

### pip-licenses ≥5.0 (dev)
- **License:** MIT
- **Homepage:** https://github.com/raimon49/pip-licenses
- **Usage:** Generates the raw dependency/license table used as input for this file.

### pytest ≥8.3 (dev)
- **License:** MIT
- **Homepage:** https://docs.pytest.org/en/latest/
- **Usage:** Test framework for all Python unit and integration tests.

### pytest-asyncio ≥0.23 (dev)
- **License:** Apache-2.0
- **Homepage:** https://github.com/pytest-dev/pytest-asyncio
- **Usage:** pytest plugin enabling async test functions across the test suite.

### respx ≥0.22 (dev)
- **License:** BSD-3-Clause
- **Homepage:** https://lundberg.github.io/respx/
- **Usage:** httpx request mocking library used in gateway and compliance-bridge tests.

### ruff ≥0.4 (lint)
- **License:** MIT
- **Homepage:** https://docs.astral.sh/ruff/
- **Usage:** Fast Python linter and formatter run in CI (replaces flake8, isort, pyupgrade).

### ts-proto ^2.0 (devDependency)
- **License:** MIT
- **Homepage:** https://github.com/stephenh/ts-proto
- **Usage:** Generates TypeScript types from `.proto` files for the AgentSight UI gRPC/protobuf bindings.

### typescript ~5.9 (devDependency)
- **License:** Apache-2.0
- **Homepage:** https://www.typescriptlang.org
- **Usage:** TypeScript compiler for the AgentSight UI.

### vite ^7.3 (devDependency)
- **License:** MIT
- **Homepage:** https://vite.dev
- **Usage:** Frontend build tool and dev server for the AgentSight UI.

---

## Infrastructure & Container Images

Third-party container images and services referenced in `docker-compose.yml`
and project Dockerfiles.

### ghcr.io/astral-sh/uv (build-time base image)
- **License:** MIT AND Apache-2.0
- **Homepage:** https://github.com/astral-sh/uv
- **Usage:** Ultra-fast Python package manager copied into Python service Dockerfiles to manage venv installation.

### nginxinc/nginx-unprivileged:alpine (runtime base image)
- **License:** BSD-2-Clause
- **Homepage:** https://github.com/nginxinc/docker-nginx-unprivileged
- **Usage:** Non-root Nginx image used as the production web server for the AgentSight UI static build.

### node:18-alpine (build-time base image)
- **License:** MIT (Node.js) / various (Alpine Linux packages)
- **Homepage:** https://hub.docker.com/_/node
- **Usage:** Node.js build environment for compiling the AgentSight UI (`npm run build`).

### openpolicyagent/opa:latest-static (service)
- **License:** Apache-2.0
- **Homepage:** https://www.openpolicyagent.org
- **Usage:** Open Policy Agent policy engine enforcing Rego trade-governance rules at runtime.

### python:3.12-slim (runtime base image)
- **License:** PSF-2.0 / various (Debian packages)
- **Homepage:** https://hub.docker.com/_/python
- **Usage:** Base image for the gateway, compliance-bridge, SLM sidecar, and NeMo Guardrails containers.

### runai-model-streamer (vLLM image add-on)
- **License:** Apache-2.0
- **Homepage:** https://github.com/run-ai/runai-model-streamer
- **Usage:** RunAI model streamer enabling vLLM to load model weights directly from GCS without local disk staging.

### runai-model-streamer-gcs (vLLM image add-on)
- **License:** Apache-2.0
- **Homepage:** https://github.com/run-ai/runai-model-streamer
- **Usage:** GCS backend plugin for the RunAI model streamer; provides ADC/Workload Identity authentication.

### vllm/vllm-openai:latest (runtime base image)
- **License:** Apache-2.0
- **Homepage:** https://github.com/vllm-project/vllm
- **Usage:** Official vLLM OpenAI-compatible inference server image extended with the RunAI GCS streamer.

---

## How to Update This File

1. After adding or removing a Python dependency in `pyproject.toml`, run
   `uv sync` to update `uv.lock`, then update the relevant entry in the
   **Python Runtime Dependencies** section above.

2. After adding or removing a Node.js dependency in
   `src/agentsight-ui/package.json`, update the **JavaScript / TypeScript
   Dependencies** section.

3. After changing a Docker base image or adding a new service to
   `docker-compose.yml`, update the **Infrastructure & Container Images**
   section.

4. To regenerate a raw license table for cross-checking, run:
   ```
   uv run pip-licenses --format=markdown --with-urls --with-authors \
       --output-file /tmp/raw-licenses.md
   ```
   Then compare the output against this file and reconcile any differences.

5. Verify SPDX identifiers against https://spdx.org/licenses/ before
   committing. Do not use informal names such as "BSD License" or
   "Apache Software License" — use the canonical SPDX identifier (e.g.
   `BSD-3-Clause`, `Apache-2.0`).

6. Commit changes to this file in the same PR as the dependency change,
   using a `chore(docs): update third-party notices` commit message.
