#!/usr/bin/env bash
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

# Local Development Launch Script: LangGraph SDK Hot-Reload Posture
#
# Prerequisites:
#   1. Docker and Docker Compose installed
#   2. Host Ollama running at http://localhost:11434 with qwen2.5:3b pre-pulled
#   3. config/environments/local-dev.env exists (auto-created from .example if missing)
#
# Usage:
#   bash scripts/dev_local.sh              # Start with in-memory checkpointer
#   bash scripts/dev_local.sh --with-redis # Start with Redis checkpointer

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored message
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verify Docker is installed and running
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop"
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running. Start Docker Desktop and try again."
    exit 1
fi

# Ensure host Ollama is running outside the container
log_info "Ensuring host Ollama is running outside container (http://localhost:11434)..."
if ! curl -s http://localhost:11434/api/tags &> /dev/null; then
    log_warn "Ollama is not responding at http://localhost:11434. Deploying host service..."
    if ! command -v ollama &> /dev/null; then
        log_warn "Ollama binary not found on host. Attempting automatic host installation..."
        if curl -fsSL https://ollama.com/install.sh | sh; then
            log_info "Ollama installed on host."
        else
            log_error "Failed to install Ollama automatically. Install manually from https://ollama.ai"
            exit 1
        fi
    fi

    # Start Ollama directly on the host (outside container)
    if command -v systemctl &> /dev/null && systemctl list-unit-files ollama.service &> /dev/null; then
        log_info "Starting Ollama systemd service on host..."
        sudo systemctl start ollama 2>/dev/null || systemctl --user start ollama 2>/dev/null || true
    fi

    if ! curl -s http://localhost:11434/api/tags &> /dev/null; then
        log_info "Starting Ollama host daemon via background process..."
        nohup ollama serve > /tmp/ollama_host.log 2>&1 &
    fi

    # Await readiness
    OLLAMA_RETRIES=15
    while ! curl -s http://localhost:11434/api/tags &> /dev/null; do
        OLLAMA_RETRIES=$((OLLAMA_RETRIES - 1))
        if [[ $OLLAMA_RETRIES -le 0 ]]; then
            log_error "Host Ollama failed to start at http://localhost:11434 within timeout."
            exit 1
        fi
        sleep 1
    done
fi

log_info "Host Ollama is active and listening at http://localhost:11434 (external to containers)."

# Verify target model is present on the host
if ! curl -s http://localhost:11434/api/tags | grep -q "qwen2.5:3b"; then
    log_warn "Model qwen2.5:3b not found in host Ollama. Pulling now (this may take a few minutes)..."
    if ! ollama pull qwen2.5:3b; then
        log_error "Failed to pull qwen2.5:3b on host. Run manually: ollama pull qwen2.5:3b"
        exit 1
    fi
    log_info "Model qwen2.5:3b ready on host."
fi

# Auto-create local-dev.env from .example if missing
LOCAL_ENV_PATH="config/environments/local-dev.env"
LOCAL_ENV_EXAMPLE="config/environments/local-dev.env.example"

if [[ ! -f "$LOCAL_ENV_PATH" ]]; then
    if [[ -f "$LOCAL_ENV_EXAMPLE" ]]; then
        log_warn "local-dev.env not found. Creating from $LOCAL_ENV_EXAMPLE..."
        cp "$LOCAL_ENV_EXAMPLE" "$LOCAL_ENV_PATH"
        log_info "Created $LOCAL_ENV_PATH. Review and customize as needed."
    else
        log_error "$LOCAL_ENV_EXAMPLE not found. Cannot auto-create $LOCAL_ENV_PATH."
        exit 1
    fi
fi

# Determine Docker Compose profile
COMPOSE_ARGS="-f docker-compose.yml -f docker-compose.local-dev.yml"
if [[ "${1:-}" == "--with-redis" ]]; then
    log_info "Starting with Redis checkpointer (--profile with-redis)..."
    COMPOSE_ARGS="$COMPOSE_ARGS --profile with-redis"
else
    log_info "Starting with in-memory checkpointer (default)..."
fi

# Launch the stack
log_info "Launching LangGraph SDK local development stack..."
log_info "  Graph Engine: http://localhost:2024"
log_info "  Gateway: http://localhost:8080"
log_info "  OPA: http://localhost:8181"
log_info ""
log_info "Press Ctrl+C to stop all services."

# shellcheck disable=SC2086
docker compose $COMPOSE_ARGS up --build
