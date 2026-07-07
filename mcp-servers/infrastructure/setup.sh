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
# Global setup script for CAGE Infrastructure MCP Server
# Configures for both Google Antigravity and Roo Code globally
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
RESET='\033[0m'

info()    { echo -e "${CYAN}ℹ️  $*${RESET}"; }
success() { echo -e "${GREEN}✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}⚠️  $*${RESET}"; }
error()   { echo -e "${RED}❌ $*${RESET}"; }

echo ""
info "Installing CAGE Infrastructure MCP Server (Global Configuration)"
echo ""

# Detect Python
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    error "Python 3 not found. Please install Python 3.11 or later."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
info "Using Python $PYTHON_VERSION"

# Get absolute path to Python executable
PYTHON_PATH=$(command -v $PYTHON_CMD)
info "Python executable: $PYTHON_PATH"

# Install the package
info "Installing MCP server package..."
cd "$SCRIPT_DIR"

# Check if we should use a virtual environment
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    info "Installing in active virtual environment: $VIRTUAL_ENV"
    pip install -e .
    PYTHON_PATH="$VIRTUAL_ENV/bin/python"
elif command -v uv &> /dev/null; then
    info "Installing with uv..."
    uv pip install -e .
else
    info "Installing with pip..."
    pip install -e .
fi

success "Package installed"

# Verify installation
info "Verifying installation..."
if $PYTHON_PATH -c "import mcp_servers.infrastructure" &> /dev/null; then
    success "MCP server module loads correctly"
else
    warn "Module import test failed, but continuing with setup"
fi

# Configure Google Antigravity
ANTIGRAVITY_DIR="$HOME/.gemini/antigravity"
ANTIGRAVITY_CONFIG="$ANTIGRAVITY_DIR/mcp_config.json"

info "Configuring Google Antigravity..."

mkdir -p "$ANTIGRAVITY_DIR"

# Create or update Antigravity config
if [[ -f "$ANTIGRAVITY_CONFIG" ]]; then
    info "Existing Antigravity config found, backing up..."
    cp "$ANTIGRAVITY_CONFIG" "$ANTIGRAVITY_CONFIG.backup"
    
    # Read existing config and add our server
    if command -v jq &> /dev/null; then
        # Use jq to merge configs if available
        TMP_CONFIG=$(mktemp)
        jq --arg python "$PYTHON_PATH" --arg project "$REPO_ROOT" \
           '.mcpServers["cage-infrastructure"] = {
              "command": $python,
              "args": ["-m", "mcp_servers.infrastructure"],
              "env": {"PROJECT_ROOT": $project}
            }' "$ANTIGRAVITY_CONFIG" > "$TMP_CONFIG"
        mv "$TMP_CONFIG" "$ANTIGRAVITY_CONFIG"
        success "Updated existing Antigravity config"
    else
        warn "jq not found - you'll need to manually add the server to $ANTIGRAVITY_CONFIG"
    fi
else
    # Create new config
    cat > "$ANTIGRAVITY_CONFIG" <<EOF
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "$PYTHON_PATH",
      "args": ["-m", "mcp_servers.infrastructure"],
      "env": {
        "PROJECT_ROOT": "$REPO_ROOT"
      }
    }
  }
}
EOF
    success "Created Antigravity config at $ANTIGRAVITY_CONFIG"
fi

# Configure Roo Code globally
info "Configuring Roo Code globally..."

# Determine correct paths based on OS
ROO_CONFIG_PATHS=()
if [[ "$OSTYPE" == "darwin"* ]]; then
    ROO_CONFIG_PATHS=(
        "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
        "$HOME/Library/Application Support/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"
        "$HOME/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    )
else
    ROO_CONFIG_PATHS=(
        "$HOME/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"
        "$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
    )
fi

# Write separate configs instead of symlinking to prevent schema validation errors
# with cloud-based MCP servers (like google-developer-knowledge) in Roo Code/Cline
for ROO_CONFIG in "${ROO_CONFIG_PATHS[@]}"; do
    ROO_DIR="$(dirname "$ROO_CONFIG")"
    mkdir -p "$ROO_DIR"
    
    # Remove symlink if it exists
    if [[ -L "$ROO_CONFIG" ]]; then
        rm "$ROO_CONFIG"
    fi
    
    if command -v jq &> /dev/null && [[ -f "$ANTIGRAVITY_CONFIG" ]]; then
        # Use jq to copy everything except google-developer-knowledge
        jq 'del(.mcpServers["google-developer-knowledge"])' "$ANTIGRAVITY_CONFIG" > "$ROO_CONFIG"
        success "Configured Roo/Cline at $ROO_CONFIG (filtered)"
    else
        # Fallback to a clean config with just the infrastructure server if jq not present
        cat > "$ROO_CONFIG" <<EOF
{
  "mcpServers": {
    "cage-infrastructure": {
      "command": "$PYTHON_PATH",
      "args": ["-m", "mcp_servers.infrastructure"],
      "env": {
        "PROJECT_ROOT": "$REPO_ROOT"
      }
    }
  }
}
EOF
        success "Configured Roo/Cline at $ROO_CONFIG (fallback)"
    fi
done

# Also set up project-local reference (optional)
info "Setting up project-local reference (optional)..."
mkdir -p "$REPO_ROOT/.roo"

if [[ ! -f "$REPO_ROOT/.roo/mcp.json" ]]; then
    if [[ -f "${ROO_CONFIG_PATHS[0]}" ]]; then
        cp "${ROO_CONFIG_PATHS[0]}" "$REPO_ROOT/.roo/mcp.json" 2>/dev/null || true
        info "Created project-local copy of Roo/Cline config (optional)"
    fi
fi

# Update .gitignore if needed
if ! grep -q "^.roo/mcp.json$" "$REPO_ROOT/.gitignore" 2>/dev/null; then
    cat >> "$REPO_ROOT/.gitignore" <<EOF

# MCP Server Configurations (symlinks to global configs)
.roo/mcp.json
EOF
    success "Updated .gitignore to exclude MCP configs"
fi

echo ""
success "Global installation complete!"
echo ""
info "Configuration Summary:"
echo "  • Python executable: $PYTHON_PATH"
echo "  • Project root: $REPO_ROOT"
echo "  • Antigravity config: $ANTIGRAVITY_CONFIG"
echo "  • Roo/Cline configs: Updated independently and filtered"
echo ""
info "Next steps:"
echo "  1. Restart VS Code (Cmd+R or Ctrl+R)"
echo "  2. The MCP server will be available in ALL projects"
echo "  3. Test by asking your agent:"
echo '     "List available infrastructure targets"'
echo ""
info "To verify configuration:"
echo "  cat $ANTIGRAVITY_CONFIG | jq .mcpServers.\"cage-infrastructure\""
echo ""
