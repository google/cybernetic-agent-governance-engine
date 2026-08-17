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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Constants ──────────────────────────────────────────────────────────────────
PID_FILE="/tmp/cage-deploy.pid"
LOG_DIR="/tmp/cage-deploy-logs"
DEPLOY_SCRIPT="$REPO_ROOT/deploy_all.sh"
BUILD_SCRIPT="$REPO_ROOT/scripts/build_images.sh"

# ── Colour helpers ─────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}ℹ️  $*${RESET}"; }
success() { echo -e "${GREEN}✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}⚠️  $*${RESET}"; }
error()   { echo -e "${RED}❌ $*${RESET}" >&2; }

# ── Helpers ────────────────────────────────────────────────────────────────────

_latest_log() {
  # Return the most recently created log file, or empty string if none.
  ls -t "$LOG_DIR"/deploy-*.log 2>/dev/null | head -1 || true
}

_is_running() {
  local pid_file="$1"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid=$(cat "$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# ── Sub-commands ───────────────────────────────────────────────────────────────

cmd_status() {
  echo ""
  if _is_running "$PID_FILE"; then
    local pid
    pid=$(cat "$PID_FILE")
    success "Deployment is RUNNING (PID $pid)"
    local log
    log=$(_latest_log)
    if [[ -n "$log" ]]; then
      info "Log: $log"
      echo ""
      echo "Last 20 lines:"
      echo "──────────────────────────────────────────────────────────────────"
      tail -20 "$log"
      echo "──────────────────────────────────────────────────────────────────"
    fi
  else
    local log
    log=$(_latest_log)
    if [[ -n "$log" ]]; then
      # Check exit status embedded in log footer
      if grep -q "^EXIT_CODE=0" "$log" 2>/dev/null; then
        success "Last deployment SUCCEEDED"
      elif grep -q "^EXIT_CODE=" "$log" 2>/dev/null; then
        local code
        code=$(grep "^EXIT_CODE=" "$log" | tail -1 | cut -d= -f2)
        error "Last deployment FAILED (exit code $code)"
      else
        warn "No active deployment. Last log: $log"
      fi
      info "Log: $log"
    else
      warn "No deployment has been started yet."
    fi
  fi
  echo ""
}

cmd_logs() {
  local log
  log=$(_latest_log)
  if [[ -z "$log" ]]; then
    warn "No deployment logs found in $LOG_DIR"
    exit 0
  fi
  info "Tailing: $log  (Ctrl+C to stop)"
  echo ""
  tail -f "$log"
}

cmd_kill() {
  if _is_running "$PID_FILE"; then
    local pid
    pid=$(cat "$PID_FILE")
    warn "Sending SIGTERM to deployment process tree (PID $pid)..."
    # Kill the entire process group so child gcloud/terraform processes also stop.
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    warn "Deployment cancelled. Check GCP Console for any in-flight Cloud Build jobs."
  else
    info "No active deployment to cancel."
  fi
}

# ── Main launch logic ──────────────────────────────────────────────────────────

launch_background() {
  local cmd_args=("$@")
  local build_only=false

  # Detect --build-only before passing args to deploy_all.sh
  local filtered_args=()
  for arg in "${cmd_args[@]}"; do
    if [[ "$arg" == "--build-only" ]]; then
      build_only=true
    else
      filtered_args+=("$arg")
    fi
  done

  # Guard: refuse to start a second deployment if one is already running.
  if _is_running "$PID_FILE"; then
    local pid
    pid=$(cat "$PID_FILE")
    error "A deployment is already running (PID $pid)."
    info  "Run './scripts/deploy_bg.sh --status' to check progress."
    info  "Run './scripts/deploy_bg.sh --kill'   to cancel it first."
    exit 1
  fi

  # Validate the target script exists.
  if [[ "$build_only" == "true" ]]; then
    if [[ ! -f "$BUILD_SCRIPT" ]]; then
      error "Build script not found: $BUILD_SCRIPT"
      exit 1
    fi
  else
    if [[ ! -f "$DEPLOY_SCRIPT" ]]; then
      error "Deploy script not found: $DEPLOY_SCRIPT"
      exit 1
    fi
    # deploy_all.sh requires --target
    local has_target=false
    for arg in "${filtered_args[@]}"; do
      [[ "$arg" == "--target" ]] && has_target=true && break
    done
    if [[ "$has_target" == "false" ]]; then
      error "Missing required --target flag."
      echo ""
      echo "Usage: $0 --target <agnostic|gcp-gke> --env <dev|prod> [OPTIONS]"
      echo "       $0 --build-only"
      echo "       $0 --status"
      echo "       $0 --logs"
      echo "       $0 --kill"
      exit 1
    fi
  fi

  # Prepare log file.
  mkdir -p "$LOG_DIR"
  chmod 700 "$LOG_DIR"
  local timestamp
  timestamp=$(date +%Y%m%d-%H%M%S)
  local log_file="$LOG_DIR/deploy-${timestamp}.log"
  touch "$log_file" && chmod 600 "$log_file"

  # Write a header to the log so it's immediately identifiable.
  {
    echo "════════════════════════════════════════════════════════════════════"
    echo "  CAGE Background Deployment"
    echo "  Started : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if [[ "$build_only" == "true" ]]; then
      echo "  Mode    : build-only"
    else
      echo "  Args    : ${filtered_args[*]:-<none>}"
    fi
    echo "  Log     : $log_file"
    echo "════════════════════════════════════════════════════════════════════"
    echo ""
  } > "$log_file"

  # Build the command to run in the background.
  # We wrap it in a subshell that:
  #   1. Runs the actual deploy/build command.
  #   2. Appends EXIT_CODE=<n> to the log so --status can report success/failure.
  #   3. Removes the PID file when done.
  local inner_cmd
  if [[ "$build_only" == "true" ]]; then
    inner_cmd="bash '$BUILD_SCRIPT'"
  else
    # Pass all filtered args through, properly quoted.
    local quoted_args
    printf -v quoted_args '%q ' "${filtered_args[@]}"
    inner_cmd="bash '$DEPLOY_SCRIPT' $quoted_args"
  fi

  # Double-fork via nohup so the process is fully detached from this terminal.
  # setsid creates a new session (no controlling terminal), preventing SIGHUP.
  nohup bash -c "
    set +e
    cd '$REPO_ROOT'
    $inner_cmd
    _exit=\$?
    echo ''
    echo '════════════════════════════════════════════════════════════════════'
    echo \"  Finished : \$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"
    echo \"EXIT_CODE=\$_exit\"
    echo '════════════════════════════════════════════════════════════════════'
    rm -f '$PID_FILE'
    exit \$_exit
  " >> "$log_file" 2>&1 &

  local bg_pid=$!
  echo "$bg_pid" > "$PID_FILE"
  disown "$bg_pid"

  echo ""
  success "Deployment launched in background (PID $bg_pid)"
  info    "Log file : $log_file"
  echo ""
  echo -e "${BOLD}Monitor progress:${RESET}"
  echo "  ./scripts/deploy_bg.sh --status   # summary + last 20 lines"
  echo "  ./scripts/deploy_bg.sh --logs     # live tail"
  echo "  ./scripts/deploy_bg.sh --kill     # cancel"
  echo ""
  echo -e "${BOLD}Or via make:${RESET}"
  echo "  make deploy-status"
  echo "  make deploy-logs"
  echo ""
}

# ── Entry point ────────────────────────────────────────────────────────────────

main() {
  if [[ $# -eq 0 ]]; then
    error "No arguments provided."
    echo ""
    echo "Usage: $0 --target <agnostic|gcp-gke> --env <dev|prod> [OPTIONS]"
    echo "       $0 --build-only"
    echo "       $0 --status"
    echo "       $0 --logs"
    echo "       $0 --kill"
    exit 1
  fi

  case "$1" in
    --status)  cmd_status ;;
    --logs)    cmd_logs ;;
    --kill)    cmd_kill ;;
    *)         launch_background "$@" ;;
  esac
}

main "$@"
