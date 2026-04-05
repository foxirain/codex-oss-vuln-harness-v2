#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  quicksearch.sh REPO_PATH [options]

Runs:
  1. bootstrap
  2. scan
  3. autopilot

Options:
  --out DIR                 Output artifact root. Default: /tmp/oss-artifacts
  --duration SPEC           Autopilot total duration. Default: 2h
  --per-run-timeout SPEC    Autopilot per-run timeout. Default: 30m
  --model MODEL             Optional Codex model override
  --sandbox MODE            Codex sandbox mode. Default: workspace-write
  --no-include-snippet      Do not pass --include-snippet to autopilot
  --unsafe-bypass           Pass --dangerously-bypass-approvals-and-sandbox
  -h, --help                Show help

Examples:
  quicksearch.sh /work/grpc
  quicksearch.sh /work/grpc --out /tmp/grpc-artifacts --duration 4h
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

REPO_PATH=""
OUT_DIR="/tmp/oss-artifacts"
DURATION="2h"
PER_RUN_TIMEOUT="30m"
MODEL=""
SANDBOX="workspace-write"
INCLUDE_SNIPPET=1
UNSAFE_BYPASS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --per-run-timeout)
      PER_RUN_TIMEOUT="$2"
      shift 2
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --sandbox)
      SANDBOX="$2"
      shift 2
      ;;
    --no-include-snippet)
      INCLUDE_SNIPPET=0
      shift
      ;;
    --unsafe-bypass)
      UNSAFE_BYPASS=1
      shift
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      exit 1
      ;;
    *)
      if [[ -z "$REPO_PATH" ]]; then
        REPO_PATH="$1"
        shift
      else
        printf 'unexpected argument: %s\n' "$1" >&2
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$REPO_PATH" ]]; then
  printf 'missing repository path\n' >&2
  exit 1
fi

REPO_PATH="$(cd "$REPO_PATH" && pwd)"
HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TODAY_UTC="$(date -u +%F)"
POLICY_PATH="$REPO_PATH/.codex-harness.md"
SIGNALS_PATH="$REPO_PATH/external_signals_${TODAY_UTC}.json"

COMMON_ARGS=()
if [[ -n "$MODEL" ]]; then
  COMMON_ARGS+=(--model "$MODEL")
fi
COMMON_ARGS+=(--sandbox "$SANDBOX")
if [[ "$UNSAFE_BYPASS" -eq 1 ]]; then
  COMMON_ARGS+=(--dangerously-bypass-approvals-and-sandbox)
fi

printf '[1/3] bootstrap: %s\n' "$REPO_PATH"
cd "$HARNESS_ROOT"
python3 -m oss_harness bootstrap "$REPO_PATH" "${COMMON_ARGS[@]}"

printf '[2/3] scan\n'
SCAN_OUTPUT="$({
  python3 -m oss_harness scan "$REPO_PATH" \
    --policy "$POLICY_PATH" \
    --signals-json "$SIGNALS_PATH" \
    --out "$OUT_DIR"
})"
printf '%s\n' "$SCAN_OUTPUT"

SESSION_DIR="$(printf '%s\n' "$SCAN_OUTPUT" | awk -F= '/^session=/{print $2; exit}')"
if [[ -z "$SESSION_DIR" ]]; then
  printf 'failed to parse session path from scan output\n' >&2
  exit 1
fi

AUTOPILOT_ARGS=(
  "$SESSION_DIR"
  --duration "$DURATION"
  --per-run-timeout "$PER_RUN_TIMEOUT"
  "${COMMON_ARGS[@]}"
)
if [[ "$INCLUDE_SNIPPET" -eq 1 ]]; then
  AUTOPILOT_ARGS+=(--include-snippet)
fi

printf '[3/3] autopilot: %s\n' "$SESSION_DIR"
python3 -m oss_harness autopilot "${AUTOPILOT_ARGS[@]}"

printf '\nDone.\n'
printf 'policy=%s\n' "$POLICY_PATH"
printf 'signals=%s\n' "$SIGNALS_PATH"
printf 'session=%s\n' "$SESSION_DIR"
