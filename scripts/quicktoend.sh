#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  quicktoend.sh REPO_PATH --template TEMPLATE [options]

Runs:
  1. bootstrap
  2. scan
  3. autopilot
  4. review
  5. repro
  6. report

Options:
  --template VALUE         Report template path or free-form instruction. Required.
  --out DIR                Output artifact root. Default: /tmp/oss-artifacts
  --duration SPEC          Autopilot total duration. Default: 2h
  --per-run-timeout SPEC   Autopilot per-run timeout. Default: 30m
  --review-timeout SPEC    Review timeout per finding. Default: 20m
  --repro-timeout SPEC     Repro timeout per finding. Default: 45m
  --report-timeout SPEC    Report timeout per finding. Default: 20m
  --tier-min TIER          Minimum review tier for repro/report. Default: A
  --model MODEL            Optional Codex model override
  --sandbox MODE           Codex sandbox mode. Default: workspace-write
  --no-include-snippet     Do not pass --include-snippet to autopilot
  --unsafe-bypass          Pass --dangerously-bypass-approvals-and-sandbox
  -h, --help               Show help

Examples:
  quicktoend.sh /work/grpc --template "GitHub Security Advisory format"
  quicktoend.sh /work/grpc --template /work/templates/advisory.md --tier-min S
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

REPO_PATH=""
TEMPLATE=""
OUT_DIR="/tmp/oss-artifacts"
DURATION="2h"
PER_RUN_TIMEOUT="30m"
REVIEW_TIMEOUT="20m"
REPRO_TIMEOUT="45m"
REPORT_TIMEOUT="20m"
TIER_MIN="A"
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
    --template)
      TEMPLATE="$2"
      shift 2
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
    --review-timeout)
      REVIEW_TIMEOUT="$2"
      shift 2
      ;;
    --repro-timeout)
      REPRO_TIMEOUT="$2"
      shift 2
      ;;
    --report-timeout)
      REPORT_TIMEOUT="$2"
      shift 2
      ;;
    --tier-min)
      TIER_MIN="$2"
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
if [[ -z "$TEMPLATE" ]]; then
  printf 'missing required --template\n' >&2
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

printf '[1/6] bootstrap: %s\n' "$REPO_PATH"
cd "$HARNESS_ROOT"
python3 -m oss_harness bootstrap "$REPO_PATH" "${COMMON_ARGS[@]}"

printf '[2/6] scan\n'
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

printf '[3/6] autopilot: %s\n' "$SESSION_DIR"
python3 -m oss_harness autopilot "${AUTOPILOT_ARGS[@]}"

printf '[4/6] review\n'
python3 -m oss_harness review "$SESSION_DIR" \
  --timeout "$REVIEW_TIMEOUT" \
  "${COMMON_ARGS[@]}"

printf '[5/6] repro (tier >= %s)\n' "$TIER_MIN"
python3 -m oss_harness repro "$SESSION_DIR" \
  --tier-min "$TIER_MIN" \
  --timeout "$REPRO_TIMEOUT" \
  "${COMMON_ARGS[@]}"

printf '[6/6] report (tier >= %s)\n' "$TIER_MIN"
python3 -m oss_harness report "$SESSION_DIR" \
  --tier-min "$TIER_MIN" \
  --template "$TEMPLATE" \
  --timeout "$REPORT_TIMEOUT" \
  "${COMMON_ARGS[@]}"

printf '\nDone.\n'
printf 'policy=%s\n' "$POLICY_PATH"
printf 'signals=%s\n' "$SIGNALS_PATH"
printf 'session=%s\n' "$SESSION_DIR"
printf 'review_dir=%s\n' "$SESSION_DIR/review"
printf 'repro_dir=%s\n' "$SESSION_DIR/repro"
printf 'report_dir=%s\n' "$SESSION_DIR/reports"
