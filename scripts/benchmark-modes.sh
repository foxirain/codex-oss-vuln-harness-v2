#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  benchmark-modes.sh CORPUS_JSON [options]

Runs oss_harness benchmark-modes and optionally saves the JSON result.

Options:
  --output PATH   Write benchmark JSON output to this file.
  -h, --help      Show help.

Examples:
  benchmark-modes.sh configs/benchmark/ot0-diverse-template.json
  benchmark-modes.sh configs/benchmark/ot0-diverse-template.json --output /tmp/benchmark.json
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

CORPUS=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      exit 1
      ;;
    *)
      if [[ -z "$CORPUS" ]]; then
        CORPUS="$1"
        shift
      else
        printf 'unexpected argument: %s\n' "$1" >&2
        exit 1
      fi
      ;;
  esac
done

HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HARNESS_ROOT"

if [[ -n "$OUTPUT" ]]; then
  python3 -m oss_harness benchmark-modes "$CORPUS" | tee "$OUTPUT"
else
  python3 -m oss_harness benchmark-modes "$CORPUS"
fi
