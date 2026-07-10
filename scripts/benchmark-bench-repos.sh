#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  benchmark-bench-repos.sh [options]

Assumes benchmark repositories live in:
  ../bench-repos/<repo>
relative to this harness repository.

This script:
  1. builds a benchmark corpus JSON from the fixed bench-repos layout
  2. bootstraps each discovered repo when policy/signals are missing
  3. runs benchmark-modes

Options:
  --bench-root DIR        Bench repo root. Default: ../bench-repos
  --output PATH           Save benchmark JSON output here
  --skip-bootstrap        Do not run bootstrap automatically
  --refresh-bootstrap     Re-run bootstrap even if policy/signals already exist
  --model MODEL           Optional model override for bootstrap
  --sandbox MODE          Sandbox for bootstrap. Default: read-only
  --unsafe-bypass         Pass --dangerously-bypass-approvals-and-sandbox to bootstrap
  -h, --help              Show help

Examples:
  ./scripts/benchmark-bench-repos.sh
  ./scripts/benchmark-bench-repos.sh --output /tmp/benchmark.json --unsafe-bypass
USAGE
}

HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BENCH_ROOT="$(cd "$HARNESS_ROOT/.." && pwd)/bench-repos"
BENCH_ROOT="$DEFAULT_BENCH_ROOT"
OUTPUT=""
SKIP_BOOTSTRAP=0
REFRESH_BOOTSTRAP=0
MODEL=""
SANDBOX="read-only"
UNSAFE_BYPASS=0
TODAY_UTC="$(date -u +%F)"
CORPUS_PATH="/tmp/codex-oss-benchmark-bench-repos-${TODAY_UTC}.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bench-root)
      BENCH_ROOT="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --skip-bootstrap)
      SKIP_BOOTSTRAP=1
      shift
      ;;
    --refresh-bootstrap)
      REFRESH_BOOTSTRAP=1
      shift
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --sandbox)
      SANDBOX="$2"
      shift 2
      ;;
    --unsafe-bypass)
      UNSAFE_BYPASS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$(dirname "$CORPUS_PATH")"

python3 - "$BENCH_ROOT" "$TODAY_UTC" "$CORPUS_PATH" <<'PY'
import json
import sys
from pathlib import Path

bench_root = Path(sys.argv[1]).expanduser().resolve()
today = sys.argv[2]
out_path = Path(sys.argv[3]).expanduser().resolve()

repo_specs = [
    {
        'name': 'grpc',
        'known_good': [
            'src/core/ext/transport/chttp2/transport/hpack_parser.cc',
            'src/core/credentials/transport/tls/ssl_utils.cc',
        ],
        'known_bad': ['test/', 'examples/', 'third_party/'],
        'use_signals': True,
        'use_sbom': True,
    },
    {
        'name': 'openthread',
        'known_good': ['src/core/thread/mesh_forwarder.cpp', 'src/lib/spinel/spinel_decoder.cpp'],
        'known_bad': ['tests/', 'examples/', 'third_party/'],
        'use_signals': True,
        'use_sbom': False,
    },
    {
        'name': 'protobuf',
        'known_good': ['src/google/protobuf/io/coded_stream.cc', 'python/message.c', 'php/ext/google/protobuf/message.c'],
        'known_bad': ['upb/reflection/stage0/google/protobuf/descriptor.upb.h', 'src/google/protobuf/io/coded_stream_unittest.cc', 'ruby/ext/google/protobuf_c/ruby-upb.h'],
        'use_signals': True,
        'use_sbom': False,
    },
    {
        'name': 'sentencepiece',
        'known_good': ['src/unigram_model.cc', 'python/src/sentencepiece/sentencepiece.i'],
        'known_bad': ['third_party/', 'test/'],
        'use_signals': False,
        'use_sbom': False,
    },
    {
        'name': 'leveldb',
        'known_good': ['db/db_impl.cc', 'table/format.cc'],
        'known_bad': ['doc/', 'benchmarks/'],
        'use_signals': False,
        'use_sbom': False,
    },
    {
        'name': 'gson',
        'known_good': ['gson/src/main/java/com/google/gson/stream/JsonReader.java'],
        'known_bad': ['gson/src/test/'],
        'use_signals': False,
        'use_sbom': False,
    },
    {
        'name': 'gvisor',
        'known_good': ['runsc/specutils/specutils.go', 'pkg/sentry/fsimpl/'],
        'known_bad': ['test/', 'tools/'],
        'use_signals': True,
        'use_sbom': False,
    },
]

cases = []
for spec in repo_specs:
    repo_root = bench_root / spec['name']
    if not repo_root.exists():
        continue
    case = {
        'name': spec['name'],
        'repo_root': str(repo_root),
        'policy': str(repo_root / '.codex-harness.md'),
        'known_good': spec['known_good'],
        'known_bad': spec['known_bad'],
    }
    signals_path = repo_root / f'external_signals_{today}.json'
    if spec['use_signals'] and signals_path.exists():
        case['signals_json'] = str(signals_path)
    sbom_path = repo_root / 'sbom.json'
    if spec['use_sbom'] and sbom_path.exists():
        case['sbom'] = str(sbom_path)
    cases.append(case)

payload = {
    'top_k': 20,
    'limit': 150,
    'cases': cases,
}
out_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
print(out_path)
print(len(cases))
PY

if [[ ! -s "$CORPUS_PATH" ]]; then
  printf 'failed to build corpus: %s\n' "$CORPUS_PATH" >&2
  exit 1
fi

CASE_COUNT="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1], "r", encoding="utf-8")).get("cases", [])))' "$CORPUS_PATH")"
if [[ "$CASE_COUNT" == "0" ]]; then
  printf 'no benchmark repositories found under %s\n' "$BENCH_ROOT" >&2
  exit 1
fi

printf 'bench_root=%s\n' "$BENCH_ROOT"
printf 'corpus=%s\n' "$CORPUS_PATH"
printf 'cases=%s\n' "$CASE_COUNT"

if [[ "$SKIP_BOOTSTRAP" -eq 0 ]]; then
  mapfile -t REPOS < <(python3 -c 'import json,sys; data=json.load(open(sys.argv[1], "r", encoding="utf-8")); [print(case["repo_root"]) for case in data.get("cases", [])]' "$CORPUS_PATH")
  for repo in "${REPOS[@]}"; do
    policy="$repo/.codex-harness.md"
    signals="$repo/external_signals_${TODAY_UTC}.json"
    if [[ "$REFRESH_BOOTSTRAP" -eq 0 && -f "$policy" && -f "$signals" ]]; then
      printf '[bootstrap keep] %s\n' "$repo"
      continue
    fi
    printf '[bootstrap run] %s\n' "$repo"
    BOOTSTRAP_ARGS=("$repo" --sandbox "$SANDBOX")
    if [[ -n "$MODEL" ]]; then
      BOOTSTRAP_ARGS+=(--model "$MODEL")
    fi
    if [[ "$UNSAFE_BYPASS" -eq 1 ]]; then
      BOOTSTRAP_ARGS+=(--dangerously-bypass-approvals-and-sandbox)
    fi
    (cd "$HARNESS_ROOT" && python3 -m oss_harness bootstrap "${BOOTSTRAP_ARGS[@]}")
  done
fi

if [[ -n "$OUTPUT" ]]; then
  (cd "$HARNESS_ROOT" && python3 -m oss_harness benchmark-modes "$CORPUS_PATH") | tee "$OUTPUT"
else
  (cd "$HARNESS_ROOT" && python3 -m oss_harness benchmark-modes "$CORPUS_PATH")
fi
