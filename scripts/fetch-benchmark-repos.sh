#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  fetch-benchmark-repos.sh CORPUS_JSON

Reads a benchmark corpus file and clones any case with a `repo_url` into its `repo_root`
if the repository does not already exist.

If the target directory already contains a git repository, the script leaves it in place.

Examples:
  fetch-benchmark-repos.sh configs/benchmark/ot0-diverse-template.json
USAGE
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

CORPUS="$1"

python3 - "$CORPUS" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

corpus = Path(sys.argv[1]).expanduser().resolve()
data = json.loads(corpus.read_text(encoding='utf-8'))
for case in data.get('cases', []):
    repo_url = case.get('repo_url')
    repo_root = case.get('repo_root')
    name = case.get('name') or repo_root or repo_url
    if not repo_url or not repo_root:
        print(f"skip {name}: missing repo_url or repo_root")
        continue
    root = Path(repo_root).expanduser().resolve()
    if (root / '.git').exists():
        print(f"keep {name}: {root} already exists")
        continue
    root.parent.mkdir(parents=True, exist_ok=True)
    print(f"clone {name}: {repo_url} -> {root}")
    subprocess.run(['git', 'clone', repo_url, str(root)], check=True)
PY
