# Codex OSS Vulnerability Harness

Standalone Codex automation harness for vulnerability hunting across general open source software.

## What It Does

- ranks high-signal files before Codex starts reviewing
- injects project-specific scope and exclusions from one Markdown policy file
- supports Python, JS/TS, Go, Rust, C/C++, Java/Kotlin, PHP, and Ruby
- accepts external signals from advisories, git history, crash logs, sanitizer logs, and manual analyst input
- runs unattended `codex exec` loops with automated verdict ingest and branch cooling

## Quick Start

```bash
git clone <this-repository-url>
cd codex-oss-vuln-harness-v2
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

oss-harness init-policy /path/to/target/.codex-harness.md
oss-harness scan /path/to/target --policy /path/to/target/.codex-harness.md --out /tmp/oss-artifacts
oss-harness inspect /tmp/oss-artifacts/session-<UTC-timestamp> --top 10
oss-harness autopilot /tmp/oss-artifacts/session-<UTC-timestamp> --duration 2h --per-run-timeout 20m --include-snippet
```

Codex tasks default to the `read-only` sandbox and do not receive the harness or
artifact directory as an additional writable root. `--sandbox workspace-write`,
`--full-auto`, and the unsafe bypass flag are explicit opt-ins; a writable target
sandbox allows model-generated commands to modify the repository.
Read-only prevents repository mutation; it does not guarantee confidentiality
for every host-readable secret. Run untrusted targets in a credential-free,
disposable container or VM, and treat model-generated findings and repros as
untrusted until a human validates them.

## External Signals

Use explicit `--signals-json`, `--crash-dir`, and `--sbom` arguments for analyst-provided inputs. The scanner records their paths and hashes in the session manifest and does not silently auto-select signal files from the target repository.
An auto-detected policy file is recorded separately as
`repository-provided-untrusted`; review its scope before relying on exclusions.

```bash
python3 -m oss_harness scan /path/to/repo   --policy /path/to/repo/.codex-harness.md   --signals-json /path/to/signals.json   --crash-dir /path/to/crash-logs   --out /tmp/oss-artifacts
```

Templates:

- `configs/oss/generic-policy-template.md`
- `configs/oss/signals-template.json`

Detailed usage:

- `docs/OSS_HARNESS.md`
