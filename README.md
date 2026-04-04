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
cd /path/to/repo
oss-harness init-policy .codex-harness.md
python3 -m oss_harness scan . --policy ./.codex-harness.md --out /tmp/oss-artifacts
python3 -m oss_harness inspect /tmp/oss-artifacts/session-YYYYMMDDTHHMMSSZ --top 10
python3 -m oss_harness autopilot /tmp/oss-artifacts/session-YYYYMMDDTHHMMSSZ --duration 2h --per-run-timeout 20m --include-snippet
```

## External Signals

Use `--signals-json` for advisory or analyst hints and `--crash-dir` for crash or sanitizer artifacts.

```bash
python3 -m oss_harness scan /path/to/repo   --policy /path/to/repo/.codex-harness.md   --signals-json /path/to/signals.json   --crash-dir /path/to/crash-logs   --out /tmp/oss-artifacts
```

Templates:

- `configs/oss/generic-policy-template.md`
- `configs/oss/signals-template.json`

Detailed usage:

- `docs/OSS_HARNESS.md`
