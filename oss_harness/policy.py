from __future__ import annotations

import re
from pathlib import Path

DEFAULT_POLICY_CANDIDATES = [
    '.codex-harness.md',
    'HARNESS_POLICY.md',
    'SECURITY_SCOPE.md',
]

SECTION_KEYS = {
    'project summary': 'project_summary',
    'summary': 'project_summary',
    'in scope': 'in_scope',
    'scope': 'in_scope',
    'out of scope': 'out_of_scope',
    'focus areas': 'focus_areas',
    'focus': 'focus_areas',
    'forbidden findings': 'forbidden_findings',
    'forbidden': 'forbidden_findings',
    'entry points': 'entry_points',
    'entrypoint': 'entry_points',
    'include paths': 'include_paths',
    'includes': 'include_paths',
    'exclude paths': 'exclude_paths',
    'excludes': 'exclude_paths',
    'languages': 'languages',
    'framework hints': 'framework_hints',
    'frameworks': 'framework_hints',
    'hot paths': 'hot_paths',
    'preferred sinks': 'preferred_sinks',
    'preferred bug classes': 'preferred_bug_classes',
    'ignore patterns': 'ignore_patterns',
    'notes': 'notes',
}

POLICY_TEMPLATE = '''# Project Policy

## Project Summary
- Describe the product, deployment model, major trust boundaries, and where untrusted input arrives.
- Note whether the target is a web service, native library, CLI, desktop app, agent, or mixed system.

## In Scope
- Write vulnerability classes and security boundaries here, not path names.
- Remote attack surface reachable by unauthenticated or low-privilege users.
- Privilege boundary mistakes, auth bypass, tenant isolation failures, and trust-boundary violations.
- Memory corruption, parser bugs, unsafe deserialization, command execution, filesystem trust-boundary bugs, and sandbox escapes.

## Out of Scope
- Write excluded bug classes or operational exclusions here, not path names.
- Denial of service only.
- Social engineering, non-code issues, or dependency-only issues outside this repository's owned code.
- Findings the project explicitly documents as accepted risk.

## Focus Areas
- Describe the security-relevant subsystems or workflows to emphasize.
- Authentication and authorization boundaries.
- File handling, archive extraction, import or upload pipelines.
- Command execution, deserialization, templating, native bindings, or trust-material loading.

## Forbidden Findings
- Write findings that should be rejected even if they look superficially suspicious.
- Admin-only self-XSS.
- Theoretical hardening suggestions without a concrete attacker-controlled path.
- Test-only, example-only, or debug-only findings that do not map to production code reachability.

## Entry Points
- Put real attacker-controlled input entrypoints here: APIs, RPC methods, CLI commands, env vars, file formats, webhooks, bootstrap configs, plugin loaders.
- /api
- /graphql
- webhook handlers
- import pipeline

## Include Paths
- Put only repository paths here. These are the directories or files the harness should analyze.
- src/
- app/
- server/
- internal/

## Exclude Paths
- Put only repository paths here. These are directories or files the harness should ignore or deprioritize.
- tests/
- examples/
- vendor/
- dist/

## Languages
- List only languages actually relevant to the vulnerability-hunting target.
- python
- go
- rust

## Framework Hints
- List frameworks, runtimes, or protocol stacks that help the scanner infer entrypoints.
- fastapi
- django
- express

## Hot Paths
- Put only high-priority repository paths or exact files here. These are not bug classes.
- auth/
- upload/
- parser/

## Preferred Sinks
- Put sink categories here, not paths.
- command execution
- unsafe deserialization
- filesystem
- memory-sensitive native path

## Preferred Bug Classes
- Put realistic bug classes here, not files or subsystems.
- authz bypass
- path traversal
- ssrf
- rce
- uaf

## Ignore Patterns
- Put free-form text or path fragments here that should reduce noise.
- accepted-risk
- wontfix
- generated/

## Notes
- Record policy constraints, reporting standards, or ambiguous areas.
- Require concrete reachability and security impact.
- Keep `In Scope` for vulnerability classes, `Include Paths` for repository paths, `Hot Paths` for high-priority files or directories, and `Entry Points` for real attacker-controlled inputs.
- Prefer findings that can plausibly become a CVE or a high-confidence advisory.
'''



def find_default_policy(repo_root: Path) -> Path | None:
    for name in DEFAULT_POLICY_CANDIDATES:
        candidate = repo_root / name
        if candidate.exists():
            return candidate
    return None


def write_policy_template(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(POLICY_TEMPLATE, encoding='utf-8')
    return path


def load_policy(path: Path | None) -> dict:
    if path is None:
        return _empty_policy()
    text = path.read_text(encoding='utf-8')
    policy = _parse_markdown_policy(text)
    policy['path'] = str(path)
    policy['raw_text'] = text
    return policy


def render_policy_summary(policy: dict) -> str:
    lines: list[str] = []
    ordered_keys = [
        'project_summary', 'in_scope', 'out_of_scope', 'focus_areas', 'forbidden_findings',
        'entry_points', 'include_paths', 'exclude_paths', 'languages', 'framework_hints',
        'hot_paths', 'preferred_sinks', 'preferred_bug_classes', 'ignore_patterns', 'notes',
    ]
    for key in ordered_keys:
        items = policy.get(key, [])
        if not items:
            continue
        lines.append(f"{key.replace('_', ' ').title()}:")
        lines.extend(f"- {item}" for item in items)
    return '\n'.join(lines).strip()


def policy_list(policy: dict, key: str) -> list[str]:
    return [str(item).strip() for item in policy.get(key, []) if str(item).strip()]


def _empty_policy() -> dict:
    base = {'path': '', 'raw_text': ''}
    for normalized in set(SECTION_KEYS.values()):
        base[normalized] = []
    return base


def _parse_markdown_policy(text: str) -> dict:
    policy = _empty_policy()
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        heading = re.match(r'^#{1,6}\s+(.*)$', line)
        if heading:
            current_key = SECTION_KEYS.get(heading.group(1).strip().lower())
            continue
        if current_key is None:
            continue
        bullet = re.match(r'^[-*+]\s+(.*)$', line)
        if bullet:
            policy[current_key].append(bullet.group(1).strip())
            continue
        numbered = re.match(r'^\d+\.\s+(.*)$', line)
        if numbered:
            policy[current_key].append(numbered.group(1).strip())
            continue
        policy[current_key].append(line)
    return policy
