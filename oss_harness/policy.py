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
- Describe the product, deployment model, and trust boundaries.

## In Scope
- Remote attack surface reachable by unauthenticated users.
- Privilege boundary mistakes reachable by low-privilege authenticated users.
- Memory corruption or sandbox escapes in native components.

## Out of Scope
- Denial of service only.
- Social engineering or non-code issues.
- Third-party services outside this repository.

## Focus Areas
- Authentication and authorization boundaries.
- File handling and archive extraction.
- Command execution, deserialization, templating, and native bindings.

## Forbidden Findings
- Accepted-risk issues explicitly documented by the project.
- Admin-only self-XSS.

## Entry Points
- /api
- /graphql
- webhook handlers
- import pipeline

## Include Paths
- src/
- app/
- server/
- internal/

## Exclude Paths
- tests/
- examples/
- vendor/
- dist/

## Languages
- python
- go
- rust

## Framework Hints
- fastapi
- django
- express

## Hot Paths
- auth/
- upload/
- parser/

## Preferred Sinks
- command execution
- unsafe deserialization
- path traversal
- authorization bypass

## Preferred Bug Classes
- authz bypass
- ssti
- ssrf
- rce
- uaf

## Ignore Patterns
- accepted-risk
- wontfix

## Notes
- Report only issues with concrete reachability and security impact.
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
