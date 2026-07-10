from __future__ import annotations

import re
from pathlib import Path

from oss_harness.paths import safe_repo_file

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

<!-- Replace the comments below with project-specific Markdown bullets. Leaving a
section empty is safe: in particular, an empty Include Paths or Languages section
does not restrict scanning. Do not leave example values that do not apply. -->

## Project Summary
<!-- Product, deployment model, trust boundaries, and untrusted inputs. -->

## In Scope
<!-- Vulnerability classes and security boundaries; do not put paths here. -->

## Out of Scope
<!-- Excluded bug classes and operational exclusions; do not put paths here. -->

## Focus Areas
<!-- Security-relevant subsystems or workflows. -->

## Forbidden Findings
<!-- Claims that must be rejected without concrete reachability and impact. -->

## Entry Points
<!-- Real attacker-controlled APIs, parsers, RPCs, CLI inputs, files, or config. -->

## Include Paths
<!-- Repository-relative paths only. Leave empty to scan every supported file. -->

## Exclude Paths
<!-- Repository-relative paths only. Built-in generated/test exclusions still apply. -->

## Languages
<!-- Relevant language names. Leave empty to use detected languages. -->

## Framework Hints
<!-- Framework, runtime, or protocol-stack names. -->

## Hot Paths
<!-- High-priority repository-relative directories or exact files. -->

## Preferred Sinks
<!-- Sink categories, such as command execution, filesystem, or deserialization. -->

## Preferred Bug Classes
<!-- Realistic bug classes, such as authz bypass, traversal, SSRF, RCE, or UAF. -->

## Ignore Patterns
<!-- Free-form text or repository-relative path fragments that reduce noise. -->

## Notes
<!-- Reporting constraints and ambiguous areas. -->
'''



def find_default_policy(repo_root: Path) -> Path | None:
    for name in DEFAULT_POLICY_CANDIDATES:
        candidate = safe_repo_file(repo_root, Path(name))
        if candidate is not None:
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
    in_comment = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if in_comment:
            if '-->' in line:
                in_comment = False
            continue
        if line.startswith('<!--'):
            in_comment = '-->' not in line
            continue
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
