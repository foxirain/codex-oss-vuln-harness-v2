from __future__ import annotations

from pathlib import Path

from oss_harness.models import Candidate
from oss_harness.policy import render_policy_summary

BASE_PLAYBOOK = '''You are auditing an open source codebase for vulnerabilities that can plausibly become a CVE or a high-confidence security advisory.

Prioritize:
- remote or low-privilege reachable attack surface
- authorization and tenant-isolation failures
- command execution, unsafe deserialization, SSRF, path traversal, template injection, SQL injection
- memory corruption, integer overflow, type confusion, parser bugs, sandbox escapes in native code
- file write or file read primitives that cross trust boundaries

A finding is weak unless you can explain:
1. the exact attacker-controlled entrypoint
2. the sensitive sink or invariant break
3. the data, object, size, permission, or state transition that fails
4. concrete impact
5. why existing checks do not stop exploitation

Do not report policy-excluded issues. If the evidence is incomplete, ask for one best next target instead of forcing a bug claim.
'''


def render_bundle_prompt(repo_root: Path, candidate: Candidate, policy: dict) -> str:
    rel_path = candidate.path.relative_to(repo_root)
    signals = '\n'.join(
        f"- line {signal.line_no}: `{signal.name}` (+{signal.weight}) :: {signal.rationale}\n  code: `{signal.line[:180]}`"
        for signal in candidate.signals
    )
    if not signals:
        signals = '- no line-level signals captured'
    reasons = '\n'.join(f'- {reason}' for reason in candidate.reasons[:16])
    external = '\n'.join(
        f"- {signal.summary} (+{signal.weight}) [{signal.source}]"
        for signal in candidate.external_signals[:8]
    ) or '- no repo or framework signals attached'
    surfaces = ', '.join(candidate.attack_surfaces) or 'unclassified'
    sinks = ', '.join(candidate.sink_kinds) or 'unclassified'
    frameworks = ', '.join(candidate.framework_hints) or 'none'
    entrypoints = ', '.join(candidate.entrypoint_markers) or 'none'
    primary_symbols = '\n'.join(
        f"- {symbol.kind} `{symbol.name}` lines {symbol.line_start}-{symbol.line_end} tags={','.join(symbol.tags) or 'none'} score={symbol.score}"
        for symbol in candidate.primary_symbols[:6]
    ) or '- no symbol-level hints captured'
    semantic_summary = '\n'.join(f'- {item}' for item in candidate.semantic_summary[:6]) or '- no semantic summary captured'
    policy_summary = render_policy_summary(policy) or 'No explicit policy file was supplied. Use general CVE-quality judgment and focus on concrete security impact.'
    return f"""{BASE_PLAYBOOK}

Project policy:
{policy_summary}

Target file: `{rel_path}`
Language: `{candidate.language}`
Subsystem: `{candidate.subsystem}`
Likely exposure: `{candidate.exposure}`
Priority score: `{candidate.score}`
Attack surfaces: `{surfaces}`
Sink kinds: `{sinks}`
Framework hints: `{frameworks}`
Entrypoint markers: `{entrypoints}`

Why this file was selected:
{reasons}

Observed signals:
{signals}

Repo or framework context:
{external}

Primary symbols:
{primary_symbols}

Semantic summary:
{semantic_summary}

Audit workflow:
1. Confirm the real attacker-reachable entrypoint into this file or a nearby caller.
2. Identify the exact trust boundary crossed by attacker-controlled data.
3. Trace that data into a sensitive sink, unsafe parser, authorization decision, memory operation, or lifetime transition.
4. Cross-check the issue against the policy's out-of-scope and forbidden sections before claiming a finding.
5. If you find a likely vulnerability, produce:
   - title
   - bug class
   - reachability
   - attacker control
   - impact
   - evidence with exact files and functions
   - exploit sketch or proof strategy
   - confidence 1-10
6. If the branch is not good enough, give one best next target only.
"""
