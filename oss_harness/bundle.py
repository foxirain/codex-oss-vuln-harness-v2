from __future__ import annotations

import json
from pathlib import Path

from oss_harness.models import Candidate, LanguageStat
from oss_harness.policy import render_policy_summary
from oss_harness.prompting import prompt_profile_for_candidate, render_bundle_prompt
from oss_harness.paths import safe_repo_file
from oss_harness.session import initialize_state


def write_session_bundle(repo_root: Path, out_dir: Path, candidates: list[Candidate], top_n: int, policy: dict, language_stats: list[LanguageStat], provenance: dict | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = out_dir / 'bundles'
    bundle_dir.mkdir(parents=True, exist_ok=True)

    manifest_candidates = []
    for candidate in candidates:
        if safe_repo_file(repo_root, candidate.path) is None:
            raise ValueError(f'candidate escapes repository or is a symlink: {candidate.path}')
        item = candidate.to_dict(repo_root)
        item['prompt_profile'] = prompt_profile_for_candidate(candidate)
        manifest_candidates.append(item)

    manifest = {
        'repo_root': str(repo_root),
        'candidate_count': len(candidates),
        'top_n': top_n,
        'policy_path': policy.get('path', ''),
        'policy_summary': render_policy_summary(policy),
        'framework_hints': policy.get('framework_hints', []),
        'preferred_sinks': policy.get('preferred_sinks', []),
        'languages': [{'language': item.language, 'file_count': item.file_count, 'extensions': item.extensions} for item in language_stats],
        'candidates': manifest_candidates,
        'provenance': provenance or {},
    }
    (out_dir / 'targets.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    report_template = {
        'title': '', 'bug_class': '', 'impact': '', 'entrypoint': '', 'attacker_control': '',
        'affected_files': [], 'evidence': [], 'exploit_sketch': '', 'confidence': 0,
        'attack_surfaces': [], 'sink_kinds': [], 'framework_hints': [], 'policy_notes': [], 'next_steps': [],
    }
    (out_dir / 'finding_template.json').write_text(json.dumps(report_template, indent=2), encoding='utf-8')
    initialize_state(out_dir)

    session_lines = [
        '# OSS Codex Harness Session', '',
        f'- Repository root: `{repo_root}`',
        f"- Policy file: `{policy.get('path', '') or 'none'}`",
        f'- Candidate count: `{len(candidates)}`',
        f'- Review budget: top `{top_n}` files', '',
        '## Detected Languages', '',
    ]
    session_lines.extend(f"- `{item.language}`: {item.file_count} files ({', '.join(item.extensions)})" for item in language_stats)
    session_lines.extend(['', '## Policy Summary', '', render_policy_summary(policy) or '- no explicit policy file', '', '## Priority Targets', ''])

    for rank, candidate in enumerate(candidates[:top_n], start=1):
        rel_path = candidate.path.relative_to(repo_root)
        slug = f"{rank:02d}-{str(rel_path).replace('/', '__')}.md"
        prompt_path = bundle_dir / slug
        profile = prompt_profile_for_candidate(candidate)
        prompt_path.write_text(render_bundle_prompt(repo_root, candidate, policy, profile=profile), encoding='utf-8')

        snippet_path = bundle_dir / slug.replace('.md', '.snippet.txt')
        snippet_path.write_text(_extract_snippet(repo_root, candidate, profile=profile), encoding='utf-8')

        surfaces = ', '.join(candidate.attack_surfaces[:3]) or 'none'
        sinks = ', '.join(candidate.sink_kinds[:3]) or 'none'
        symbols = ', '.join(symbol.name for symbol in candidate.primary_symbols[:3]) or 'none'
        session_lines.append(
            f"{rank}. `{rel_path}` | score `{candidate.score}` | lang `{candidate.language}` | profile `{profile}` | exposure `{candidate.exposure}` | surfaces `{surfaces}` | sinks `{sinks}` | symbols `{symbols}` | prompt `{prompt_path.name}`"
        )

    session_lines.extend([
        '', '## Codex Usage Pattern', '',
        '1. Start with the highest-score prompt file in `bundles/` or use `oss-harness next <session_dir>`.',
        '2. Keep Codex on one branch at a time: entrypoint, trust boundary, sink, invariant, impact.',
        '3. Record verdicts with `oss-harness record ...` or let `oss-harness autopilot ...` ingest them automatically.',
        '4. Save confirmed issues into copies of `finding_template.json`.',
    ])
    (out_dir / 'SESSION.md').write_text('\n'.join(session_lines) + '\n', encoding='utf-8')
    return out_dir


def _extract_snippet(repo_root: Path, candidate: Candidate, profile: str = 'balanced') -> str:
    safe_path = safe_repo_file(repo_root, candidate.path)
    if safe_path is None:
        return ''
    try:
        lines = safe_path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return ''
    seen: set[tuple[int, int]] = set()
    blocks: list[str] = []
    radius = {'lean': 1, 'balanced': 2, 'deep': 3}.get(profile, 2)
    symbol_limit = {'lean': 1, 'balanced': 2, 'deep': 2}.get(profile, 2)
    signal_limit = {'lean': 2, 'balanced': 3, 'deep': 4}.get(profile, 3)

    for symbol in candidate.primary_symbols[:symbol_limit]:
        start = max(1, symbol.line_start)
        end = min(len(lines), max(start, min(symbol.line_end, start + radius * 4)))
        if (start, end) in seen:
            continue
        seen.add((start, end))
        header = f'## symbol {symbol.name} lines {start}-{end}'
        body = '\n'.join(f"{line_no:>6} {lines[line_no - 1]}" for line_no in range(start, end + 1))
        blocks.append(f'{header}\n{body}')

    for signal in candidate.signals[:signal_limit]:
        start = max(1, signal.line_no - radius)
        end = min(len(lines), signal.line_no + radius)
        if (start, end) in seen:
            continue
        seen.add((start, end))
        header = f'## lines {start}-{end} [{signal.name}]'
        body = '\n'.join(f"{line_no:>6} {lines[line_no - 1]}" for line_no in range(start, end + 1))
        blocks.append(f'{header}\n{body}')
    return '\n\n'.join(blocks) + ('\n' if blocks else '')
