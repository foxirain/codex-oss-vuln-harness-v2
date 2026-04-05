from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from oss_harness.autopilot import run_autopilot
from oss_harness.automation import run_bootstrap
from oss_harness.bundle import write_session_bundle
from oss_harness.findings import list_finding_files, select_finding_files
from oss_harness.ingest import load_response, parse_response
from oss_harness.policy import find_default_policy, load_policy, write_policy_template
from oss_harness.reporting import run_report
from oss_harness.repro import run_repro
from oss_harness.reviewing import TIER_ORDER, run_review
from oss_harness.session import completed_ranks, load_state, record_review, response_archive_dir, response_path, save_state, set_pending_review
from oss_harness.targeting import discover_candidates, load_json_config

SUBCOMMANDS = {
    'scan', 'inspect', 'codex', 'next', 'record', 'ingest', 'loop', 'status', 'autopilot', 'init-policy',
    'bootstrap', 'review', 'repro', 'report',
}
VERDICTS = ['cve_candidate', 'plausible_security_bug', 'latent_bug', 'not_cve_candidate', 'needs_more_context']
MAX_MANUAL_FOLLOWUPS = 2
TIER_CHOICES = ['S', 'A', 'B', 'C', 'D']


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='oss-harness', description='Prepare reusable vulnerability-hunting sessions for Codex across general OSS projects.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    policy_parser = subparsers.add_parser('init-policy', help='Write a starter Markdown policy file.')
    policy_parser.add_argument('path', type=Path, nargs='?', default=Path('.codex-harness.md'), help='Output Markdown path.')

    bootstrap_parser = subparsers.add_parser('bootstrap', help='Use Codex to generate a final policy file and external signals JSON.')
    bootstrap_parser.add_argument('repo_root', help='Path to the repository to bootstrap.')
    bootstrap_parser.add_argument('--policy-path', type=Path, help='Output policy path. Defaults to <repo>/.codex-harness.md')
    bootstrap_parser.add_argument('--signals-path', type=Path, help='Output signals path. Defaults to <repo>/external_signals_YYYY-MM-DD.json')
    bootstrap_parser.add_argument('--out-dir', type=Path, help='Directory for bootstrap logs and summary. Defaults to <repo>/.codex-bootstrap')
    _add_codex_task_args(bootstrap_parser, timeout_default='45m')

    scan_parser = subparsers.add_parser('scan', help='Score files and generate a review session.')
    scan_parser.add_argument('repo_root', help='Path to the repository to analyze.')
    scan_parser.add_argument('--policy', type=Path, help='Markdown policy file defining scope and exclusions.')
    scan_parser.add_argument('--config', type=Path, help='Optional JSON config for include paths or signal caps.')
    scan_parser.add_argument('--signals-json', type=Path, help='Optional local JSON containing crash, advisory, or external file signals.')
    scan_parser.add_argument('--crash-dir', type=Path, help='Optional directory of sanitizer, panic, or crash logs to map back into repo files.')
    scan_parser.add_argument('--out', type=Path, default=Path('artifacts'), help='Directory where session artifacts will be written.')
    scan_parser.add_argument('--limit', type=int, default=120, help='Maximum number of ranked candidates to retain.')
    scan_parser.add_argument('--top', type=int, default=30, help='How many prompt bundles to generate.')

    inspect_parser = subparsers.add_parser('inspect', help='Print a ranked summary from a generated session.')
    inspect_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    inspect_parser.add_argument('--top', type=int, default=15, help='Number of ranked entries to print.')

    codex_parser = subparsers.add_parser('codex', help='Print a ready-to-paste Codex prompt for a ranked target.')
    codex_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    codex_parser.add_argument('--rank', type=int, default=1, help='Rank number from SESSION.md / targets.json.')
    codex_parser.add_argument('--include-snippet', action='store_true', help='Append the generated code snippet.')
    codex_parser.add_argument('--extra-instruction', default='', help='Extra instruction appended to the prompt.')

    next_parser = subparsers.add_parser('next', help='Print the next prompt based on session state.')
    next_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    next_parser.add_argument('--include-snippet', action='store_true', help='Append the generated code snippet.')

    record_parser = subparsers.add_parser('record', help='Record a review verdict and prepare the next step.')
    record_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    record_parser.add_argument('--rank', type=int, required=True, help='Rank that was just reviewed.')
    record_parser.add_argument('--target', required=True, help='Target path or function that was reviewed.')
    record_parser.add_argument('--verdict', choices=VERDICTS, required=True, help='Strict verdict for the review.')
    record_parser.add_argument('--notes', default='', help='Short review notes or summary.')
    record_parser.add_argument('--next-target', default='', help='Optional manual next file/function if Codex suggested one.')
    record_parser.add_argument('--next-prompt', default='', help='Optional focused follow-up instruction for the manual next target.')
    record_parser.add_argument('--no-auto-advance', action='store_true', help='Do not advance to the next ranked target automatically.')

    ingest_parser = subparsers.add_parser('ingest', help='Parse a Codex response and update session state automatically.')
    ingest_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    ingest_parser.add_argument('--rank', type=int, required=True, help='Rank that was just reviewed.')
    ingest_parser.add_argument('--target', required=True, help='Target path or function that was reviewed.')
    ingest_parser.add_argument('--response-file', type=Path, help='Path to a text file containing the Codex response. If omitted, stdin is used.')
    ingest_parser.add_argument('--next-prompt', default='', help='Optional focused prompt to pair with the parsed next target.')
    ingest_parser.add_argument('--no-auto-advance', action='store_true', help='Do not advance to the next ranked target automatically.')

    loop_parser = subparsers.add_parser('loop', help='One command loop: ingest fixed response file if present, then print next prompt.')
    loop_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    loop_parser.add_argument('--include-snippet', action='store_true', help='Append the generated code snippet.')
    loop_parser.add_argument('--next-prompt', default='', help='Optional focused prompt to pair with the parsed next target.')

    status_parser = subparsers.add_parser('status', help='Show session review progress.')
    status_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')

    review_parser = subparsers.add_parser('review', help='Use Codex to re-review finding files and assign tiers.')
    review_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    review_parser.add_argument('--finding', action='append', default=[], help='Optional finding file path, filename, or substring selector. Repeatable.')
    _add_codex_task_args(review_parser, timeout_default='20m')

    repro_parser = subparsers.add_parser('repro', help='Generate reproduction scripts and result files for selected findings.')
    repro_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    repro_parser.add_argument('--finding', action='append', default=[], help='Optional finding file path, filename, or substring selector. Repeatable.')
    repro_parser.add_argument('--tier-min', choices=TIER_CHOICES, help='Optional minimum review tier to select findings from the review index.')
    _add_codex_task_args(repro_parser, timeout_default='45m')

    report_parser = subparsers.add_parser('report', help='Generate final reports for selected findings using findings, reviews, and repro artifacts.')
    report_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    report_parser.add_argument('--finding', action='append', default=[], help='Optional finding file path, filename, or substring selector. Repeatable.')
    report_parser.add_argument('--tier-min', choices=TIER_CHOICES, help='Optional minimum review tier to select findings from the review index.')
    report_parser.add_argument('--template', required=True, help='Template file path or free-form format instruction.')
    _add_codex_task_args(report_parser, timeout_default='20m')

    autopilot_parser = subparsers.add_parser('autopilot', help='Run Codex non-interactively for a fixed time budget.')
    autopilot_parser.add_argument('session_dir', type=Path, help='Path to a generated session directory.')
    autopilot_parser.add_argument('--duration', default='1h', help='Total autopilot budget. Example: 30m, 1h.')
    autopilot_parser.add_argument('--per-run-timeout', default='20m', help='Maximum time per Codex execution. Example: 10m.')
    autopilot_parser.add_argument('--include-snippet', action='store_true', help='Append generated code snippets to prompts.')
    autopilot_parser.add_argument('--model', default='', help='Optional Codex model override.')
    autopilot_parser.add_argument('--sandbox', choices=['read-only', 'workspace-write', 'danger-full-access'], default='workspace-write', help='Sandbox mode for codex exec when not bypassing safeguards.')
    autopilot_parser.add_argument('--no-full-auto', action='store_true', help='Do not pass --full-auto to codex exec.')
    autopilot_parser.add_argument('--dangerously-bypass-approvals-and-sandbox', action='store_true', help="Pass through Codex's unsafe bypass flag.")
    autopilot_parser.add_argument('--stop-on-finding', action='store_true', help='Stop as soon as a strong candidate is found.')
    return parser



def _add_codex_task_args(parser: argparse.ArgumentParser, *, timeout_default: str) -> None:
    parser.add_argument('--timeout', default=timeout_default, help=f'Maximum time budget for each Codex task. Default: {timeout_default}.')
    parser.add_argument('--model', default='', help='Optional Codex model override.')
    parser.add_argument('--sandbox', choices=['read-only', 'workspace-write', 'danger-full-access'], default='workspace-write', help='Sandbox mode for codex exec when not bypassing safeguards.')
    parser.add_argument('--no-full-auto', action='store_true', help='Do not pass --full-auto to codex exec.')
    parser.add_argument('--dangerously-bypass-approvals-and-sandbox', action='store_true', help="Pass through Codex's unsafe bypass flag.")



def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    normalized_argv = _normalize_argv(raw_argv)
    parser = build_parser()
    args = parser.parse_args(normalized_argv)
    if args.command == 'init-policy':
        path = write_policy_template(Path(args.path).expanduser().resolve())
        print(f'policy={path}')
        return 0
    if args.command == 'bootstrap':
        return _run_bootstrap(parser, args)
    if args.command == 'scan':
        return _run_scan(parser, args)
    if args.command == 'inspect':
        return _run_inspect(args)
    if args.command == 'codex':
        return _run_codex(args)
    if args.command == 'next':
        return _run_next(args)
    if args.command == 'record':
        return _run_record(args)
    if args.command == 'ingest':
        return _run_ingest(args)
    if args.command == 'loop':
        return _run_loop(args)
    if args.command == 'status':
        return _run_status(args)
    if args.command == 'review':
        return _run_review(args)
    if args.command == 'repro':
        return _run_repro(args)
    if args.command == 'report':
        return _run_report(args)
    if args.command == 'autopilot':
        return _run_autopilot(args)
    parser.error(f'unknown command: {args.command}')
    return 2



def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ['scan', '--help']
    if argv[0] in SUBCOMMANDS or argv[0] in {'-h', '--help'}:
        return argv
    return ['scan', *argv]



def _run_bootstrap(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).expanduser().resolve()
    if not repo_root.exists():
        parser.error(f'repository does not exist: {repo_root}')
    if not repo_root.is_dir():
        parser.error(f'repository is not a directory: {repo_root}')
    policy_path = Path(args.policy_path).expanduser().resolve() if args.policy_path else repo_root / '.codex-harness.md'
    signals_path = Path(args.signals_path).expanduser().resolve() if args.signals_path else repo_root / f"external_signals_{datetime.now(UTC).strftime('%Y-%m-%d')}.json"
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else repo_root / '.codex-bootstrap'
    result = run_bootstrap(
        repo_root,
        policy_path=policy_path,
        signals_path=signals_path,
        out_dir=out_dir,
        timeout_spec=args.timeout,
        model=args.model,
        sandbox=args.sandbox,
        full_auto=not args.no_full_auto,
        unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox,
    )
    for key, value in result.items():
        print(f'{key}={value}')
    return 0 if policy_path.exists() and signals_path.exists() else 1



def _run_scan(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).expanduser().resolve()
    if not repo_root.exists():
        parser.error(f'repository does not exist: {repo_root}')
    if not repo_root.is_dir():
        parser.error(f'repository is not a directory: {repo_root}')
    policy_path = Path(args.policy).expanduser().resolve() if args.policy else find_default_policy(repo_root)
    config = load_json_config(Path(args.config).expanduser().resolve()) if args.config else {}
    policy = load_policy(policy_path)
    candidates, language_stats = discover_candidates(repo_root, policy=policy, limit=args.limit, config=config, external_signal_path=(Path(args.signals_json).expanduser().resolve() if args.signals_json else None), crash_dir=(Path(args.crash_dir).expanduser().resolve() if args.crash_dir else None))
    timestamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    session_dir = args.out / f'session-{timestamp}'
    write_session_bundle(repo_root=repo_root, out_dir=session_dir, candidates=candidates, top_n=args.top, policy=policy, language_stats=language_stats)
    print(f'session={session_dir}')
    print(f'repo_root={repo_root}')
    print(f"policy={policy_path or ''}")
    print(f"signals_json={Path(args.signals_json).expanduser().resolve() if args.signals_json else ''}")
    print(f"crash_dir={Path(args.crash_dir).expanduser().resolve() if args.crash_dir else ''}")
    print(f'candidates={len(candidates)}')
    print(f'top_prompts={min(args.top, len(candidates))}')
    print(f'fixed_response_file={response_path(session_dir)}')
    return 0



def _run_inspect(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.session_dir)
    candidates = manifest.get('candidates', [])
    print(f"session={Path(args.session_dir).resolve()}")
    print(f"repo_root={manifest.get('repo_root', '')}")
    print(f"policy={manifest.get('policy_path', '')}")
    print(f"candidate_count={manifest.get('candidate_count', 0)}")
    print('languages=' + ', '.join(item['language'] for item in manifest.get('languages', [])))
    for rank, candidate in enumerate(candidates[: args.top], start=1):
        surfaces = ', '.join(candidate.get('attack_surfaces', [])[:2]) or 'none'
        sinks = ', '.join(candidate.get('sink_kinds', [])[:2]) or 'none'
        symbols = ', '.join(symbol.get('name', '') for symbol in candidate.get('primary_symbols', [])[:2] if symbol.get('name')) or 'none'
        print(f"{rank:02d} score={candidate['score']:>3} lang={candidate['language']:<10} exposure={candidate['exposure']:<22} surfaces={surfaces:<24} sinks={sinks:<24} symbols={symbols:<20} path={candidate['path']}")
    return 0



def _run_codex(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    prompt, prompt_path, snippet_path, target = _load_rank_prompt(session_dir, manifest, args.rank)
    if args.extra_instruction:
        prompt = prompt.rstrip() + '\n\n' + args.extra_instruction.strip() + '\n'
    set_pending_review(session_dir, args.rank, target, str(prompt_path))
    _print_codex_runbook(manifest['repo_root'], prompt, prompt_path, snippet_path, args.include_snippet, response_path(session_dir))
    return 0



def _run_next(args: argparse.Namespace) -> int:
    _print_next_prompt(Path(args.session_dir).expanduser().resolve(), include_snippet=args.include_snippet)
    return 0



def _run_record(args: argparse.Namespace) -> int:
    state = record_review(session_dir=Path(args.session_dir).expanduser().resolve(), rank=args.rank, target=args.target, verdict=args.verdict, notes=args.notes, next_target=args.next_target, next_prompt=args.next_prompt, auto_advance=not args.no_auto_advance)
    _print_record_result(args.rank, args.verdict, state)
    return 0



def _run_ingest(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    text = load_response(args.response_file, sys.stdin.read())
    state = _ingest_text(session_dir, text, rank=args.rank, target=args.target, next_prompt=args.next_prompt, auto_advance=not args.no_auto_advance)
    _print_record_result(args.rank, state['history'][-1]['verdict'], state)
    print(f"parsed_next_target={state['history'][-1].get('next_target', '')}")
    return 0



def _run_loop(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    state = load_state(session_dir)
    fixed_response = Path(state.get('pending_response_file', response_path(session_dir)))
    if fixed_response.exists() and fixed_response.stat().st_size > 0:
        pending_rank = state.get('pending_rank')
        pending_target = state.get('pending_target', '').strip()
        if pending_target:
            text = fixed_response.read_text(encoding='utf-8')
            state = _ingest_text(session_dir, text, rank=pending_rank, target=pending_target, next_prompt=args.next_prompt, auto_advance=True)
            archive_dir = response_archive_dir(session_dir)
            archive_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
            shutil.move(str(fixed_response), str(archive_dir / f'response-{stamp}.txt'))
            print(f"ingested_verdict={state['history'][-1]['verdict']}")
            print(f"ingested_next_target={state['history'][-1].get('next_target', '')}")
        else:
            print('response_file_present_but_no_pending_target=1')
    _print_next_prompt(session_dir, include_snippet=args.include_snippet)
    return 0



def _run_status(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    done = completed_ranks(state)
    print(f'session={session_dir}')
    print(f"repo_root={manifest.get('repo_root', '')}")
    print(f"candidate_count={manifest.get('candidate_count', 0)}")
    print(f'completed={sorted(done)}')
    print(f"current_rank={state.get('current_rank', 1)}")
    print(f"manual_next_target={state.get('manual_next_target', '')}")
    print(f"pending_rank={state.get('pending_rank')}")
    print(f"pending_target={state.get('pending_target', '')}")
    print(f"fixed_response_file={state.get('pending_response_file', response_path(session_dir))}")
    print(f"finding_count={len(list_finding_files(session_dir))}")
    for item in state.get('history', [])[-5:]:
        print(f"history rank={item.get('rank')} verdict={item.get('verdict')} target={item.get('target')}")
    return 0



def _run_review(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    finding_files = select_finding_files(session_dir, args.finding)
    if not finding_files:
        raise SystemExit(f'no finding files selected under {session_dir / "autopilot" / "findings"}')
    result = run_review(
        session_dir,
        repo_root=Path(manifest['repo_root']).expanduser().resolve(),
        finding_files=finding_files,
        timeout_spec=args.timeout,
        model=args.model,
        sandbox=args.sandbox,
        full_auto=not args.no_full_auto,
        unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox,
    )
    for key, value in result.items():
        print(f'{key}={value}')
    return 0



def _run_repro(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    finding_files = _select_findings_for_action(session_dir, args.finding, args.tier_min)
    if not finding_files:
        raise SystemExit('no findings selected for repro')
    result = run_repro(
        session_dir,
        repo_root=Path(manifest['repo_root']).expanduser().resolve(),
        finding_files=finding_files,
        timeout_spec=args.timeout,
        model=args.model,
        sandbox=args.sandbox,
        full_auto=not args.no_full_auto,
        unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox,
    )
    for key, value in result.items():
        print(f'{key}={value}')
    return 0



def _run_report(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir).expanduser().resolve()
    manifest = _load_manifest(session_dir)
    finding_files = _select_findings_for_action(session_dir, args.finding, args.tier_min)
    if not finding_files:
        raise SystemExit('no findings selected for report generation')
    template_text = _load_template_text(args.template)
    result = run_report(
        session_dir,
        repo_root=Path(manifest['repo_root']).expanduser().resolve(),
        finding_files=finding_files,
        template_text=template_text,
        timeout_spec=args.timeout,
        model=args.model,
        sandbox=args.sandbox,
        full_auto=not args.no_full_auto,
        unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox,
    )
    for key, value in result.items():
        print(f'{key}={value}')
    return 0



def _run_autopilot(args: argparse.Namespace) -> int:
    return run_autopilot(Path(args.session_dir), include_snippet=args.include_snippet, duration_spec=args.duration, per_run_timeout_spec=args.per_run_timeout, model=args.model, sandbox=args.sandbox, full_auto=not args.no_full_auto, unsafe_bypass=args.dangerously_bypass_approvals_and_sandbox, stop_on_finding=args.stop_on_finding)



def _load_manifest(session_dir: Path) -> dict:
    manifest_path = session_dir / 'targets.json'
    if not manifest_path.exists():
        raise SystemExit(f'missing session manifest: {manifest_path}')
    with manifest_path.open('r', encoding='utf-8') as handle:
        return json.load(handle)



def _load_rank_prompt(session_dir: Path, manifest: dict, rank: int) -> tuple[str, Path, Path, str]:
    candidates = manifest.get('candidates', [])
    if not candidates:
        raise SystemExit('no candidates found in session')
    if rank < 1 or rank > len(candidates):
        raise SystemExit(f'rank out of range: {rank} (1-{len(candidates)})')
    candidate = candidates[rank - 1]
    bundle_dir = session_dir / 'bundles'
    bundle_prefix = f"{rank:02d}-{candidate['path'].replace('/', '__')}"
    prompt_path = bundle_dir / f'{bundle_prefix}.md'
    snippet_path = bundle_dir / f'{bundle_prefix}.snippet.txt'
    if not prompt_path.exists():
        raise SystemExit(f'missing prompt bundle: {prompt_path}. Rerun `oss-harness scan` with the current harness version and use the new session directory.')
    return prompt_path.read_text(encoding='utf-8'), prompt_path, snippet_path, candidate['path']



def _print_next_prompt(session_dir: Path, include_snippet: bool) -> None:
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    manual_target = state.get('manual_next_target', '').strip()
    manual_prompt = state.get('manual_next_prompt', '').strip()
    depth = int(state.get('manual_followup_depth', 0))
    if manual_target and depth >= MAX_MANUAL_FOLLOWUPS:
        state['manual_next_target'] = ''
        state['manual_next_prompt'] = ''
        state['manual_followup_depth'] = 0
        state['pending_target'] = ''
        state['pending_rank'] = None
        state['pending_prompt_source'] = ''
        save_state(session_dir, state)
        manual_target = ''
        manual_prompt = ''
    if manual_target:
        prompt = _manual_followup_prompt(state, manual_target, manual_prompt)
        set_pending_review(session_dir, None, manual_target, str(session_dir / 'review_state.json'))
        _print_codex_runbook(manifest['repo_root'], prompt, session_dir / 'review_state.json', None, False, response_path(session_dir))
        return
    rank = _next_pending_rank(state, manifest)
    prompt, prompt_path, snippet_path, target = _load_rank_prompt(session_dir, manifest, rank)
    set_pending_review(session_dir, rank, target, str(prompt_path))
    _print_codex_runbook(manifest['repo_root'], prompt, prompt_path, snippet_path, include_snippet, response_path(session_dir))



def _ingest_text(session_dir: Path, text: str, rank: int | None, target: str, next_prompt: str, auto_advance: bool) -> dict:
    parsed = parse_response(text)
    state = load_state(session_dir)
    depth = int(state.get('manual_followup_depth', 0))
    next_target = parsed['next_target'] if parsed['should_continue'] else ''
    if next_target and depth >= MAX_MANUAL_FOLLOWUPS:
        next_target = ''
        next_prompt = ''
    return record_review(session_dir=session_dir, rank=rank, target=target, verdict=parsed['verdict'], notes=parsed['notes'], next_target=next_target, next_prompt=next_prompt, auto_advance=auto_advance)



def _print_codex_runbook(repo_root: str, prompt: str, prompt_path: Path, snippet_path: Path | None, include_snippet: bool, fixed_response_file: Path) -> None:
    print('# Codex CLI Runbook')
    print()
    print('1. Start Codex in the repository you scanned.')
    print(f'   cd {repo_root}')
    print('   codex')
    print()
    print('2. Paste the prompt below into Codex.')
    print()
    print('```text')
    print(prompt.rstrip())
    print()
    print('Write your final answer to this fixed file before you return it:')
    print(fixed_response_file)
    if include_snippet and snippet_path and snippet_path.exists():
        print()
        print('Supplemental snippet from the harness:')
        print(snippet_path.read_text(encoding='utf-8').rstrip())
    print('```')
    print()
    print(f'Source prompt: {prompt_path}')
    print(f'Fixed response file: {fixed_response_file}')
    if include_snippet and snippet_path:
        print(f'Snippet file: {snippet_path}')



def _next_pending_rank(state: dict, manifest: dict) -> int:
    done = completed_ranks(state)
    candidates = manifest.get('candidates', [])
    start = max(1, int(state.get('current_rank', 1)))
    for rank in range(start, len(candidates) + 1):
        if rank in done:
            continue
        candidate = candidates[rank - 1]
        if _is_actionable_candidate(candidate.get('path', '')):
            return rank
    raise SystemExit('all ranked targets in this session have already been reviewed')



def _is_actionable_candidate(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith(('docs/', 'examples/', 'samples/', 'vendor/', 'third_party/')):
        return False
    if '/test/' in lowered or '/tests/' in lowered or '/spec/' in lowered or '/specs/' in lowered:
        return False
    if lowered.endswith(('_test.go', '.spec.js', '.test.js', '.spec.ts', '.test.ts')):
        return False
    return True



def _manual_followup_prompt(state: dict, manual_target: str, manual_prompt: str) -> str:
    history = state.get('history', [])
    previous = history[-1] if history else {}
    lines = ['Continue from the previous audit.', 'Do not restart broad review.', '', f"Previous verdict: {previous.get('verdict', '')}", f"Previous target: {previous.get('target', '')}"]
    notes = previous.get('notes', '').strip()
    if notes:
        lines.append(f'Previous notes: {notes}')
    lines.extend(['', f'Now focus only on: {manual_target}'])
    if manual_prompt:
        lines.extend(['', manual_prompt.strip()])
    else:
        lines.extend(['', 'Requirements:', '1. Confirm the exact attacker-reachable path into this target.', '2. Validate concrete attacker control, trust-boundary crossing, and security impact.', '3. If nothing concrete exists, give a strict verdict and the single best next target.'])
    return '\n'.join(lines) + '\n'



def _print_record_result(rank: int | None, verdict: str, state: dict) -> None:
    print(f'recorded_rank={rank}')
    print(f'verdict={verdict}')
    print(f"current_rank={state.get('current_rank', 1)}")
    print(f"manual_next_target={state.get('manual_next_target', '')}")



def _select_findings_for_action(session_dir: Path, selectors: list[str], tier_min: str | None) -> list[Path]:
    finding_files = select_finding_files(session_dir, selectors)
    if not tier_min:
        return finding_files
    review_index_path = session_dir / 'review' / 'review_index.json'
    if not review_index_path.exists():
        raise SystemExit(f'missing review index: {review_index_path}. Run `oss-harness review` first or omit --tier-min.')
    review_index = json.loads(review_index_path.read_text(encoding='utf-8'))
    allowed_names = {
        item.get('finding_file')
        for item in review_index.get('reviews', [])
        if TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0) >= TIER_ORDER[tier_min]
    }
    filtered = [path for path in finding_files if path.name in allowed_names]
    return filtered



def _load_template_text(value: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.exists() and candidate.is_file():
        return candidate.read_text(encoding='utf-8')
    return value
