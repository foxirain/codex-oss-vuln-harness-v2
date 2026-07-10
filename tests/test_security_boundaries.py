import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from oss_harness.cli import build_parser
from oss_harness.executor import run_codex_exec
from oss_harness.paths import safe_repo_file, validate_repo_target
from oss_harness.policy import load_policy, write_policy_template
from oss_harness.provenance import repository_state, scan_provenance
from oss_harness.targeting import discover_candidates


class SecurityBoundaryTests(unittest.TestCase):
    def test_symlinks_and_unsafe_next_targets_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            outside = root / 'outside'
            (repo / 'src').mkdir(parents=True)
            outside.mkdir()
            (repo / 'src' / 'safe.py').write_text('def parse(data):\n    return eval(data)\n', encoding='utf-8')
            (outside / 'secret.py').write_text('SECRET = "do-not-copy"\n', encoding='utf-8')
            (repo / 'leak.py').symlink_to(outside / 'secret.py')
            (repo / 'linked-dir').symlink_to(outside, target_is_directory=True)

            self.assertIsNone(safe_repo_file(repo, repo / 'leak.py'))
            self.assertEqual(validate_repo_target(repo, 'src/safe.py::parse'), 'src/safe.py::parse')
            (repo / 'src' / 'qualified.cc').write_text('void Namespace::Class::method() {}\n', encoding='utf-8')
            self.assertEqual(
                validate_repo_target(repo, 'src/qualified.cc::Namespace::Class::method'),
                'src/qualified.cc::Namespace::Class::method',
            )
            for unsafe in (
                '../outside/secret.py', '/etc/passwd', r'C:\\Windows\\win.ini',
                r'\\server\\share\\file.py', 'leak.py', 'linked-dir/secret.py',
                'src/safe.py\nother.py', 'src/safe.py\x00',
            ):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    validate_repo_target(repo, unsafe)

            candidates, _ = discover_candidates(repo, policy={}, limit=20)
            paths = [candidate.path.relative_to(repo).as_posix() for candidate in candidates]
            self.assertNotIn('leak.py', paths)
            self.assertNotIn('linked-dir/secret.py', paths)

    def test_policy_template_does_not_turn_examples_into_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = write_policy_template(root / '.codex-harness.md')
            policy = load_policy(policy_path)
            self.assertEqual(policy['include_paths'], [])
            self.assertEqual(policy['languages'], [])
            (root / 'Main.java').write_text(
                'class Main { void run(String x) throws Exception { Runtime.getRuntime().exec(x); } }\n',
                encoding='utf-8',
            )
            candidates, _ = discover_candidates(root, policy=policy, limit=20)
            self.assertIn('Main.java', [candidate.path.relative_to(root).as_posix() for candidate in candidates])

    def test_executor_has_no_implicit_writable_add_dir_and_clears_stale_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = root / 'out' / 'response.txt'
            stdout = root / 'out' / 'stdout.txt'
            stderr = root / 'out' / 'stderr.txt'
            response.parent.mkdir()
            response.write_text('stale', encoding='utf-8')
            completed = subprocess.CompletedProcess(['codex'], 0, 'ok', '')
            with patch('oss_harness.executor.subprocess.run', return_value=completed) as mocked:
                artifacts = run_codex_exec(
                    repo_root=root, prompt_text='audit', response_file=response,
                    stdout_file=stdout, stderr_file=stderr, timeout_seconds=10,
                    model='', sandbox='read-only', full_auto=False,
                    unsafe_bypass=False,
                )
            command = mocked.call_args.args[0]
            self.assertNotIn('--add-dir', command)
            self.assertEqual(mocked.call_args.kwargs['cwd'], str(root.resolve()))
            self.assertFalse(response.exists())
            self.assertEqual(artifacts.returncode, 0)

    def test_full_auto_requires_explicit_writable_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                run_codex_exec(
                    repo_root=root, prompt_text='audit', response_file=root / 'r',
                    stdout_file=root / 'o', stderr_file=root / 'e', timeout_seconds=10,
                    model='', sandbox='read-only', full_auto=True, unsafe_bypass=False,
                )

    def test_cli_codex_tasks_default_to_read_only_without_full_auto(self) -> None:
        parser = build_parser()
        for argv in (['autopilot', '/tmp/session'], ['review', '/tmp/session']):
            args = parser.parse_args(argv)
            self.assertEqual(args.sandbox, 'read-only')
            self.assertFalse(args.full_auto)

    def test_policy_provenance_distinguishes_repository_and_analyst_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            repository_policy = repo / '.codex-harness.md'
            analyst_policy = root / 'analyst-policy.md'
            repository_policy.write_text('# policy', encoding='utf-8')
            analyst_policy.write_text('# policy', encoding='utf-8')
            self.assertEqual(
                scan_provenance(repo, policy=repository_policy)['inputs']['policy']['trust'],
                'repository-provided-untrusted',
            )
            self.assertEqual(
                scan_provenance(repo, policy=analyst_policy)['inputs']['policy']['trust'],
                'analyst-provided',
            )

    def test_repository_provenance_records_untracked_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'
            repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / 'new_parser.py').write_text('def parse(data): return data\n', encoding='utf-8')
            state = repository_state(repo)
            self.assertFalse(state['tracked_dirty'])
            self.assertTrue(state['untracked_present'])
            self.assertTrue(state['worktree_dirty'])


if __name__ == '__main__':
    unittest.main()
