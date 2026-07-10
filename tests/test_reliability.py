import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest
from unittest.mock import patch

from oss_harness.autopilot import _ingest_pending_response
from oss_harness.executor import ExecArtifacts
from oss_harness.findings import finding_slug
from oss_harness.review_schema import validate_review
from oss_harness.reviewing import run_review
from oss_harness.session import (
    failed_ranks,
    initialize_state,
    load_state,
    record_attempt_failure,
    record_review,
    response_path,
    set_pending_review,
)


class ReliabilityTests(unittest.TestCase):
    def _session(self, root: Path) -> tuple[Path, Path]:
        repo = root / 'repo'
        session = root / 'session'
        repo.mkdir()
        session.mkdir()
        (repo / 'target.py').write_text('def parse(data): return eval(data)\n', encoding='utf-8')
        (session / 'targets.json').write_text(
            '{"repo_root": "%s", "candidates": [{"path": "target.py"}]}' % repo,
            encoding='utf-8',
        )
        initialize_state(session)
        set_pending_review(session, 1, 'target.py', 'prompt.md')
        return repo, session

    def test_parse_errors_retry_without_creating_a_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, session = self._session(root)
            findings_dir = session / 'autopilot' / 'findings'
            findings_dir.mkdir(parents=True)
            findings_log = session / 'autopilot' / 'findings.txt'
            progress = session / 'autopilot' / 'progress.txt'
            for attempt in range(1, 4):
                response_path(session).write_text('unstructured response', encoding='utf-8')
                result = _ingest_pending_response(session, findings_dir, findings_log, progress)
                state = load_state(session)
                self.assertEqual(state['history'], [])
                self.assertEqual(result['terminal_failure'], attempt == 3)
            self.assertEqual(failed_ranks(load_state(session)), {1})
            self.assertEqual(load_state(session)['current_rank'], 2)

    def test_incomplete_strong_verdict_retries_instead_of_completing_rank(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, session = self._session(root)
            findings_dir = session / 'autopilot' / 'findings'
            findings_dir.mkdir(parents=True)
            progress = session / 'autopilot' / 'progress.txt'
            response = (
                'Strict verdict: cve_candidate\nSingle best next target: none\n'
                'entrypoint: none\nattacker_control: none\nsink: none\n'
                'impact: none\nnot blocked by: none\n'
            )
            for _ in range(3):
                response_path(session).write_text(response, encoding='utf-8')
                _ingest_pending_response(session, findings_dir, session / 'findings.txt', progress)
            state = load_state(session)
            self.assertEqual(state['history'], [])
            self.assertEqual(failed_ranks(state), {1})
            self.assertEqual(list(findings_dir.glob('finding-*.txt')), [])

    def test_success_resets_retry_counter_for_the_same_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / 'session'
            session.mkdir()
            initialize_state(session)
            record_attempt_failure(session, rank=1, target='a.py', kind='timeout', detail='', max_attempts=3)
            record_attempt_failure(session, rank=1, target='a.py', kind='timeout', detail='', max_attempts=3)
            record_review(session, 1, 'a.py', 'not_cve_candidate', '', '', '', True)
            _, terminal, attempts = record_attempt_failure(session, rank=1, target='a.py', kind='timeout', detail='', max_attempts=3)
            self.assertEqual(attempts, 1)
            self.assertFalse(terminal)

    def test_concurrent_records_do_not_lose_history_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / 'session'
            session.mkdir()
            initialize_state(session)
            def write(rank: int) -> None:
                record_review(session, rank, f'{rank}.py', 'not_cve_candidate', '', '', '', False)
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(write, range(1, 41)))
            self.assertEqual(len(load_state(session)['history']), 40)

    def test_review_nonzero_cannot_reuse_stale_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, session = self._session(root)
            finding = session / 'autopilot' / 'findings' / 'finding-1.txt'
            finding.parent.mkdir(parents=True)
            finding.write_text('candidate', encoding='utf-8')
            stale = session / 'review' / finding_slug(finding) / 'review.json'
            stale.parent.mkdir(parents=True)
            stale.write_text('{"tier": "S"}', encoding='utf-8')

            def failed_exec(**kwargs):
                kwargs['response_file'].write_text('{"tier":"S"}', encoding='utf-8')
                return ExecArtifacts(kwargs['response_file'], kwargs['stdout_file'], kwargs['stderr_file'], 1)

            with patch('oss_harness.reviewing.run_codex_exec', side_effect=failed_exec):
                result = run_review(
                    session, repo_root=repo, finding_files=[finding], timeout_spec='1s',
                    model='', sandbox='read-only', full_auto=False, unsafe_bypass=False,
                )
            self.assertEqual(result['success'], 'false')
            self.assertEqual(result['succeeded'], '0')
            self.assertFalse(stale.exists())

    def test_high_tier_placeholder_schema_is_rejected(self) -> None:
        review = {
            'finding_file': 'finding.txt', 'title': 'Candidate', 'tier': 'S',
            'confidence': 'high', 'disposition': 'confirmed', 'summary': 'Potential issue',
            'entrypoint': 'not applicable because unknown', 'reachability': 'reachable',
            'attacker_control': 'bytes', 'sink': 'copy', 'impact': 'write',
            'key_evidence': ['a.py:1'], 'blocking_gaps': [], 'next_actions': [],
        }
        with self.assertRaises(ValueError):
            validate_review(review)

    def test_high_tier_placeholder_evidence_is_rejected(self) -> None:
        review = {
            'finding_file': 'finding.txt', 'title': 'Candidate', 'tier': 'S',
            'confidence': 'high', 'disposition': 'confirmed', 'summary': 'Potential issue',
            'entrypoint': 'public parser', 'reachability': 'reachable API',
            'attacker_control': 'input bytes', 'sink': 'fixed-size copy',
            'impact': 'out-of-bounds write', 'key_evidence': ['-', 'unknown details'],
            'blocking_gaps': [], 'next_actions': [],
        }
        with self.assertRaises(ValueError):
            validate_review(review)


if __name__ == '__main__':
    unittest.main()
