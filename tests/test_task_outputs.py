import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from oss_harness.automation import POLICY_HEADINGS, run_bootstrap
from oss_harness.executor import ExecArtifacts
from oss_harness.reporting import run_report
from oss_harness.repro import _validate_repro_payload, run_repro


def successful_exec_with(text: str, calls: list[dict]):
    def run(**kwargs):
        calls.append(kwargs)
        kwargs['response_file'].parent.mkdir(parents=True, exist_ok=True)
        kwargs['response_file'].write_text(text, encoding='utf-8')
        return ExecArtifacts(kwargs['response_file'], kwargs['stdout_file'], kwargs['stderr_file'], 0)
    return run


class TaskOutputTests(unittest.TestCase):
    def test_repro_envelope_rejects_traversal(self) -> None:
        with self.assertRaises(ValueError):
            _validate_repro_payload({
                'status': 'success',
                'files': {'repro.sh': 'echo x', 'result.md': 'Status: success', '../escape': 'x'},
            })

    def test_bootstrap_validates_response_then_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            (repo / 'src.py').write_text('def parse(x): return x\n', encoding='utf-8')
            policy = '# Project Policy\n\n' + '\n\n'.join(f'## {heading}' for heading in POLICY_HEADINGS)
            payload = json.dumps({
                'policy_markdown': policy,
                'signals': {'signals': [{
                    'path': 'src.py', 'source': 'manual', 'weight': 7,
                    'summary': 'analyst-selected parser', 'metadata': {},
                }]},
                'summary_markdown': '# Bootstrap Summary\n\nproject_type: library',
            })
            calls: list[dict] = []
            with patch('oss_harness.automation.run_codex_exec', side_effect=successful_exec_with(payload, calls)):
                result = run_bootstrap(
                    repo, policy_path=repo / '.codex-harness.md',
                    signals_path=root / 'signals.json', out_dir=root / 'bootstrap',
                    timeout_spec='1s', model='', sandbox='read-only',
                    full_auto=False, unsafe_bypass=False,
                )
            self.assertEqual(result['success'], 'true')
            self.assertTrue((repo / '.codex-harness.md').exists())
            self.assertEqual(json.loads((root / 'signals.json').read_text())['signals'][0]['path'], 'src.py')
            self.assertNotIn('add_dirs', calls[0])

    def test_repro_json_envelope_cannot_write_outside_item_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            session = root / 'session'
            repo.mkdir()
            session.mkdir()
            finding = session / 'finding-1.txt'
            finding.write_text('candidate', encoding='utf-8')
            payload = json.dumps({
                'status': 'partial',
                'files': {
                    'repro.sh': '#!/usr/bin/env bash\nset -euo pipefail\necho partial',
                    'result.md': 'Status: partial\n\nRun `./repro.sh`; exact build dependency remains unavailable.',
                },
            })
            calls: list[dict] = []
            with patch('oss_harness.repro.run_codex_exec', side_effect=successful_exec_with(payload, calls)):
                result = run_repro(
                    session, repo_root=repo, finding_files=[finding], timeout_spec='1s',
                    model='', sandbox='read-only', full_auto=False, unsafe_bypass=False,
                )
            self.assertEqual(result['success'], 'true')
            scripts = list((session / 'repro').glob('*/repro.sh'))
            self.assertEqual(len(scripts), 1)
            self.assertTrue(scripts[0].stat().st_mode & 0o100)
            self.assertNotIn('add_dirs', calls[0])

    def test_failed_repro_removes_all_helpers_from_previous_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            session = root / 'session'
            repo.mkdir()
            session.mkdir()
            finding = session / 'finding-1.txt'
            finding.write_text('candidate', encoding='utf-8')
            from oss_harness.findings import finding_slug
            item_dir = session / 'repro' / finding_slug(finding)
            item_dir.mkdir(parents=True)
            (item_dir / 'helper.py').write_text('stale helper', encoding='utf-8')

            def failed(**kwargs):
                return ExecArtifacts(kwargs['response_file'], kwargs['stdout_file'], kwargs['stderr_file'], 1)

            with patch('oss_harness.repro.run_codex_exec', side_effect=failed):
                result = run_repro(
                    session, repo_root=repo, finding_files=[finding], timeout_spec='1s',
                    model='', sandbox='read-only', full_auto=False, unsafe_bypass=False,
                )
            self.assertEqual(result['success'], 'false')
            self.assertFalse((item_dir / 'helper.py').exists())
            self.assertEqual(list(item_dir.glob('*.py')), [])

    def test_report_is_written_only_after_successful_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            session = root / 'session'
            repo.mkdir()
            session.mkdir()
            finding = session / 'finding-1.txt'
            finding.write_text('candidate', encoding='utf-8')
            report_text = '# Finding\n\n' + ('Concrete evidence and impact. ' * 5)
            calls: list[dict] = []
            with patch('oss_harness.reporting.run_codex_exec', side_effect=successful_exec_with(report_text, calls)):
                result = run_report(
                    session, repo_root=repo, finding_files=[finding], template_text='Advisory',
                    timeout_spec='1s', model='', sandbox='read-only', full_auto=False,
                    unsafe_bypass=False,
                )
            self.assertEqual(result['success'], 'true')
            self.assertEqual(len(list((session / 'reports').glob('*/report.md'))), 1)
            self.assertNotIn('add_dirs', calls[0])


if __name__ == '__main__':
    unittest.main()
