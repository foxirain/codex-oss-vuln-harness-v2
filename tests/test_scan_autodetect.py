from pathlib import Path
import tempfile
import unittest

from oss_harness.cli import _resolve_scan_inputs, build_parser
from oss_harness.policy import find_default_policy


class ScanAutodetectTests(unittest.TestCase):
    def test_policy_autodetect_prefers_known_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            policy = repo / '.codex-harness.md'
            policy.write_text('# Project Policy\n', encoding='utf-8')
            self.assertEqual(find_default_policy(repo), policy)

    def test_untrusted_signal_inputs_are_not_auto_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'external_signals.json').write_text('{}', encoding='utf-8')
            sbom = repo / 'sbom.json'
            sbom.write_text('{}', encoding='utf-8')
            crash_dir = repo / 'crash-logs'
            crash_dir.mkdir()
            parser = build_parser()
            args = parser.parse_args(['scan', str(repo)])
            _, _, signals, crashes, selected_sbom, _, _ = _resolve_scan_inputs(parser, args)
            self.assertIsNone(signals)
            self.assertIsNone(crashes)
            self.assertIsNone(selected_sbom)


if __name__ == '__main__':
    unittest.main()
