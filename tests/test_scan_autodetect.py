from pathlib import Path
import tempfile
import time
import unittest

from oss_harness.cli import _choose_latest_file, _find_default_crash_dir, _find_default_sbom, _find_default_signals_json
from oss_harness.policy import find_default_policy


class ScanAutodetectTests(unittest.TestCase):
    def test_policy_autodetect_prefers_known_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            policy = repo / '.codex-harness.md'
            policy.write_text('# Project Policy\n', encoding='utf-8')
            self.assertEqual(find_default_policy(repo), policy)

    def test_signals_autodetect_picks_latest_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            older = repo / 'external_signals_2026-04-07.json'
            newer = repo / 'external_signals_2026-04-08.json'
            older.write_text('{}', encoding='utf-8')
            time.sleep(0.01)
            newer.write_text('{}', encoding='utf-8')
            self.assertEqual(_find_default_signals_json(repo), newer)
            self.assertEqual(_choose_latest_file([older, newer]), newer)

    def test_sbom_autodetect_finds_cyclonedx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            sbom = repo / 'service.cyclonedx.json'
            sbom.write_text('{}', encoding='utf-8')
            self.assertEqual(_find_default_sbom(repo), sbom)

    def test_crash_dir_autodetect_finds_common_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            crash_dir = repo / 'crash-logs'
            crash_dir.mkdir()
            self.assertEqual(_find_default_crash_dir(repo), crash_dir)


if __name__ == '__main__':
    unittest.main()
