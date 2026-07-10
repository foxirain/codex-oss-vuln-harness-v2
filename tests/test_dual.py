import json
from pathlib import Path
import tempfile
import unittest

from oss_harness.dual import merge_dual_candidates, write_dual_session_bundle
from oss_harness.models import Candidate, LanguageStat


class DualModeTests(unittest.TestCase):
    def _candidate(self, repo_root: Path, rel_path: str, *, score: int, subsystem: str = 'src', exposure: str = 'remote API') -> Candidate:
        return Candidate(path=repo_root / rel_path, language='c_cpp', subsystem=subsystem, exposure=exposure, score=score)

    def test_merge_dual_candidates_refills_when_top_paths_overlap(self) -> None:
        repo_root = Path('/tmp/repo')
        blind = [
            self._candidate(repo_root, 'shared.cc', score=90),
            self._candidate(repo_root, 'b.cc', score=80),
            self._candidate(repo_root, 'c.cc', score=70),
        ]
        signal = [
            self._candidate(repo_root, 'shared.cc', score=95),
            self._candidate(repo_root, 'x.cc', score=85),
            self._candidate(repo_root, 'y.cc', score=75),
        ]
        merged, provenance = merge_dual_candidates(blind, signal, per_side_top=2, repo_root=repo_root)
        self.assertEqual([str(item.path.relative_to(repo_root)) for item in merged], ['shared.cc', 'x.cc', 'b.cc', 'y.cc'])
        self.assertEqual(provenance['shared.cc']['sources'], ['blind', 'signal'])
        self.assertEqual(provenance['y.cc']['signal_rank'], 3)

    def test_merge_dual_candidates_limits_header_flood(self) -> None:
        repo_root = Path('/tmp/repo')
        blind = [
            self._candidate(repo_root, 'include/a.h', score=100, subsystem='include', exposure='parser or serialization path'),
            self._candidate(repo_root, 'include/b.h', score=99, subsystem='include', exposure='parser or serialization path'),
            self._candidate(repo_root, 'src/impl.cc', score=70, subsystem='src', exposure='transport or protocol state machine'),
        ]
        signal = [
            self._candidate(repo_root, 'include/c.h', score=98, subsystem='include', exposure='parser or serialization path'),
            self._candidate(repo_root, 'src/transport.cc', score=85, subsystem='src', exposure='transport or protocol state machine'),
            self._candidate(repo_root, 'src/ffi.cc', score=80, subsystem='bindings', exposure='language binding or FFI path'),
        ]
        merged, _ = merge_dual_candidates(blind, signal, per_side_top=2, repo_root=repo_root)
        rel_paths = [str(item.path.relative_to(repo_root)) for item in merged]
        self.assertIn('src/impl.cc', rel_paths)
        self.assertIn('src/transport.cc', rel_paths)
        self.assertLessEqual(sum(path.endswith('.h') for path in rel_paths), 1)

    def test_relaxed_deferred_fill_deduplicates_paths_accepted_by_other_side(self) -> None:
        repo_root = Path('/tmp/repo')
        blind = [
            self._candidate(repo_root, 'include/a.h', score=100, subsystem='include', exposure='parser'),
            self._candidate(repo_root, 'include/shared.h', score=90, subsystem='include', exposure='parser'),
        ]
        signal = [
            self._candidate(repo_root, 'include/b.h', score=99, subsystem='include', exposure='parser'),
            self._candidate(repo_root, 'include/shared.h', score=95, subsystem='include', exposure='parser'),
        ]
        merged, provenance = merge_dual_candidates(blind, signal, per_side_top=2, repo_root=repo_root)
        paths = [item.path.relative_to(repo_root).as_posix() for item in merged]
        self.assertEqual(paths.count('include/shared.h'), 1)
        self.assertEqual(set(provenance['include/shared.h']['sources']), {'blind', 'signal'})

    def test_dual_session_keeps_scan_and_candidate_provenance_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            (repo / 'a.py').write_text('def parse(x): return eval(x)\n', encoding='utf-8')
            blind = [self._candidate(repo, 'a.py', score=10)]
            signal = [self._candidate(repo, 'a.py', score=20)]
            scan = {
                'harness_version': '0.2.0', 'repository': {'commit': 'abc'},
                'inputs': {'policy': None, 'config': None, 'signals': {'path': 'signals.json'}, 'crash_dir': {'path': 'crashes'}, 'sbom': {'path': 'sbom.json'}},
            }
            result = write_dual_session_bundle(
                repo_root=repo, out_dir=root / 'session', blind_candidates=blind,
                signal_candidates=signal, per_side_top=1, policy={},
                language_stats=[LanguageStat(language='python', file_count=1, extensions=['.py'])],
                scan_provenance=scan,
            )
            blind_manifest = json.loads((result['blind_session'] / 'targets.json').read_text())
            signal_manifest = json.loads((result['signal_session'] / 'targets.json').read_text())
            merged_manifest = json.loads((result['merged_session'] / 'targets.json').read_text())
            self.assertIsNone(blind_manifest['provenance']['inputs']['signals'])
            self.assertFalse(blind_manifest['provenance']['git_history'])
            self.assertEqual(signal_manifest['provenance']['inputs']['signals']['path'], 'signals.json')
            self.assertTrue(signal_manifest['provenance']['git_history'])
            self.assertEqual(merged_manifest['provenance']['repository']['commit'], 'abc')
            self.assertIn('a.py', merged_manifest['dual_candidate_provenance'])


if __name__ == '__main__':
    unittest.main()
