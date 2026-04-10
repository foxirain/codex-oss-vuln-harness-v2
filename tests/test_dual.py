from pathlib import Path
import unittest

from oss_harness.dual import merge_dual_candidates
from oss_harness.models import Candidate


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


if __name__ == '__main__':
    unittest.main()
