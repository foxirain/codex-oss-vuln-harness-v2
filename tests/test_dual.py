from pathlib import Path
import unittest

from oss_harness.dual import merge_dual_candidates
from oss_harness.models import Candidate


class DualModeTests(unittest.TestCase):
    def _candidate(self, repo_root: Path, rel_path: str, *, score: int) -> Candidate:
        return Candidate(path=repo_root / rel_path, language='c_cpp', subsystem='src', exposure='remote API', score=score)

    def test_merge_dual_candidates_takes_top_n_from_each_side(self) -> None:
        repo_root = Path('/tmp/repo')
        blind = [
            self._candidate(repo_root, 'a.cc', score=90),
            self._candidate(repo_root, 'b.cc', score=80),
            self._candidate(repo_root, 'c.cc', score=70),
        ]
        signal = [
            self._candidate(repo_root, 'x.cc', score=95),
            self._candidate(repo_root, 'y.cc', score=85),
            self._candidate(repo_root, 'z.cc', score=75),
        ]
        merged, provenance = merge_dual_candidates(blind, signal, per_side_top=2, repo_root=repo_root)
        self.assertEqual([str(item.path.relative_to(repo_root)) for item in merged], ['a.cc', 'x.cc', 'b.cc', 'y.cc'])
        self.assertEqual(provenance['a.cc']['blind_rank'], 1)
        self.assertEqual(provenance['x.cc']['signal_rank'], 1)

    def test_merge_dual_candidates_dedupes_shared_paths_and_tracks_both_sources(self) -> None:
        repo_root = Path('/tmp/repo')
        blind = [self._candidate(repo_root, 'shared.cc', score=60), self._candidate(repo_root, 'blind-only.cc', score=50)]
        signal = [self._candidate(repo_root, 'shared.cc', score=95), self._candidate(repo_root, 'signal-only.cc', score=70)]
        merged, provenance = merge_dual_candidates(blind, signal, per_side_top=2, repo_root=repo_root)
        self.assertEqual([str(item.path.relative_to(repo_root)) for item in merged], ['shared.cc', 'blind-only.cc', 'signal-only.cc'])
        self.assertEqual(provenance['shared.cc']['sources'], ['blind', 'signal'])
        self.assertEqual(provenance['shared.cc']['blind_rank'], 1)
        self.assertEqual(provenance['shared.cc']['signal_rank'], 1)
        self.assertEqual(merged[0].score, 95)


if __name__ == '__main__':
    unittest.main()
