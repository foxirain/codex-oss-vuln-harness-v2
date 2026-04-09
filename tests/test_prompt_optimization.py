from pathlib import Path
import unittest

from oss_harness.models import Candidate, ExternalSignal, Signal, SymbolHint
from oss_harness.prompting import prompt_profile_for_candidate, render_bundle_prompt, should_attach_snippet


class PromptOptimizationTests(unittest.TestCase):
    def _candidate(self, **kwargs) -> Candidate:
        base = dict(
            path=Path('/tmp/repo/src/core/ext/transport/chttp2/transport/frame_security.cc'),
            language='c_cpp',
            subsystem='src',
            exposure='transport or protocol state machine',
            score=140,
            attack_surfaces=['request entrypoint'],
            sink_kinds=['memory-sensitive native path'],
            framework_hints=[],
            entrypoint_markers=['handler'],
            primary_symbols=[SymbolHint(name='ParseFrame', kind='function', line_start=10, line_end=60, tags=['entrypoint'])],
            semantic_summary=['entrypoint-like parser function', 'state machine transition near sink'],
            reasons=['graph:fan_in (+8)', 'policy_hot_path:transport (+8)', 'line 44: dangerous_copy (+9)'],
            signals=[Signal(name='dangerous_copy', weight=9, line_no=44, line='memcpy(dst, src, len);', rationale='unsafe copy near parser state', language='c_cpp')],
            path_signals=[],
            external_signals=[ExternalSignal(source='crash', weight=12, summary='asan in nearby parser path')],
        )
        base.update(kwargs)
        return Candidate(**base)

    def test_prompt_profile_prefers_deep_for_native_high_risk_targets(self) -> None:
        candidate = self._candidate()
        self.assertEqual(prompt_profile_for_candidate(candidate), 'deep')

    def test_snippet_attachment_is_adaptive(self) -> None:
        deep = self._candidate()
        lean = self._candidate(language='python', exposure='remote API', score=18, sink_kinds=['filesystem'], external_signals=[])
        self.assertTrue(should_attach_snippet(deep, requested=True, attempt=0))
        self.assertFalse(should_attach_snippet(deep, requested=True, attempt=1))
        self.assertFalse(should_attach_snippet(lean, requested=True, attempt=0))

    def test_render_bundle_prompt_uses_targeted_policy_focus(self) -> None:
        repo_root = Path('/tmp/repo')
        candidate = self._candidate(path=repo_root / 'src/core/ext/transport/chttp2/transport/frame_security.cc')
        policy = {
            'in_scope': ['remote parser bugs', 'memory corruption'],
            'out_of_scope': ['docs-only issues'],
            'forbidden_findings': ['test-only assertions'],
            'entry_points': ['src/core/ext/transport', '/api'],
            'hot_paths': ['src/core/ext/transport/chttp2/transport', 'auth/'],
            'preferred_sinks': ['memory-sensitive native path', 'filesystem'],
            'preferred_bug_classes': ['uaf', 'oob write'],
            'notes': ['require concrete reachability'],
        }
        prompt = render_bundle_prompt(repo_root, candidate, policy, profile='deep')
        self.assertIn('Matching hot paths', prompt)
        self.assertIn('src/core/ext/transport/chttp2/transport', prompt)
        self.assertNotIn('auth/', prompt)
        self.assertNotIn('code:', prompt)


if __name__ == '__main__':
    unittest.main()
