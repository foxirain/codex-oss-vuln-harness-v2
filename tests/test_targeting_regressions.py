from collections import Counter
from pathlib import Path
import unittest

from oss_harness.models import ExternalSignal, Signal
from oss_harness.targeting import (
    _artifact_profile,
    _canonicalize_policy_paths,
    _external_signal_profile,
    _has_strong_external_signal,
    _infer_exposure,
    _language_for_path,
    _matches_path_pattern,
    _retention_reason,
    _select_languages,
    _should_skip_path,
    _weighted_signal_value,
    _normalize_prefixes,
)


class _SemanticMeta:
    def __init__(self, entrypoint_lines=None, sink_lines=None):
        self.entrypoint_lines = entrypoint_lines or []
        self.sink_lines = sink_lines or []


class TargetingRegressionTests(unittest.TestCase):
    def test_human_readable_language_names_normalize(self) -> None:
        detected = Counter({'c_cpp': 10, 'python': 3, 'php': 2})
        selected = _select_languages(detected, {'c++', 'python c extension', 'php c extension', 'protocol buffers'})
        self.assertEqual(selected, {'c_cpp', 'python', 'php'})

    def test_swig_i_file_is_analyzable(self) -> None:
        file_path = Path('python/src/sentencepiece/sentencepiece.i')
        self.assertEqual(_language_for_path(file_path, {'python'}), 'python')
        self.assertEqual(_language_for_path(file_path, {'c_cpp'}), 'c_cpp')

    def test_glob_excludes_and_ignore_patterns_apply(self) -> None:
        self.assertTrue(_matches_path_pattern('src/google/protobuf/io/coded_stream_unittest.cc', '**/*_unittest.*'))
        self.assertTrue(_should_skip_path('src/google/protobuf/io/coded_stream_unittest.cc', [], ['**/*_unittest.*'], []))
        self.assertTrue(_should_skip_path('src/google/protobuf/io/tokenizer.cc', [], [], ['src/google/protobuf/io/*']))

    def test_absolute_policy_paths_are_canonicalized(self) -> None:
        repo_root = Path('/work/leveldb')
        canonical = _canonicalize_policy_paths(repo_root, ['/work/leveldb/db/db_impl.cc', 'table/format.cc'])
        self.assertEqual(canonical, ['db/db_impl.cc', 'table/format.cc'])
        self.assertFalse(_should_skip_path('db/db_impl.cc', canonical, [], []))

    def test_absolute_policy_paths_survive_normalization(self) -> None:
        repo_root = Path('/work/openthread')
        normalized = _normalize_prefixes(['/work/openthread/src/core/thread', 'src/core/net'])
        canonical = _canonicalize_policy_paths(repo_root, normalized)
        self.assertEqual(canonical, ['src/core/thread', 'src/core/net'])
        self.assertFalse(_should_skip_path('src/core/thread/mesh_forwarder.cpp', canonical, [], []))

    def test_strong_external_signal_gets_retention_exemption(self) -> None:
        external = [ExternalSignal(source='advisory', weight=8, summary='recent CVE-adjacent fix', metadata={})]
        reason = _retention_reason(
            score=8,
            signals=[],
            external_signals=external,
            hot_path_hits=0,
            entrypoint_hits=0,
            focus_hits=0,
            in_degree=0,
            out_degree=0,
            semantic_meta=None,
        )
        self.assertTrue(reason)
        self.assertTrue(_has_strong_external_signal(external))

    def test_graph_and_semantic_evidence_can_prevent_false_negative_drop(self) -> None:
        reason = _retention_reason(
            score=6,
            signals=[Signal(name='alloc_free', weight=6, line_no=10, line='malloc(x)', rationale='memory lifetime surface', language='c_cpp')],
            external_signals=[],
            hot_path_hits=0,
            entrypoint_hits=0,
            focus_hits=0,
            in_degree=4,
            out_degree=0,
            semantic_meta=_SemanticMeta(entrypoint_lines=[12]),
        )
        self.assertTrue(reason)

    def test_external_signal_profile_distinguishes_signal_families(self) -> None:
        profile = _external_signal_profile([
            ExternalSignal(source='git', weight=6, summary='history', metadata={}),
            ExternalSignal(source='crash', weight=12, summary='asan crash', metadata={}),
            ExternalSignal(source='advisory', weight=7, summary='cve fix', metadata={}),
        ])
        self.assertEqual(profile['source_count'], 3)
        self.assertEqual(profile['crash_like'], 1)
        self.assertEqual(profile['advisory_like'], 1)
        self.assertEqual(profile['git_like'], 1)

    def test_native_exposure_is_more_specific_for_transport_and_tls(self) -> None:
        exposure = _infer_exposure(
            'src/core/ext/transport/chttp2/transport/frame_security.cc',
            language='c_cpp',
            signals=[],
            attack_surfaces=set(),
            sink_kinds={'memory-sensitive native path'},
            external_signals=[ExternalSignal(source='crash', weight=12, summary='asan', metadata={})],
            framework_hints=set(),
        )
        self.assertEqual(exposure, 'transport or protocol state machine')
        exposure = _infer_exposure(
            'src/core/credentials/transport/tls/ssl_utils.cc',
            language='c_cpp',
            signals=[],
            attack_surfaces=set(),
            sink_kinds=set(),
            external_signals=[],
            framework_hints=set(),
        )
        self.assertEqual(exposure, 'trust-material or handshake path')

    def test_native_binding_exposure_is_labeled(self) -> None:
        exposure = _infer_exposure(
            'php/ext/google/protobuf/message.c',
            language='c_cpp',
            signals=[],
            attack_surfaces=set(),
            sink_kinds={'memory-sensitive native path'},
            external_signals=[],
            framework_hints=set(),
        )
        self.assertEqual(exposure, 'language binding or FFI path')

    def test_generated_artifact_profile_is_strongly_penalized(self) -> None:
        profile = _artifact_profile('upb/reflection/stage0/google/protobuf/descriptor.upb.h', '// generated by upbc\n// do not edit\n')
        self.assertTrue(profile['is_severe_generated'])
        self.assertLess(_weighted_signal_value(10, profile), 4)

    def test_generated_artifact_is_not_retained_by_graph_alone(self) -> None:
        profile = _artifact_profile('ruby/ext/google/protobuf_c/ruby-upb.h', '/* generated by ... DO NOT EDIT */')
        reason = _retention_reason(
            score=6,
            signals=[],
            external_signals=[ExternalSignal(source='graph', weight=8, summary='fan-in', metadata={})],
            hot_path_hits=0,
            entrypoint_hits=0,
            focus_hits=0,
            in_degree=8,
            out_degree=0,
            semantic_meta=None,
            generated_profile=profile,
        )
        self.assertFalse(reason)

    def test_generated_artifact_can_only_be_retained_by_direct_strong_evidence(self) -> None:
        profile = _artifact_profile('ruby/ext/google/protobuf_c/ruby-upb.c', '/* generated by ... DO NOT EDIT */')
        reason = _retention_reason(
            score=6,
            signals=[],
            external_signals=[ExternalSignal(source='crash', weight=12, summary='asan crash', metadata={})],
            hot_path_hits=0,
            entrypoint_hits=0,
            focus_hits=0,
            in_degree=0,
            out_degree=0,
            semantic_meta=None,
            generated_profile=profile,
        )
        self.assertTrue(reason)


if __name__ == '__main__':
    unittest.main()
