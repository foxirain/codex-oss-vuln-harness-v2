from pathlib import Path
import json
import tempfile
import unittest

from oss_harness.sbom import load_sbom_signal_index
from oss_harness.targeting import _external_signal_profile, _retention_reason


class SbomAwareTargetingTests(unittest.TestCase):
    def test_sbom_maps_component_to_glue_and_vendor_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'
            repo.mkdir()
            (repo / 'third_party/protobuf').mkdir(parents=True)
            (repo / 'third_party/protobuf/message.c').write_text('int x;', encoding='utf-8')
            (repo / 'php/ext/google/protobuf').mkdir(parents=True)
            (repo / 'php/ext/google/protobuf/message.c').write_text('int y;', encoding='utf-8')
            sbom = repo / 'sbom.json'
            sbom.write_text(json.dumps({'components': [{'name': 'protobuf', 'version': '27.1', 'purl': 'pkg:generic/protobuf@27.1'}]}), encoding='utf-8')
            index = load_sbom_signal_index(repo, sbom)
            self.assertIn('third_party/protobuf/message.c', index)
            self.assertIn('php/ext/google/protobuf/message.c', index)
            glue_signal = index['php/ext/google/protobuf/message.c'][0]
            self.assertEqual(glue_signal.source, 'sbom')
            self.assertTrue(glue_signal.metadata.get('glue_path'))

    def test_sbom_vulnerability_signal_strengthens_retention_profile(self) -> None:
        from oss_harness.models import ExternalSignal
        signals = [
            ExternalSignal(source='sbom', weight=12, summary='sbom vulnerability-linked component', metadata={'vulnerabilities': ['CVE-2026-0001']}),
            ExternalSignal(source='git', weight=4, summary='recent churn', metadata={}),
        ]
        profile = _external_signal_profile(signals)
        self.assertGreaterEqual(profile['total_weight'], 16)
        reason = _retention_reason(
            score=6,
            signals=[],
            external_signals=signals,
            hot_path_hits=0,
            entrypoint_hits=0,
            focus_hits=0,
            in_degree=0,
            out_degree=0,
            semantic_meta=None,
        )
        self.assertTrue(reason)


if __name__ == '__main__':
    unittest.main()
