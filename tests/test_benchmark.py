import json
import tempfile
from pathlib import Path
import unittest

from oss_harness.benchmark import run_benchmark_modes


POLICY = """# Project Policy

## Project Summary
- test repo

## In Scope
- parser bugs

## Out of Scope
- docs only

## Focus Areas
- parser

## Forbidden Findings
- test only

## Entry Points
- parser

## Include Paths
- src/

## Exclude Paths
- tests/

## Languages
- c++

## Framework Hints
- none

## Hot Paths
- src/

## Preferred Sinks
- memory-sensitive native path

## Preferred Bug Classes
- oob write

## Ignore Patterns
- generated/

## Notes
- test corpus
"""


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_modes_compares_three_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            (repo / 'src').mkdir(parents=True)
            (repo / 'src' / 'parser.cc').write_text('int parse(const char* in) { char buf[8]; memcpy(buf, in, 16); return 0; }\n', encoding='utf-8')
            (repo / '.codex-harness.md').write_text(POLICY, encoding='utf-8')
            (repo / 'external_signals_test.json').write_text(json.dumps({
                'signals': [
                    {'path': 'src/parser.cc', 'source': 'advisory', 'weight': 9, 'summary': 'recent parser fix'}
                ]
            }), encoding='utf-8')
            corpus = root / 'benchmark.json'
            corpus.write_text(json.dumps({
                'top_k': 5,
                'limit': 20,
                'cases': [
                    {
                        'name': 'demo',
                        'repo_root': str(repo),
                        'known_good': ['src/parser.cc'],
                        'known_bad': [],
                    }
                ]
            }), encoding='utf-8')
            result = run_benchmark_modes(corpus)
            self.assertEqual(result['aggregate']['cases'], 1)
            self.assertIn('blind', result['cases'][0]['modes'])
            self.assertIn('signal', result['cases'][0]['modes'])
            self.assertIn('dual', result['cases'][0]['modes'])
            self.assertIsNotNone(result['analysis']['best_mode_by_labeled_precision'])


if __name__ == '__main__':
    unittest.main()
