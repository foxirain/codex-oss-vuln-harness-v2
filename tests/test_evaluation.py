import json
import tempfile
from pathlib import Path
import unittest

from oss_harness.evaluation import run_eval_corpus


class EvaluationTests(unittest.TestCase):
    def test_eval_corpus_computes_precision_and_promotion_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / 'session'
            (session / 'autopilot' / 'findings').mkdir(parents=True)
            (session / 'review').mkdir(parents=True)
            (session / 'targets.json').write_text(json.dumps({
                'candidates': [
                    {'path': 'src/good.cc'},
                    {'path': 'src/noisy.cc'},
                ]
            }), encoding='utf-8')
            (session / 'autopilot' / 'findings' / 'finding-1.txt').write_text('x', encoding='utf-8')
            (session / 'review' / 'review_index.json').write_text(json.dumps({
                'reviews': [
                    {
                        'finding_file': 'finding-1.txt', 'title': 'Bounds violation',
                        'tier': 'A', 'confidence': 'high', 'disposition': 'strong',
                        'summary': 'Attacker bytes reach a fixed-size copy.',
                        'entrypoint': 'parse', 'reachability': 'public parser API',
                        'attacker_control': 'input bytes', 'sink': 'memcpy',
                        'impact': 'out-of-bounds write', 'key_evidence': ['src/good.cc:1'],
                        'blocking_gaps': [], 'next_actions': ['build repro'],
                    },
                ]
            }), encoding='utf-8')
            corpus = root / 'corpus.json'
            corpus.write_text(json.dumps({
                'cases': [
                    {
                        'name': 'demo',
                        'session_dir': str(session),
                        'known_good': ['src/good.cc'],
                        'known_bad': ['src/noisy.cc'],
                        'top_k': 2,
                    }
                ]
            }), encoding='utf-8')
            result = run_eval_corpus(corpus)
            self.assertEqual(result['aggregate']['cases'], 1)
            self.assertEqual(result['cases'][0]['known_good_hits'], ['src/good.cc'])
            self.assertEqual(result['cases'][0]['known_bad_hits'], ['src/noisy.cc'])
            self.assertEqual(result['cases'][0]['review_confirmation_rate'], 1.0)


if __name__ == '__main__':
    unittest.main()
