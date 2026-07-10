import unittest

from oss_harness.ingest import parse_response


class IngestQualityTests(unittest.TestCase):
    def test_parses_exact_inline_verdict(self) -> None:
        parsed = parse_response('Strict verdict: cve_candidate\nSingle best next target: none\nentrypoint: api\nattacker_control: body\nsink: memcpy\nimpact: oob write\nnot blocked by: length is trusted before validation\n')
        self.assertEqual(parsed['verdict'], 'cve_candidate')
        self.assertTrue(parsed['promotion_ready'])

    def test_parses_bullet_verdict(self) -> None:
        parsed = parse_response('Strict verdict:\n- not_cve_candidate\nSingle best next target: none\n')
        self.assertEqual(parsed['verdict'], 'not_cve_candidate')
        self.assertFalse(parsed['promotion_ready'])

    def test_rejects_garbage_verdict_suffix(self) -> None:
        with self.assertRaises(ValueError):
            parse_response('Strict verdict: cve_candidate maybe\nSingle best next target: none\n')

    def test_remains_negative_for_not_cve_candidate(self) -> None:
        parsed = parse_response('Strict verdict: not_cve_candidate\nSingle best next target: none\nentrypoint: api\nattacker_control: body\nsink: blocked\nimpact: none\n')
        self.assertEqual(parsed['verdict'], 'not_cve_candidate')
        self.assertFalse(parsed['promotion_ready'])

    def test_requires_all_structured_fields_for_promotion(self) -> None:
        parsed = parse_response('''Strict verdict: plausible_security_bug
Single best next target: none
entrypoint: ParseFrame
attacker_control: HPACK bytes
sink: memcpy into fixed buffer
impact:
''')
        self.assertEqual(parsed['verdict'], 'plausible_security_bug')
        self.assertFalse(parsed['promotion_ready'])

    def test_rejects_duplicate_verdicts(self) -> None:
        with self.assertRaises(ValueError):
            parse_response('Strict verdict: cve_candidate\nFinal verdict: cve_candidate\n')

    def test_does_not_infer_verdict_from_negative_prose(self) -> None:
        with self.assertRaises(ValueError):
            parse_response('There is insufficient evidence to consider this a CVE candidate.')

    def test_placeholder_proof_fields_do_not_promote(self) -> None:
        parsed = parse_response('Strict verdict: cve_candidate\nSingle best next target: none\nentrypoint: none\nattacker_control: none\nsink: none\nimpact: none\nnot blocked by: none\n')
        self.assertFalse(parsed['promotion_ready'])


if __name__ == '__main__':
    unittest.main()
