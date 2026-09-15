import unittest

from nodelogmedic.diagnose import DiagnosisConfig, diagnose_lines
from nodelogmedic.explain import explain_local
from nodelogmedic.redact import redact_line
from nodelogmedic.render import render_text


class MedicTests(unittest.TestCase):
    def test_redacts_sensitive_shapes(self) -> None:
        raw = "rpc=https://user:pass@example.test jwt=abc /home/alice/node 192.0.2.10 0x" + "ab" * 20
        safe, count = redact_line(raw)
        self.assertGreaterEqual(count, 4)
        self.assertNotIn("alice", safe)
        self.assertNotIn("192.0.2.10", safe)
        self.assertNotIn("user:pass", safe)
        self.assertNotIn("0xabab", safe)
        self.assertNotIn("abc", safe)

    def test_redacts_structured_and_quoted_credentials(self) -> None:
        raw = (
            '{"password":"correct horse battery staple",'
            '"access_token":"structured-secret"} '
            'client_secret="two word secret"'
        )
        safe, count = redact_line(raw)
        self.assertEqual(count, 3)
        self.assertNotIn("correct horse", safe)
        self.assertNotIn("structured-secret", safe)
        self.assertNotIn("two word secret", safe)

    def test_redacts_plain_and_structured_authorization(self) -> None:
        raw = (
            'authorization: Basic dXNlcjpwYXNz '
            'headers={"Authorization":"Bearer header.payload.signature"}'
        )
        safe, count = redact_line(raw)
        self.assertEqual(count, 2)
        self.assertNotIn("dXNlcjpwYXNz", safe)
        self.assertNotIn("header.payload.signature", safe)

    def test_redacts_before_line_length_bound(self) -> None:
        raw = "x" * 240 + ' password="first secret second secret"'
        safe, count = redact_line(raw, max_length=256)
        self.assertEqual(count, 1)
        self.assertLessEqual(len(safe), 256)
        self.assertNotIn("first secret", safe)

    def test_diagnoses_after_redaction(self) -> None:
        report = diagnose_lines([
            "ERROR no beacon client seen peer=192.0.2.1 jwt=/secret/jwt.hex\n",
            "WARN looking for peers url=https://node.example.invalid\n",
            "WARN looking for peers url=https://node.example.invalid\n",
        ])
        ids = [finding["rule_id"] for finding in report["findings"]]
        self.assertEqual(ids, ["consensus-disconnected", "peer-connectivity"])
        self.assertEqual(report["summary"]["redactions"], 4)
        self.assertEqual(report["findings"][1]["occurrences"], 2)
        self.assertNotIn("192.0.2.1", str(report))

    def test_evidence_is_bounded(self) -> None:
        report = diagnose_lines(["no space left on device\n"] * 10, DiagnosisConfig(max_evidence=2))
        finding = report["findings"][0]
        self.assertEqual(finding["occurrences"], 10)
        self.assertEqual(len(finding["evidence"]), 2)

    def test_clean_input_has_stable_board(self) -> None:
        report = diagnose_lines(["INFO imported new chain segment\n"])
        board = render_text(report)
        self.assertIn("No known symptom rules matched", board)
        self.assertEqual(report["summary"]["findings"], 0)

    def test_config_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_evidence"):
            DiagnosisConfig(max_evidence=0)

    def test_ai_endpoint_must_be_loopback(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            explain_local({}, "https://example.com", "model")


if __name__ == "__main__":
    unittest.main()
