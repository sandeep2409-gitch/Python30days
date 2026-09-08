import unittest
from password_analyzer.analyzer import PasswordAnalyzer
from password_analyzer.models import Severity, StrengthRating


class TestPasswordAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_known_leaked_password(self):
        res = self.analyzer.analyze("password")
        self.assertIn(res.rating, [StrengthRating.VERY_WEAK, StrengthRating.WEAK])
        has_leak_alert = any(f.severity == Severity.CRITICAL and "breach" in f.message for f in res.findings)
        self.assertTrue(has_leak_alert)
        self.assertEqual(res.crack_estimates.offline_gpu, "Instant (< 1 millisecond)")

    def test_truly_random_strong_password(self):
        # 16 characters, all pools used, no dictionary or sequences
        res = self.analyzer.analyze("vN8$qL2!kX9#mZ5@")
        self.assertEqual(res.rating, StrengthRating.VERY_STRONG)
        self.assertGreater(res.effective_entropy, 85)
        self.assertIn("Trillions", res.crack_estimates.offline_gpu)

    def test_passphrase_high_entropy(self):
        res = self.analyzer.analyze("correct horse battery staple")
        self.assertEqual(res.rating, StrengthRating.VERY_STRONG)
        self.assertGreater(res.length, 20)

    def test_empty_password(self):
        res = self.analyzer.analyze("")
        self.assertEqual(res.rating, StrengthRating.VERY_WEAK)
        self.assertEqual(res.effective_entropy, 0.0)


if __name__ == "__main__":
    unittest.main()
