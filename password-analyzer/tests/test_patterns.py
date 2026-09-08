import unittest
from password_analyzer.patterns import detect_patterns, normalize_leetspeak
from password_analyzer.models import Severity


class TestPatterns(unittest.TestCase):
    def test_normalize_leetspeak(self):
        self.assertEqual(normalize_leetspeak("P@ssw0rd"), "password")
        self.assertEqual(normalize_leetspeak("M0n3y!"), "moneyi")
        self.assertEqual(normalize_leetspeak("4dm1n"), "admin")

    def test_detect_keyboard_sequence(self):
        findings, penalty = detect_patterns("safeqwerty123")
        seq_found = any("Sequential keyboard" in f.message for f in findings)
        self.assertTrue(seq_found)
        self.assertGreater(penalty, 0)

    def test_detect_repetition(self):
        findings, penalty = detect_patterns("aaaa12345678")
        repeat_found = any("repeated character sequence" in f.message for f in findings)
        self.assertTrue(repeat_found)

    def test_detect_dictionary_word_in_leetspeak(self):
        findings, penalty = detect_patterns("mypassw0rd!")
        dict_found = any("l33tspeak substitution" in f.message for f in findings)
        self.assertTrue(dict_found)

    def test_short_password_critical_warning(self):
        findings, penalty = detect_patterns("abc")
        critical_found = any(f.severity == Severity.CRITICAL and "too short" in f.message for f in findings)
        self.assertTrue(critical_found)


if __name__ == "__main__":
    unittest.main()
