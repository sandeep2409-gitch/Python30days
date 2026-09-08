import unittest
from password_analyzer.entropy import calculate_entropy


class TestEntropy(unittest.TestCase):
    def test_empty_string(self):
        entropy, pool, flags = calculate_entropy("")
        self.assertEqual(entropy, 0.0)
        self.assertEqual(pool, 0)
        self.assertFalse(any(flags.values()))

    def test_lowercase_only(self):
        # 8 characters, pool of 26 (a-z). log2(26) ~= 4.700439718
        # 8 * 4.700439718 ~= 37.6035 bits
        entropy, pool, flags = calculate_entropy("abcdefgh")
        self.assertEqual(pool, 26)
        self.assertAlmostEqual(entropy, 37.60, places=1)
        self.assertTrue(flags["lowercase"])
        self.assertFalse(flags["uppercase"])
        self.assertFalse(flags["digits"])
        self.assertFalse(flags["symbols"])

    def test_full_pool(self):
        # lower (26) + upper (26) + digit (10) + symbol (32) = 94
        pwd = "A1!a"
        entropy, pool, flags = calculate_entropy(pwd)
        self.assertEqual(pool, 94)
        self.assertTrue(flags["lowercase"])
        self.assertTrue(flags["uppercase"])
        self.assertTrue(flags["digits"])
        self.assertTrue(flags["symbols"])

    def test_spaces_included(self):
        pwd = "hello world"
        entropy, pool, flags = calculate_entropy(pwd)
        self.assertTrue(flags["spaces"])
        self.assertEqual(pool, 27)  # 26 lowercase + 1 space


if __name__ == "__main__":
    unittest.main()
