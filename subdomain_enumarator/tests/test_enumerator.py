import os
import tempfile
import unittest
from unittest.mock import patch
import socket

from subdomain_enumarator.main import (
    clean_domain,
    check_subdomain,
    load_wordlist,
    enumerate_subdomains,
    DEFAULT_SUBDOMAINS,
)


class TestSubdomainEnumerator(unittest.TestCase):

    def test_clean_domain(self):
        self.assertEqual(clean_domain("example.com"), "example.com")
        self.assertEqual(clean_domain("@example.com"), "example.com")
        self.assertEqual(clean_domain("http://example.com"), "example.com")
        self.assertEqual(clean_domain("https://example.com/path/to/resource"), "example.com")
        self.assertEqual(clean_domain("example.com:8080"), "example.com")
        self.assertEqual(clean_domain("  sub.example.com/  "), "sub.example.com")

    @patch("socket.gethostbyname")
    def test_check_subdomain_success(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "93.184.216.34"
        fqdn, ip = check_subdomain("example.com", "www")
        self.assertEqual(fqdn, "www.example.com")
        self.assertEqual(ip, "93.184.216.34")

    @patch("socket.gethostbyname")
    def test_check_subdomain_not_found(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror(8, "nodename nor servname provided, or not known")
        fqdn, ip = check_subdomain("example.com", "nonexistent")
        self.assertEqual(fqdn, "nonexistent.example.com")
        self.assertIsNone(ip)

    @patch("socket.gethostbyname")
    def test_check_subdomain_timeout(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.timeout("timed out")
        fqdn, ip = check_subdomain("example.com", "slowsub")
        self.assertEqual(fqdn, "slowsub.example.com")
        self.assertIsNone(ip)

    def test_load_wordlist_fallback_nonexistent(self):
        words = load_wordlist("/nonexistent/path/words.txt")
        self.assertEqual(words, DEFAULT_SUBDOMAINS)

    def test_load_wordlist_custom_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write("# comment\nalpha\nbeta\n\ngamma\n")
            tmp_path = tmp.name

        try:
            words = load_wordlist(tmp_path)
            self.assertEqual(words, ["alpha", "beta", "gamma"])
        finally:
            os.remove(tmp_path)

    @patch("socket.gethostbyname")
    def test_enumerate_subdomains(self, mock_gethostbyname):
        def fake_resolver(fqdn):
            if fqdn == "www.example.com":
                return "1.1.1.1"
            elif fqdn == "api.example.com":
                return "2.2.2.2"
            raise socket.gaierror("not found")

        mock_gethostbyname.side_effect = fake_resolver

        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp_out:
            out_file = tmp_out.name

        try:
            test_wordlist = ["www", "api", "fake1", "fake2"]
            discovered = enumerate_subdomains(
                domain="example.com",
                wordlist=test_wordlist,
                threads=4,
                output_file=out_file,
            )

            discovered_dict = dict(discovered)
            self.assertEqual(len(discovered), 2)
            self.assertEqual(discovered_dict.get("www.example.com"), "1.1.1.1")
            self.assertEqual(discovered_dict.get("api.example.com"), "2.2.2.2")

            # Check output file contents
            with open(out_file, "r") as f:
                content = f.read()
            self.assertIn("www.example.com -> 1.1.1.1", content)
            self.assertIn("api.example.com -> 2.2.2.2", content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)


if __name__ == "__main__":
    unittest.main()

