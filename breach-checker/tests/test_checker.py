"""Unit tests for breach_checker package."""

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

# Ensure src is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from breach_checker.client import HIBPClient, XposedOrNotClient, get_client
from breach_checker.models import BreachRecord, CheckResult, ScanSummary, Status
from breach_checker.scanner import (
    export_results,
    export_to_csv,
    export_to_json,
    export_to_text,
    load_targets_from_file,
    scan_targets,
)


class TestModels(unittest.TestCase):
    def test_breach_record_to_dict(self):
        record = BreachRecord(
            name="Adobe",
            title="Adobe Systems",
            domain="adobe.com",
            breach_date="2013-10-04",
            pwn_count=152445165,
            data_classes=["Email addresses", "Passwords"],
            description="Compromised credentials.",
        )
        d = record.to_dict()
        self.assertEqual(d["name"], "Adobe")
        self.assertEqual(d["pwn_count"], 152445165)
        self.assertEqual(len(d["data_classes"]), 2)

    def test_check_result_properties(self):
        b1 = BreachRecord(name="Service1")
        b2 = BreachRecord(name="Service2")
        res = CheckResult(
            account="victim@example.com",
            provider="xposedornot",
            status=Status.BREACHED,
            breaches=[b1, b2],
            response_time=0.45,
        )
        self.assertTrue(res.is_breached)
        self.assertEqual(res.breach_count, 2)
        d = res.to_dict()
        self.assertEqual(d["account"], "victim@example.com")
        self.assertEqual(d["status"], "BREACHED")
        self.assertEqual(d["breach_count"], 2)

    def test_scan_summary_aggregation(self):
        summary = ScanSummary()
        summary.add_result(CheckResult("a@example.com", "xposedornot", Status.BREACHED, [BreachRecord(name="B1")]))
        summary.add_result(CheckResult("b@example.com", "xposedornot", Status.CLEAN))
        summary.add_result(CheckResult("c@example.com", "xposedornot", Status.ERROR, error_message="Network fail"))

        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.breached, 1)
        self.assertEqual(summary.clean, 1)
        self.assertEqual(summary.errors, 1)


class TestXposedOrNotClient(unittest.TestCase):
    def setUp(self):
        self.client = XposedOrNotClient()

    def test_username_without_at_returns_error(self):
        res = self.client.check("admin_user")
        self.assertEqual(res.status, Status.ERROR)
        self.assertIn("only supports email", res.error_message)

    @patch("urllib.request.urlopen")
    def test_breached_nested_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({
            "breaches": [["Adobe", "LinkedIn"]],
            "email": "victim@example.com",
            "status": "success",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.check("victim@example.com")
        self.assertEqual(res.status, Status.BREACHED)
        self.assertEqual(res.breach_count, 2)
        names = [b.name for b in res.breaches]
        self.assertIn("Adobe", names)
        self.assertIn("LinkedIn", names)

    @patch("urllib.request.urlopen")
    def test_clean_response_with_error_not_found(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({
            "Error": "Not found",
            "email": None,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.check("clean@example.com")
        self.assertEqual(res.status, Status.CLEAN)
        self.assertEqual(res.breach_count, 0)

    @patch("urllib.request.urlopen")
    def test_clean_response_http_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=404, msg="Not Found", hdrs={}, fp=None
        )
        res = self.client.check("safe@example.com")
        self.assertEqual(res.status, Status.CLEAN)

    @patch("urllib.request.urlopen")
    def test_rate_limited_http_429(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=429, msg="Too Many Requests", hdrs={}, fp=None
        )
        res = self.client.check("test@example.com")
        self.assertEqual(res.status, Status.ERROR)
        self.assertIn("Rate limited", res.error_message)


class TestHIBPClient(unittest.TestCase):
    def test_missing_api_key_returns_error(self):
        client = HIBPClient(api_key=None)
        res = client.check("test@example.com")
        self.assertEqual(res.status, Status.ERROR)
        self.assertIn("Missing HIBP API key", res.error_message)

    @patch("urllib.request.urlopen")
    def test_breached_response(self, mock_urlopen):
        client = HIBPClient(api_key="test_key_123")
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps([
            {
                "Name": "Dropbox",
                "Title": "Dropbox Cloud",
                "Domain": "dropbox.com",
                "BreachDate": "2012-07-01",
                "PwnCount": 68000000,
                "DataClasses": ["Email addresses", "Passwords"],
            }
        ]).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = client.check("victim@example.com")
        self.assertEqual(res.status, Status.BREACHED)
        self.assertEqual(res.breach_count, 1)
        self.assertEqual(res.breaches[0].name, "Dropbox")
        self.assertEqual(res.breaches[0].pwn_count, 68000000)

    @patch("urllib.request.urlopen")
    def test_clean_response_http_404(self, mock_urlopen):
        client = HIBPClient(api_key="test_key_123")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=404, msg="Not Found", hdrs={}, fp=None
        )
        res = client.check("clean@example.com")
        self.assertEqual(res.status, Status.CLEAN)

    @patch("urllib.request.urlopen")
    def test_unauthorized_http_401(self, mock_urlopen):
        client = HIBPClient(api_key="invalid_key")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=401, msg="Unauthorized", hdrs={}, fp=None
        )
        res = client.check("test@example.com")
        self.assertEqual(res.status, Status.ERROR)
        self.assertIn("HTTP 401", res.error_message)


class TestClientFactory(unittest.TestCase):
    def test_get_client_auto_without_key(self):
        client = get_client("auto", api_key=None)
        self.assertIsInstance(client, XposedOrNotClient)

    def test_get_client_auto_with_key(self):
        client = get_client("auto", api_key="my_hibp_key")
        self.assertIsInstance(client, HIBPClient)

    def test_get_client_explicit_xposedornot(self):
        client = get_client("xposedornot")
        self.assertIsInstance(client, XposedOrNotClient)

    def test_get_client_invalid_raises(self):
        with self.assertRaises(ValueError):
            get_client("nonexistent_provider")


class TestScannerAndExporters(unittest.TestCase):
    def test_load_targets_text_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write("# comment\nalpha@example.com\n\nbeta@example.com\nalpha@example.com\n")
            tmp_path = tmp.name

        try:
            targets = load_targets_from_file(tmp_path)
            self.assertEqual(targets, ["alpha@example.com", "beta@example.com"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_load_targets_csv_file(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as tmp:
            tmp.write("ID,Email,Role\n1,user1@example.com,Admin\n2,user2@example.com,User\n")
            tmp_path = tmp.name

        try:
            targets = load_targets_from_file(tmp_path)
            self.assertEqual(targets, ["user1@example.com", "user2@example.com"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_scan_targets_execution(self):
        mock_client = MagicMock()
        mock_client.check.side_effect = [
            CheckResult("user1@example.com", "mock", Status.BREACHED, [BreachRecord("BreachA")]),
            CheckResult("user2@example.com", "mock", Status.CLEAN),
        ]

        progress_calls = []
        def on_prog(idx, tot, tgt, res):
            progress_calls.append((idx, tot, tgt))

        summary = scan_targets(
            targets=["user1@example.com", "user2@example.com"],
            client=mock_client,
            delay_seconds=0.0,
            on_progress=on_prog,
        )

        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.breached, 1)
        self.assertEqual(summary.clean, 1)
        self.assertEqual(len(progress_calls), 2)

    def test_export_formats(self):
        summary = ScanSummary(total=1, breached=1, clean=0, errors=0, duration_seconds=1.23)
        b = BreachRecord(name="TestLeak", breach_date="2022-01-01", data_classes=["Emails"])
        summary.results.append(CheckResult("leak@example.com", "mock", Status.BREACHED, [b]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = os.path.join(tmp_dir, "out.json")
            csv_path = os.path.join(tmp_dir, "out.csv")
            txt_path = os.path.join(tmp_dir, "out.txt")

            export_results(summary, json_path)
            export_results(summary, csv_path)
            export_results(summary, txt_path)

            # Check JSON
            with open(json_path, "r") as f:
                data = json.load(f)
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["breached"], 1)

            # Check CSV
            with open(csv_path, "r") as f:
                content = f.read()
            self.assertIn("leak@example.com", content)
            self.assertIn("TestLeak", content)

            # Check TXT
            with open(txt_path, "r") as f:
                content = f.read()
            self.assertIn("BREACH CHECKER SCAN REPORT", content)
            self.assertIn("leak@example.com", content)


if __name__ == "__main__":
    unittest.main()
