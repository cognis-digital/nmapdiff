"""Hardening tests: error handling, edge cases, and bad input paths.

Standard library only, no network.  All tests are independent and
do not modify any shared state.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapdiff.cli import main  # noqa: E402
from nmapdiff.core import (  # noqa: E402
    ScanReport,
    diff_scans,
    parse_scan,
    parse_scan_file,
)


# ---------------------------------------------------------------------------
# Minimal valid nmap XML used by several tests
# ---------------------------------------------------------------------------
_MINIMAL_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV host" startstr="now">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_EMPTY_NMAPRUN = '<?xml version="1.0"?><nmaprun args="" startstr=""/>'


class TestParseScanEdgeCases(unittest.TestCase):
    """parse_scan() should raise ValueError for bad inputs, not crash."""

    def test_empty_string_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_scan("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_scan("   \n\t  ")

    def test_non_string_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_scan(None)  # type: ignore[arg-type]
        self.assertIn("str", str(ctx.exception))

    def test_non_string_bytes_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_scan(b"<nmaprun/>")  # type: ignore[arg-type]

    def test_empty_nmaprun_returns_empty_report(self):
        report = parse_scan(_EMPTY_NMAPRUN)
        self.assertIsInstance(report, ScanReport)
        self.assertEqual(len(report.hosts), 0)
        self.assertEqual(report.open_port_count(), 0)

    def test_nmaprun_with_no_hosts(self):
        xml = '<?xml version="1.0"?><nmaprun args="" startstr=""><host/></nmaprun>'
        # <host> with no <address> should be silently skipped
        report = parse_scan(xml)
        self.assertEqual(len(report.hosts), 0)

    def test_port_with_no_portid_skipped(self):
        xml = """<?xml version="1.0"?>
<nmaprun args="" startstr="">
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="not-a-number">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        report = parse_scan(xml)
        host = report.hosts["1.2.3.4"]
        # invalid portid silently skipped; valid one kept
        self.assertIn(("tcp", 22), host.ports)
        self.assertEqual(len(host.ports), 1)

    def test_truncated_xml_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_scan("<nmaprun><host")
        self.assertIn("invalid XML", str(ctx.exception))


class TestParseScanFile(unittest.TestCase):
    """parse_scan_file() should surface clean errors for I/O problems."""

    def test_missing_file_raises_os_error(self):
        with self.assertRaises(OSError):
            parse_scan_file("/no/such/path/scan.xml")

    def test_binary_file_raises_value_error(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            # Write bytes that are not valid UTF-8
            tmp.write(b"\xff\xfe binary garbage \x00\x01\x02")
            tmp_path = tmp.name
        try:
            with self.assertRaises(ValueError) as ctx:
                parse_scan_file(tmp_path)
            self.assertIn("UTF-8", str(ctx.exception))
        finally:
            os.unlink(tmp_path)

    def test_valid_file_parses_correctly(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", encoding="utf-8", delete=False
        ) as tmp:
            tmp.write(_MINIMAL_XML)
            tmp_path = tmp.name
        try:
            report = parse_scan_file(tmp_path)
            self.assertIn("192.168.1.1", report.hosts)
        finally:
            os.unlink(tmp_path)


class TestDiffEdgeCases(unittest.TestCase):
    """diff_scans() with empty or symmetric inputs."""

    def test_both_empty_no_findings(self):
        empty = ScanReport()
        diff = diff_scans(empty, empty)
        self.assertFalse(diff.has_findings())
        self.assertEqual(diff.summary()["total_findings"], 0)

    def test_empty_baseline_all_new(self):
        report = parse_scan(_MINIMAL_XML)
        diff = diff_scans(ScanReport(), report)
        kinds = {h.kind for h in diff.host_changes}
        self.assertIn("new_host", kinds)
        port_kinds = {p.kind for p in diff.port_changes}
        self.assertIn("new_port", port_kinds)

    def test_empty_current_all_removed(self):
        report = parse_scan(_MINIMAL_XML)
        diff = diff_scans(report, ScanReport())
        kinds = {h.kind for h in diff.host_changes}
        self.assertIn("removed_host", kinds)

    def test_identical_reports_no_findings(self):
        report = parse_scan(_MINIMAL_XML)
        diff = diff_scans(report, report)
        self.assertFalse(diff.has_findings())

    def test_to_dict_structure(self):
        report = parse_scan(_MINIMAL_XML)
        diff = diff_scans(ScanReport(), report)
        d = diff.to_dict()
        self.assertIn("summary", d)
        self.assertIn("host_changes", d)
        self.assertIn("port_changes", d)
        self.assertIn("total_findings", d["summary"])
        self.assertIn("by_kind", d["summary"])


class TestCLIHardeningPaths(unittest.TestCase):
    """CLI returns exit 2 with a message on stderr for bad input."""

    def _write(self, tmpdir: str, name: str, content: str) -> str:
        path = os.path.join(tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_missing_baseline_returns_2_with_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = self._write(tmp, "c.xml", _MINIMAL_XML)
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", "/no/such/baseline.xml", current])
            self.assertEqual(rc, 2)
            self.assertIn("error", err.getvalue().lower())

    def test_missing_current_returns_2_with_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = self._write(tmp, "b.xml", _MINIMAL_XML)
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", baseline, "/no/such/current.xml"])
            self.assertEqual(rc, 2)
            self.assertIn("error", err.getvalue().lower())

    def test_malformed_xml_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = self._write(tmp, "bad.xml", "<this is not xml <<<")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", bad, bad])
            self.assertEqual(rc, 2)

    def test_non_nmap_xml_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = self._write(tmp, "wrong.xml", "<html><body/></html>")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", wrong, wrong])
            self.assertEqual(rc, 2)

    def test_binary_file_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin.xml")
            with open(path, "wb") as fh:
                fh.write(b"\xff\xfe not xml \x00\x01")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", path, path])
            self.assertEqual(rc, 2)

    def test_empty_file_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = self._write(tmp, "empty.xml", "")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["diff", empty, empty])
            self.assertEqual(rc, 2)

    def test_no_command_returns_2(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_json_format_on_empty_scans(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            empty_xml = self._write(tmp, "empty.xml", _EMPTY_NMAPRUN)
            buf = io.StringIO()
            from contextlib import redirect_stdout

            with redirect_stdout(buf):
                rc = main(["diff", empty_xml, empty_xml, "--format", "json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["diff"]["summary"]["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
