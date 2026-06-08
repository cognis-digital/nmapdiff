"""Smoke tests for nmapdiff. Standard library only, no network."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapdiff import TOOL_NAME, TOOL_VERSION  # noqa: E402
from nmapdiff.cli import main  # noqa: E402
from nmapdiff.core import diff_scans, parse_scan  # noqa: E402


BASELINE = """<?xml version="1.0"?>
<nmaprun args="nmap -sV host" startstr="now">
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

CURRENT = """<?xml version="1.0"?>
<nmaprun args="nmap -sV host" startstr="later">
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.27.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.27.0"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.12" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestParsing(unittest.TestCase):
    def test_parse_tracks_only_open_ports(self):
        report = parse_scan(BASELINE)
        self.assertIn("10.0.0.10", report.hosts)
        host = report.hosts["10.0.0.10"]
        # 22 and 80 are open; 443 is closed and must be skipped.
        self.assertEqual(set(host.ports), {("tcp", 22), ("tcp", 80)})
        self.assertEqual(report.open_port_count(), 2)

    def test_parse_rejects_non_nmap_xml(self):
        with self.assertRaises(ValueError):
            parse_scan("<rootthing><a/></rootthing>")

    def test_parse_rejects_invalid_xml(self):
        with self.assertRaises(ValueError):
            parse_scan("<not closed")


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.diff = diff_scans(parse_scan(BASELINE), parse_scan(CURRENT))

    def test_has_findings(self):
        self.assertTrue(self.diff.has_findings())

    def test_new_host_detected(self):
        kinds = {(h.kind, h.address) for h in self.diff.host_changes}
        self.assertIn(("new_host", "10.0.0.12"), kinds)

    def test_new_and_changed_ports(self):
        by = {}
        for p in self.diff.port_changes:
            by.setdefault(p.kind, set()).add((p.address, p.portid))
        # 443 newly opened on .10, plus all ports on the new host .12
        self.assertIn(("10.0.0.10", 443), by["new_port"])
        self.assertIn(("10.0.0.12", 23), by["new_port"])
        # nginx version bump on port 80
        self.assertIn(("10.0.0.10", 80), by["service_change"])

    def test_identical_scans_have_no_findings(self):
        same = diff_scans(parse_scan(BASELINE), parse_scan(BASELINE))
        self.assertFalse(same.has_findings())

    def test_summary_counts(self):
        s = self.diff.summary()
        self.assertEqual(
            s["total_findings"],
            len(self.diff.host_changes) + len(self.diff.port_changes),
        )


class TestCLI(unittest.TestCase):
    def _write(self, tmpdir, name, content):
        path = os.path.join(tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "nmapdiff")
        self.assertTrue(TOOL_VERSION)

    def test_cli_exit_1_on_findings_json(self):
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            b = self._write(tmp, "b.xml", BASELINE)
            c = self._write(tmp, "c.xml", CURRENT)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["diff", b, c, "--format", "json"])
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["tool"], "nmapdiff")
            self.assertGreater(payload["diff"]["summary"]["total_findings"], 0)

    def test_cli_exit_0_on_no_changes(self):
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            b = self._write(tmp, "b.xml", BASELINE)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["diff", b, b])
            self.assertEqual(rc, 0)

    def test_cli_exit_2_on_missing_file(self):
        rc = main(["diff", "/no/such/baseline.xml", "/no/such/current.xml"])
        self.assertEqual(rc, 2)

    def test_cli_no_command_returns_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
