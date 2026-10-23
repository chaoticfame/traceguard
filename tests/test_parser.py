"""Regression checks for parsing, bounds, timestamps, and the real CLI."""

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from traceguard.parser import parse_line

LINE = "Oct  8 09:10:11 lab sshd[123]: Failed password for invalid user demo from 192.0.2.10 port 2222 ssh2"
ISO_LINE = "2026-12-31T23:59:59-02:00 lab sshd[123]: Failed password for invalid user demo from 192.0.2.10 port 2222 ssh2"
ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_failure(self):
        event = parse_line(LINE, year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failure")
        self.assertEqual(event.username, "demo")
        self.assertEqual(event.source_port, 2222)

    def test_ipv6_publickey_success(self):
        line = "Oct  8 09:10:11 lab sshd[9]: Accepted publickey for demo from 2001:db8::1 port 22 ssh2: ED25519 SHA256:example"
        event = parse_line(line, year=2026)
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_timestamp_context(self):
        event = parse_line(LINE, year=2026, utc_offset_minutes=480)
        self.assertEqual(event.timestamp, "2026-10-08T01:10:11+00:00")

    def test_iso_timestamp_uses_embedded_context(self):
        event = parse_line(ISO_LINE, year=2000, utc_offset_minutes=480)
        same = parse_line(ISO_LINE, year=1999, utc_offset_minutes=-300)
        self.assertEqual(event.timestamp, "2027-01-01T01:59:59+00:00")
        self.assertEqual(event.event_id, same.event_id)

    def test_iso_offset_year_rollover_boundaries(self):
        cases = {
            "2026-12-31T23:59:59-14:00": "2027-01-01T13:59:59+00:00",
            "2027-01-01T00:00:00+14:00": "2026-12-31T10:00:00+00:00",
        }
        for stamp, expected in cases.items():
            with self.subTest(stamp=stamp):
                event = parse_line(
                    ISO_LINE.replace("2026-12-31T23:59:59-02:00", stamp),
                    year=2026,
                )
                self.assertEqual(event.timestamp, expected)

    def test_stable_identifier(self):
        self.assertEqual(parse_line(LINE, year=2026).event_id,
                         parse_line(LINE + "\r\n", year=2026).event_id)
        self.assertNotEqual(parse_line(LINE, year=2026).event_id,
                            parse_line(LINE, year=2025).event_id)

    def test_malformed_records(self):
        for line in ("noise", LINE.replace("192.0.2.10", "bad-ip"),
                     LINE.replace("2222", "65536"), LINE.replace("2222", "0"),
                     LINE.replace("Oct  8", "Feb 30"), LINE + "\x00", "x" * 8193):
            with self.subTest(line=line[:80]):
                self.assertIsNone(parse_line(line, year=2026))

    def test_rejects_noncanonical_or_invalid_iso_timestamps(self):
        replacements = (
            "2026-12-31T23:59:59", "2026-12-31T23:59:59Z",
            "2026-12-31T23:59:59.1-02:00", "2026-12-31 23:59:59-02:00",
            "2026-02-30T23:59:59-02:00", "2026-12-31T23:59:59+14:01",
            "2026-12-31T23:59:59-15:00",
        )
        for stamp in replacements:
            with self.subTest(stamp=stamp):
                line = ISO_LINE.replace("2026-12-31T23:59:59-02:00", stamp)
                self.assertIsNone(parse_line(line, year=2026))

    def test_invalid_context(self):
        for kwargs in ({"year": 0}, {"year": 2026, "utc_offset_minutes": 1440}):
            with self.assertRaises(ValueError):
                parse_line(LINE, **kwargs)

    def test_cli(self):
        result = subprocess.run(
            [sys.executable, "-m", "traceguard", "examples/auth.log", "--year", "2026"],
            cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 3)
        self.assertEqual(json.loads(result.stdout.splitlines()[0])["outcome"], "failure")
        self.assertIn("parsed=3 skipped=1", result.stderr)

    def test_iso_cli_fixture(self):
        result = subprocess.run(
            [sys.executable, "-m", "traceguard", "examples/auth-iso.log",
             "--year", "2000", "--utc-offset-minutes", "480"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["timestamp"], "2027-01-01T01:59:50+00:00")
        self.assertIn("parsed=3 skipped=0", result.stderr)

    def test_cli_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-m", "traceguard", str(Path(directory) / "missing.log"),
                 "--year", "2026"], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)

    def test_cli_oversized_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("x" * 20000 + "\n" + LINE + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "traceguard", str(path), "--year", "2026"],
                cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("parsed=1 skipped=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
