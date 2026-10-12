"""End-to-end checks for deterministic, bounded triage output."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAILURES = [
    "Oct  8 09:10:11 lab sshd[1]: Failed password for invalid user demo from 192.0.2.10 port 2201 ssh2",
    "Oct  8 09:10:21 lab sshd[2]: Failed password for invalid user demo from 192.0.2.10 port 2202 ssh2",
    "Oct  8 09:10:31 lab sshd[3]: Failed password for invalid user demo from 192.0.2.10 port 2203 ssh2",
]
SUCCESS = "Oct  8 09:11:00 lab sshd[4]: Accepted password for demo from 192.0.2.10 port 2204 ssh2"
NOISE = "Oct  8 09:11:01 lab sshd[4]: pam_unix(sshd:session): session opened"


def _triage(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    """Run the installed module exactly as an operator would."""
    return subprocess.run(
        [sys.executable, "-m", "traceguard", "triage", str(path),
         "--year", "2026", *extra],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


class TriageCliTests(unittest.TestCase):
    def _write_log(self, directory: str, lines: list[str]) -> Path:
        path = Path(directory) / "auth.log"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_emits_burst_and_success_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_log(directory, [*FAILURES, SUCCESS, NOISE])
            result = _triage(path, "--failure-threshold", "3")

        self.assertEqual(result.returncode, 0, result.stderr)
        findings = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([item["finding_type"] for item in findings],
                         ["failure_burst", "success_after_failure"])
        self.assertEqual(findings[0]["failure_count"], 3)
        self.assertEqual(findings[1]["burst_finding_id"], findings[0]["finding_id"])
        self.assertEqual(findings[1]["evidence_ids"][:-1],
                         findings[0]["evidence_ids"])
        self.assertIn(
            "parsed=4 skipped=1 failure_bursts=1 success_after_failure=1",
            result.stderr,
        )

    def test_output_is_stable_for_reordered_input(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self._write_log(directory, [*FAILURES, SUCCESS])
            first_result = _triage(first, "--failure-threshold", "3")
            second = Path(directory) / "reordered.log"
            second.write_text(
                "\n".join([SUCCESS, *reversed(FAILURES)]) + "\n",
                encoding="utf-8",
            )
            second_result = _triage(second, "--failure-threshold", "3")

        self.assertEqual(first_result.returncode, 0, first_result.stderr)
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        self.assertEqual(first_result.stdout, second_result.stdout)

    def test_default_policy_can_return_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_log(directory, [*FAILURES, SUCCESS])
            result = _triage(path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("failure_bursts=0 success_after_failure=0", result.stderr)

    def test_rejects_invalid_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_log(directory, [*FAILURES, SUCCESS])
            result = _triage(path, "--failure-threshold", "1")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("failure_threshold must be an integer between 2 and 10000",
                      result.stderr)

    def test_rejects_more_than_maximum_parsed_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_log(directory, [FAILURES[0]] * 10_001)
            result = _triage(path, "--failure-threshold", "2")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("Triage input exceeds 10000 parsed events", result.stderr)


if __name__ == "__main__":
    unittest.main()
