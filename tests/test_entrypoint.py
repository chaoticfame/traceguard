"""Regression tests for installable package metadata and console dispatch."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tomllib
import unittest
from unittest.mock import patch

from traceguard.__main__ import main


ROOT = Path(__file__).resolve().parents[1]


class EntrypointTests(unittest.TestCase):
    """Keep distribution metadata aligned with the tested CLI contract."""

    def test_metadata_registers_dependency_free_console_script(self) -> None:
        """Expose the real dispatcher without adding runtime dependencies."""
        metadata = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        project = metadata["project"]

        self.assertEqual(project["name"], "traceguard")
        self.assertEqual(project["requires-python"], ">=3.11")
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(project["scripts"]["traceguard"],
                         "traceguard.__main__:main")
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["authors"], [{"name": "dems"}])

    def test_console_dispatch_reads_process_arguments(self) -> None:
        """An installed wrapper can call ``main()`` without an argument list."""
        output = io.StringIO()
        errors = io.StringIO()
        fixture = ROOT / "examples" / "auth.log"
        arguments = ["traceguard", str(fixture), "--year", "2026"]

        with patch.object(sys, "argv", arguments), redirect_stdout(output), \
                redirect_stderr(errors):
            result = main()

        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(result, 0)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["outcome"], "failure")
        self.assertEqual(errors.getvalue(), "parsed=3 skipped=1\n")

    def test_subcommand_help_uses_installed_command_name(self) -> None:
        """Help output must be copyable after package installation."""
        output = io.StringIO()

        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["pipeline", "--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertTrue(output.getvalue().startswith("usage: traceguard pipeline"))

    def test_license_matches_verified_package_author(self) -> None:
        """Ship the declared OSI license with the verified author identity."""
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

        self.assertTrue(license_text.startswith("MIT License\n"))
        self.assertIn("Copyright (c) 2026 dems", license_text)


if __name__ == "__main__":
    unittest.main()
