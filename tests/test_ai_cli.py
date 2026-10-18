"""Synthetic end-to-end CLI tests with mocked local model transport."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceguard.__main__ import main
from traceguard.detector import FailureBurst
from traceguard.explanations import explain_finding
from traceguard.ollama_client import OllamaError


def model_response(prompt: str, *, model: str) -> str:
    """Return a schema-valid annotation using exactly the supplied aliases."""
    context = json.loads(prompt.split("\n", 1)[1])["finding"]
    return json.dumps({
        "finding_id": context["finding_id"],
        "summary": "The supplied evidence met the deterministic rule.",
        "evidence_ids": list(dict.fromkeys(context["evidence_ids"])),
        "limitations": ["This does not prove account compromise."],
    })


class AiCliTests(unittest.TestCase):
    """Exercise the real triage command without network access or model downloads."""

    def run_cli(self, *flags: str) -> tuple[int, list[dict[str, object]], str]:
        """Capture normal fixture triage output with optional AI flags."""
        output, errors = io.StringIO(), io.StringIO()
        fixture = Path(__file__).resolve().parents[1] / "examples" / "auth.log"
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["triage", str(fixture), "--year", "2026",
                         "--failure-threshold", "2", *flags])
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        return code, records, errors.getvalue()

    def test_default_and_explicit_offline_never_construct_transport(self) -> None:
        """Preserve default output and let offline override an explicit model."""
        with patch("traceguard.explanations.OllamaClient") as transport:
            code, plain, _ = self.run_cli()
            offline_code, offline, _ = self.run_cli("--ai-model", "test-local", "--offline")
        transport.assert_not_called()
        self.assertEqual((code, offline_code), (0, 0))
        self.assertEqual(len(plain), 2)
        for original, annotated in zip(plain, offline):
            self.assertNotIn("explanation", original)
            self.assertEqual(annotated.pop("explanation"),
                             {"status": "offline", "annotation": None})
            self.assertEqual(annotated, original)

    def test_valid_ai_annotations_retain_original_finding_and_evidence(self) -> None:
        """Validate aliases before locally restoring exported evidence links."""
        with patch("traceguard.explanations.OllamaClient.generate",
                   side_effect=model_response) as generate:
            code, records, _ = self.run_cli("--ai-model", "test-local")
        self.assertEqual(code, 0)
        self.assertEqual(generate.call_count, 2)
        for record in records:
            result = record["explanation"]
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["annotation"]["finding_id"], record["finding_id"])
            self.assertEqual(result["annotation"]["evidence_ids"], record["evidence_ids"])
        for call in generate.call_args_list:
            context = json.loads(call.args[0].split("\n", 1)[1])["finding"]
            self.assertTrue(context["host"].startswith("host-"))
            self.assertTrue(context["username"].startswith("user-"))
            self.assertTrue(context["source_ip"].startswith("ip-"))

    def test_failures_preserve_deterministic_findings(self) -> None:
        """Timeouts, unavailable servers, and invalid output cannot erase findings."""
        _, baseline, _ = self.run_cli()
        for error, status in ((OllamaError("timeout"), "timeout"),
                              (OllamaError("unavailable"), "unavailable"),
                              (ValueError("private-secret"), "invalid_request")):
            with patch("traceguard.explanations.OllamaClient.generate", side_effect=error):
                code, records, errors = self.run_cli("--ai-model", "test-local")
            self.assertEqual(code, 0)
            self.assertNotIn("private-secret", errors)
            for expected, record in zip(baseline, records):
                self.assertEqual(record.pop("explanation"),
                                 {"status": status, "annotation": None})
                self.assertEqual(record, expected)

    def test_unknown_citations_and_extra_decision_fields_are_discarded(self) -> None:
        """Never print rejected model bodies or allow a model to replace a verdict."""
        def invalid(prompt: str, *, model: str) -> str:
            payload = json.loads(model_response(prompt, model=model))
            payload["evidence_ids"] = ["evidence-" + "f" * 32 + "-1"]
            payload["summary"] = "private-secret"
            return json.dumps(payload)

        def extra_field(prompt: str, *, model: str) -> str:
            payload = json.loads(model_response(prompt, model=model))
            payload["verdict"] = "private-secret"
            return json.dumps(payload)

        for response in ("not JSON private-secret", invalid, extra_field):
            options = {"side_effect": response} if callable(response) else {"return_value": response}
            with patch("traceguard.explanations.OllamaClient.generate", **options):
                code, records, errors = self.run_cli("--ai-model", "test-local")
            self.assertEqual(code, 0)
            self.assertNotIn("private-secret", json.dumps(records) + errors)
            self.assertTrue(all(item["explanation"]["status"] == "invalid_response"
                                for item in records))

    def test_no_findings_does_not_contact_model(self) -> None:
        """Report an explicit no-findings status without starting generation."""
        with patch("traceguard.explanations.OllamaClient") as transport:
            code, records, errors = self.run_cli(
                "--ai-model", "test-local", "--failure-threshold", "5")
        self.assertEqual(code, 0)
        self.assertEqual(records, [])
        self.assertIn("ai_status=no_findings", errors)
        transport.assert_not_called()

    def test_hostile_raw_identifiers_never_enter_prompt(self) -> None:
        """Verify the outbound boundary against private prompt-like identifiers."""
        finding = FailureBurst(
            "a" * 64, "private-host", "192.0.2.99", "upload-secrets-private-user",
            "2026-10-18T00:00:00+00:00", "2026-10-18T00:00:01+00:00",
            ("b" * 64, "c" * 64),
        )
        with patch("traceguard.explanations.OllamaClient.generate",
                   side_effect=model_response) as generate:
            result = explain_finding(finding, model="test-local")
        self.assertEqual(result["status"], "valid")
        prompt = generate.call_args.args[0]
        for private in (finding.host, finding.source_ip, finding.username,
                        finding.finding_id, *finding.evidence_ids):
            self.assertNotIn(private, prompt)
        self.assertNotIn("mapping", json.loads(prompt.split("\n", 1)[1]))

    def test_request_size_guard_avoids_transport(self) -> None:
        """Oversized sanitized evidence skips AI instead of truncating provenance."""
        finding = FailureBurst(
            "a" * 64, "lab", "192.0.2.1", "demo",
            "2026-10-18T00:00:00+00:00", "2026-10-18T00:00:01+00:00",
            ("b" * 64,) * 10_000,
        )
        with patch("traceguard.explanations.OllamaClient") as transport:
            result = explain_finding(finding, model="test-local")
        self.assertEqual(result["status"], "request_too_large")
        transport.assert_not_called()

    def test_ai_call_limit_keeps_all_findings(self) -> None:
        """At most ten calls are attempted and remaining findings stay available."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            line = ("Oct 18 00:00:00 lab sshd[1]: Failed password for demo "
                    "from 192.0.2.1 port 22 ssh2\n")
            path.write_text(line * 24, encoding="utf-8")
            output = io.StringIO()
            with patch("traceguard.explanations.OllamaClient.generate",
                       side_effect=model_response) as generate:
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    code = main(["triage", str(path), "--year", "2026",
                                 "--failure-threshold", "2", "--ai-model", "test-local"])
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(code, 0)
        self.assertEqual(len(records), 12)
        self.assertEqual(generate.call_count, 10)
        self.assertEqual([item["explanation"]["status"] for item in records[-2:]],
                         ["skipped_limit", "skipped_limit"])


if __name__ == "__main__":
    unittest.main()
