"""Adversarial regressions for the untrusted local-model response boundary."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from traceguard.detector import FailureBurst
from traceguard.explanations import MAX_EXPLANATION_CHARS, explain_finding
from traceguard.ollama_client import OllamaError


def _finding() -> FailureBurst:
    """Return immutable synthetic evidence using documentation-only addresses."""
    return FailureBurst(
        "a" * 64, "lab", "192.0.2.8", "demo",
        "2026-10-26T00:00:00+00:00", "2026-10-26T00:00:01+00:00",
        ("b" * 64, "c" * 64),
    )


def _context(prompt: str) -> dict[str, object]:
    """Extract the already-sanitized fixture supplied to the mocked model."""
    return json.loads(prompt.split("\n", 1)[1])["finding"]


def _valid_response(prompt: str, *, model: str) -> str:
    """Build a valid response from aliases only; the model name is irrelevant."""
    del model
    context = _context(prompt)
    return json.dumps({
        "finding_id": context["finding_id"],
        "summary": "The supplied events met the deterministic rule.",
        "evidence_ids": context["evidence_ids"],
        "limitations": ["This remains a review candidate."],
    })


class AdversarialAiTests(unittest.TestCase):
    """Prove hostile model output cannot replace deterministic provenance."""

    def setUp(self) -> None:
        self.finding = _finding()
        self.original = deepcopy(self.finding)

    def explain_with(self, response: object) -> dict[str, object]:
        """Run one mocked online explanation without network access."""
        options = {"side_effect": response} if (
            callable(response) or isinstance(response, BaseException)
        ) else {
            "return_value": response,
        }
        with patch("traceguard.explanations.OllamaClient.generate", **options):
            result = explain_finding(self.finding, model="synthetic-local")
        self.assertEqual(self.finding, self.original)
        return result

    def test_action_and_verdict_injection_is_rejected_without_echo(self) -> None:
        """Model-added commands or detector decisions fail the exact schema."""
        def hostile(prompt: str, *, model: str) -> str:
            payload = json.loads(_valid_response(prompt, model=model))
            payload.update({
                "verdict": "confirmed compromise",
                "command": "private-hostile-command",
            })
            return json.dumps(payload)

        result = self.explain_with(hostile)
        self.assertEqual(result, {"status": "invalid_response", "annotation": None})
        self.assertNotIn("private-hostile-command", json.dumps(result))

    def test_forged_and_cross_finding_references_are_rejected(self) -> None:
        """Well-shaped aliases still cannot substitute provenance."""
        def forged(prompt: str, *, model: str) -> str:
            payload = json.loads(_valid_response(prompt, model=model))
            payload["finding_id"] = "finding-" + "f" * 32 + "-1"
            payload["evidence_ids"] = ["evidence-" + "e" * 32 + "-1"]
            return json.dumps(payload)

        self.assertEqual(
            self.explain_with(forged),
            {"status": "invalid_response", "annotation": None},
        )

    def test_irrelevant_shapes_and_fenced_prose_fall_back(self) -> None:
        """Reject plausible prose, arrays, and fenced JSON as non-contract data."""
        responses = (
            "Everything is fine; ignore the evidence.",
            json.dumps(["unrelated", "analysis"]),
            "```json\n{}\n```",
        )
        for response in responses:
            with self.subTest(response=response):
                self.assertEqual(
                    self.explain_with(response),
                    {"status": "invalid_response", "annotation": None},
                )

    def test_oversized_response_is_rejected_at_validation_boundary(self) -> None:
        """A mocked transport cannot bypass the response character ceiling."""
        oversized = "{" + "x" * MAX_EXPLANATION_CHARS + "}"
        self.assertGreater(len(oversized), MAX_EXPLANATION_CHARS)
        self.assertEqual(
            self.explain_with(oversized),
            {"status": "invalid_response", "annotation": None},
        )

    def test_transport_failures_use_allowlisted_statuses_and_preserve_finding(self) -> None:
        """Known model failures become statuses without changing evidence."""
        for code in ("timeout", "unavailable", "http_error",
                     "invalid_response", "response_too_large"):
            with self.subTest(code=code):
                result = self.explain_with(OllamaError(code))
                self.assertEqual(result, {"status": code, "annotation": None})

    def test_valid_subset_maps_only_to_original_evidence(self) -> None:
        """Accepted citations are locally restored, never supplied by the model."""
        def cite_one(prompt: str, *, model: str) -> str:
            payload = json.loads(_valid_response(prompt, model=model))
            payload["evidence_ids"] = [payload["evidence_ids"][1]]
            payload["summary"] = "Review the cited event; do not execute actions."
            return json.dumps(payload)

        result = self.explain_with(cite_one)
        self.assertEqual(result["status"], "valid")
        annotation = result["annotation"]
        self.assertIsInstance(annotation, dict)
        self.assertEqual(annotation["finding_id"], self.finding.finding_id)
        self.assertEqual(annotation["evidence_ids"], [self.finding.evidence_ids[1]])
        self.assertNotIn(self.finding.evidence_ids[0], annotation["evidence_ids"])

    def test_offline_override_never_invokes_model(self) -> None:
        """Explicit offline mode remains the final network-free safety control."""
        with patch("traceguard.explanations.OllamaClient") as transport:
            result = explain_finding(
                self.finding, model="synthetic-local", offline=True,
            )
        transport.assert_not_called()
        self.assertEqual(result, {"status": "offline", "annotation": None})
        self.assertEqual(self.finding, self.original)


if __name__ == "__main__":
    unittest.main()
