"""Mocked transport regressions; no model downloads or live network calls."""

import http.client
import io
import json
import unittest
from unittest.mock import MagicMock, patch

from traceguard.ollama_client import MAX_RESPONSE_BYTES, OllamaClient, OllamaError


class OllamaClientTests(unittest.TestCase):
    """Verify request shape, network restrictions, bounds, and offline errors."""

    def setUp(self) -> None:
        """Replace the entire HTTP transport before creating any client."""
        patcher = patch("traceguard.ollama_client.http.client.HTTPConnection")
        self.factory = patcher.start()
        self.addCleanup(patcher.stop)
        self.connection = self.factory.return_value
        self.response = MagicMock()
        self.connection.getresponse.return_value = self.response
        self.response.status = 200
        self.response.getheader.side_effect = lambda name, default: {
            "Content-Type": "application/json", "Content-Encoding": "identity",
        }.get(name, default)
        self.client = OllamaClient(offline=False, timeout_seconds=2.5)
        self.set_body(b'{"done":true,"response":"{}"}')

    def set_body(self, body: bytes) -> None:
        """Serve byte chunks through the bounded response reader."""
        self.response.read1.side_effect = io.BytesIO(body).read1

    def generate(self) -> str:
        """Issue one request using a synthetic local model name and payload."""
        return self.client.generate('{"evidence_ids":["alias-1"]}', model="test-local:1")

    def test_non_streaming_request_and_cleanup(self) -> None:
        """Send only the chosen endpoint/path, model, prompt, and JSON options."""
        self.assertEqual(self.generate(), "{}")
        self.factory.assert_called_once_with("127.0.0.1", 11434, timeout=2.5)
        args, kwargs = self.connection.request.call_args
        self.assertEqual(args, ("POST", "/api/generate"))
        body = json.loads(kwargs["body"])
        self.assertEqual(body["model"], "test-local:1")
        self.assertIs(body["stream"], False)
        self.assertEqual(body["format"], "json")
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")
        self.connection.close.assert_called_once()

    def test_offline_default_never_connects(self) -> None:
        """Explicit offline mode is predictable and requires no running server."""
        with self.assertRaises(OllamaError) as raised:
            OllamaClient().generate("sanitized", model="test-local")
        self.assertEqual(raised.exception.code, "offline")
        self.factory.assert_not_called()

    def test_rejects_remote_ambiguous_and_credentialed_endpoints(self) -> None:
        """No DNS, credentials, paths, query injection, or alternate schemes."""
        for endpoint in ("http://example.com", "http://localhost", "http://10.0.0.1",
                         "https://127.0.0.1", "http://user:pass@127.0.0.1",
                         "http://127.0.0.1/other", "http://127.0.0.1?x=1",
                         "http://127.0.0.1#x", "http://127.0.0.1:0",
                         "http://127.0.0.1:65536", "http://127.1", " http://127.0.0.1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                OllamaClient(endpoint=endpoint)
        self.factory.assert_not_called()

    def test_ipv6_loopback_is_supported(self) -> None:
        """Connect to a literal IPv6 loopback address without resolving a name."""
        client = OllamaClient(endpoint="http://[::1]:12345/", offline=False)
        self.assertEqual(client.generate("sanitized", model="test-local"), "{}")
        self.factory.assert_called_once_with("::1", 12345, timeout=10.0)

    def test_invalid_settings_and_requests_never_connect(self) -> None:
        """Reject unbounded timeouts, oversized prompts, and malformed models."""
        for timeout in (0, -1, 61, True, float("nan"), float("inf"), "10"):
            with self.assertRaises(ValueError):
                OllamaClient(timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            OllamaClient(offline=1)
        for prompt, model in (("", "test"), ("x" * 65_537, "test"),
                              ("x", "bad\nmodel"), ("x", "test:cloud"),
                              ("\ud800", "test")):
            with self.assertRaises(ValueError):
                self.client.generate(prompt, model=model)
        self.factory.assert_not_called()

    def test_timeout_and_unavailable_are_private_and_close_connection(self) -> None:
        """Network failures produce stable codes, not private exception details."""
        for exception, code in ((TimeoutError("private"), "timeout"),
                                (ConnectionRefusedError("private"), "unavailable"),
                                (http.client.BadStatusLine("private"), "invalid_response")):
            self.connection.request.side_effect = exception
            with self.assertRaises(OllamaError) as raised:
                self.generate()
            self.assertEqual(raised.exception.code, code)
            self.assertNotIn("private", str(raised.exception))
        self.assertEqual(self.connection.close.call_count, 3)

    def test_http_errors_and_redirects_are_not_followed(self) -> None:
        """Redirects and missing models fail without reading private error bodies."""
        for status in (301, 302, 307, 404, 500):
            self.response.status = status
            with self.assertRaises(OllamaError) as raised:
                self.generate()
            self.assertEqual(raised.exception.code, "http_error")
        self.response.read1.assert_not_called()
        self.assertEqual(self.factory.call_count, 5)

    def test_exact_response_limit_and_limit_plus_one(self) -> None:
        """Bound bytes actually read without trusting Content-Length headers."""
        base = b'{"done":true,"response":"{}"}'
        self.set_body(base + b" " * (MAX_RESPONSE_BYTES - len(base)))
        self.assertEqual(self.generate(), "{}")
        self.set_body(base + b" " * (MAX_RESPONSE_BYTES + 1 - len(base)))
        with self.assertRaises(OllamaError) as raised:
            self.generate()
        self.assertEqual(raised.exception.code, "response_too_large")

    def test_rejects_invalid_envelopes(self) -> None:
        """Reject malformed UTF-8/JSON, duplicates, nonfinite values and streaming."""
        for body in (b"\xff", b"noise", b"[]", b'{"done":false,"response":"{}"}',
                     b'{"done":true,"response":null}', b'{"done":true,"response":" "}',
                     b'{"done":true,"response":"{}","error":"private"}',
                     b'{"done":true,"done":true,"response":"{}"}',
                     b'{"done":true,"response":"{}","extra":NaN}'):
            self.set_body(body)
            with self.assertRaises(OllamaError) as raised:
                self.generate()
            self.assertEqual(raised.exception.code, "invalid_response")

    def test_read_errors_and_compression_fail_safely(self) -> None:
        """Socket failures during body reads are handled and gzip is not decoded."""
        self.response.read1.side_effect = TimeoutError("private")
        with self.assertRaises(OllamaError) as raised:
            self.generate()
        self.assertEqual(raised.exception.code, "timeout")
        self.response.getheader.side_effect = lambda name, default: "gzip"
        with self.assertRaises(OllamaError) as raised:
            self.generate()
        self.assertEqual(raised.exception.code, "invalid_response")


if __name__ == "__main__":
    unittest.main()
