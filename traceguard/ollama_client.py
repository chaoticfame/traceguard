"""Opt-in, bounded stdlib HTTP transport for a loopback Ollama server."""

from dataclasses import dataclass
import http.client
from ipaddress import ip_address
import json
import math
import re
from urllib.parse import urlsplit

MAX_PROMPT_CHARS = 65_536
MAX_RESPONSE_BYTES = 65_536
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


class OllamaError(RuntimeError):
    """Expose a stable error code without server bodies, prompts, or URLs."""

    def __init__(self, code: str) -> None:
        """Retain a machine-readable failure category for offline fallback."""
        self.code = code
        super().__init__(f"Local Ollama request failed: {code}")


def _endpoint(value: str) -> tuple[str, int]:
    """Accept only plain HTTP literal loopback origins, without DNS lookup."""
    try:
        if not isinstance(value, str) or len(value) > 256:
            raise ValueError("Invalid endpoint")
        if any(ord(char) <= 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid endpoint")
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != "http" or host is None
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or not ip_address(host).is_loopback):
            raise ValueError("Invalid endpoint")
        port = parsed.port if parsed.port is not None else 11434
        if not 1 <= port <= 65_535:
            raise ValueError("Invalid port")
        return host, port
    except (ValueError, TypeError) as exc:
        raise ValueError("Ollama endpoint must be an HTTP literal loopback origin") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate keys in the transport envelope."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate response key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    """Reject non-standard JSON numbers such as NaN and Infinity."""
    raise ValueError("Non-standard JSON constant")


@dataclass(frozen=True, slots=True)
class OllamaClient:
    """Call an already-installed local model only when explicitly enabled.

    The timeout is a per-socket-operation timeout, not a total wall-clock
    deadline. No proxies, DNS names, redirects, retries, model pulls, shell
    execution, or automatic requests are used. A loopback origin constrains the
    destination, not the server's own behavior; configure Ollama itself for
    local-only models. Callers must pass sanitized evidence, never raw logs.
    Returned model text is untrusted and needs a separate explanation validator.
    """

    endpoint: str = "http://127.0.0.1:11434"
    timeout_seconds: float = 10.0
    offline: bool = True

    def __post_init__(self) -> None:
        """Validate settings without opening a connection."""
        _endpoint(self.endpoint)
        if (type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds)
                or not 0 < self.timeout_seconds <= 60):
            raise ValueError("Ollama timeout must be finite and between 0 and 60 seconds")
        if type(self.offline) is not bool:
            raise ValueError("Ollama offline setting must be a boolean")

    def generate(self, prompt: str, *, model: str) -> str:
        """POST a bounded prompt and return a completed JSON-format response.

        Uses Ollama's non-streaming /api/generate contract. The outer envelope
        must be valid JSON with done=true and response as nonempty text; JSON
        syntax and evidence-schema validation of that text belong to the next
        layer. All error messages omit request and server-response contents.
        """
        if self.offline:
            raise OllamaError("offline")
        if not isinstance(prompt, str) or not 1 <= len(prompt) <= MAX_PROMPT_CHARS:
            raise ValueError("Ollama prompt must contain 1 to 65536 characters")
        if not isinstance(model, str) or _MODEL.fullmatch(model) is None:
            raise ValueError("Ollama model name is invalid")
        if "cloud" in model.lower():
            raise ValueError("Ollama cloud models are not permitted")
        try:
            body = json.dumps({
                "model": model, "prompt": prompt, "stream": False, "format": "json",
            }, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Ollama prompt must be valid UTF-8 text") from None
        host, port = _endpoint(self.endpoint)
        connection = http.client.HTTPConnection(host, port, timeout=self.timeout_seconds)
        try:
            connection.request("POST", "/api/generate", body=body, headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            response = connection.getresponse()
            if response.status != 200:
                raise OllamaError("http_error")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0]
            encoding = response.getheader("Content-Encoding", "identity")
            if content_type.strip().lower() != "application/json" or encoding != "identity":
                raise OllamaError("invalid_response")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise OllamaError("response_too_large")
                chunks.append(chunk)
        except TimeoutError:
            raise OllamaError("timeout") from None
        except OSError:
            raise OllamaError("unavailable") from None
        except http.client.HTTPException:
            raise OllamaError("invalid_response") from None
        finally:
            connection.close()
        try:
            envelope = json.loads(b"".join(chunks).decode("utf-8"),
                                  object_pairs_hook=_unique_object,
                                  parse_constant=_reject_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise OllamaError("invalid_response") from None
        if (not isinstance(envelope, dict) or envelope.get("done") is not True
                or not isinstance(envelope.get("response"), str)
                or not envelope["response"].strip() or "error" in envelope):
            raise OllamaError("invalid_response")
        return envelope["response"]
