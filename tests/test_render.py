"""Synthetic regression tests for terminal escape injection and output bounds."""

from collections.abc import Iterator
from dataclasses import replace
import unittest

from traceguard.config import DetectionConfig
from traceguard.detector import FailureBurst, detect_failure_bursts, correlate_success_after_failure_bursts
from traceguard.parser import parse_line
from traceguard.render import render_finding, render_findings, terminal_text


class RenderTests(unittest.TestCase):
    """Verify actual detector outputs and adversarial display-only text."""

    def setUp(self) -> None:
        """Create a duplicate-occurrence burst followed by one successful login."""
        line = 'Oct 20 00:00:00 lab sshd[1]: Failed password for demo from 192.0.2.1 port 22 ssh2'
        success = line.replace('Failed', 'Accepted').replace('00:00:00', '00:00:01')
        events = [parse_line(item, year=2026) for item in (line, line, success)]
        config = DetectionConfig(failure_threshold=2)
        self.burst, = detect_failure_bursts(events, config)
        self.correlated, = correlate_success_after_failure_bursts(events, [self.burst], config)

    def test_real_findings_show_timestamps_and_complete_small_evidence(self) -> None:
        """Keep duplicate fingerprints and identify success separately from failures."""
        text = render_findings([self.burst, self.correlated])
        self.assertIn('failure_burst [', text)
        self.assertIn('success_after_failure [', text)
        self.assertIn('burst: 2026-10-20T00:00:00+00:00 -> 2026-10-20T00:00:00+00:00', text)
        self.assertIn('success: 2026-10-20T00:00:01+00:00', text)
        self.assertIn('failures: 2', text)
        self.assertIn(', '.join(self.correlated.evidence_ids), text)
        self.assertIn('review candidate', text)

    def test_every_displayed_field_escapes_controls(self) -> None:
        """Block ANSI CSI/OSC, line injection and bidi formatting in every field."""
        hostile = '\x1b[2J\x1b]8;;https://example.invalid\x07\r\n\t\x7f\x9b\u202e\ud800'
        for name in ('finding_id', 'host', 'source_ip', 'username', 'started_at', 'ended_at'):
            with self.subTest(field=name):
                text = render_finding(replace(self.burst, **{name: hostile}))
                self.assertIn('\\x1b[2J', text)
                self.assertTrue(all(char == '\n' or 32 <= ord(char) <= 126 for char in text))
                self.assertEqual(text.count('\n'), 7)
        text = render_finding(replace(self.correlated, succeeded_at=hostile, evidence_ids=(hostile,) * 3))
        self.assertIn('\\u202e', text)
        self.assertNotIn('\x1b', text)

    def test_escape_notation_is_unambiguous(self) -> None:
        """Literal backslash sequences differ from encoded control characters."""
        self.assertEqual(terminal_text('\x1b'), '\\x1b')
        self.assertEqual(terminal_text('\\x1b'), '\\\\x1b')
        self.assertEqual(terminal_text('"'), '\\"')
        self.assertEqual(terminal_text('\U0001f600'), '\\U0001f600')

    def test_field_limits_include_marker_without_partial_escapes(self) -> None:
        """Oversized text is bounded and truncation never cuts an escape token."""
        for value in ('a' * 1_000_000, '\x1b' * 1000, '\u202e' * 1000, '\U0001f600' * 1000):
            rendered = terminal_text(value, limit=20)
            self.assertLessEqual(len(rendered), 20)
            self.assertTrue(rendered.endswith('...'))
        self.assertEqual(terminal_text('a' * 20, limit=20), 'a' * 20)
        self.assertEqual(terminal_text('\x1b' * 8, limit=20), '\\x1b' * 4 + '...')
        self.assertEqual(terminal_text('\x1b' * 5, limit=20), '\\x1b' * 5)
        self.assertEqual(terminal_text('a' * 21, limit=20), 'a' * 17 + '...')

    def test_all_unicode_control_ranges_are_printable_ascii(self) -> None:
        """Exercise every C0/C1 code point, DEL, bidi and surrogate boundaries."""
        for code in (*range(32), *range(127, 160), 0x2028, 0x202e, 0x2066, 0xd800, 0xffff, 0x10ffff):
            text = terminal_text(chr(code))
            self.assertTrue(text.startswith('\\'))
            self.assertTrue(all(32 <= ord(char) <= 126 for char in text))

    def test_evidence_preview_has_exact_omission_count(self) -> None:
        """Bound display work while making omitted evidence visible."""
        finding = replace(self.burst, evidence_ids=tuple(f'{index:064x}' for index in range(10_000)))
        text = render_finding(finding)
        self.assertIn('evidence (10000):', text)
        self.assertIn('(+9997 omitted)', text)
        self.assertNotIn(f'{9999:064x}', text)
        self.assertLess(len(text), 1500)

    def test_stable_order_empty_input_and_no_mutation(self) -> None:
        """Rendering preserves input order rather than silently reprioritizing it."""
        items = [self.correlated, self.burst]
        before = list(items)
        self.assertEqual(render_findings(items), render_findings(iter(items)))
        self.assertEqual(items, before)
        self.assertTrue(render_findings(items).startswith('success_after_failure'))
        self.assertEqual(render_findings([]), 'No findings.\n')

    def test_invalid_inputs_fail_without_echoing_private_values(self) -> None:
        """Reject malformed records and configuration through privacy-safe errors."""
        for finding in (None, replace(self.burst, host=123),
                        replace(self.burst, evidence_ids=()),
                        replace(self.burst, evidence_ids=('secret',) * 10_001),
                        replace(self.burst, evidence_ids=(None,))):
            with self.assertRaises(ValueError) as raised:
                render_finding(finding)
            self.assertNotIn('secret', str(raised.exception))
        for limit in (True, 7, 1001, 12.5):
            with self.assertRaises(ValueError):
                terminal_text('secret', limit=limit)
        with self.assertRaises(ValueError):
            render_findings(None)

    def test_infinite_iterator_is_stopped_at_limit_plus_one(self) -> None:
        """Reject an oversized batch before rendering any output."""
        consumed = 0

        def findings() -> Iterator[FailureBurst]:
            nonlocal consumed
            while True:
                consumed += 1
                yield self.burst

        with self.assertRaisesRegex(ValueError, '100 findings'):
            render_findings(findings())
        self.assertEqual(consumed, 101)


if __name__ == '__main__':
    unittest.main()
