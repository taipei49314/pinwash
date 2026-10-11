"""Spec 20: host-matched decoding and the absent-base comparison (SPEC §3;
R19; #22, AI-assisted ruling R-22a with the challenger's amendments to Q1a
and Q1b).

Claude Code reads `.claude/settings.json` and `.claude/settings.local.json`
as UTF-16LE when the file starts FF FE, else as UTF-8 with U+FFFD for bad
bytes, and drops one leading byte order mark before a strict JSON parse;
`.mcp.json` the same without UTF-16. gemini-cli (Node) reads UTF-8 with
U+FFFD and keeps a byte order mark. A base Claude Code cannot parse is
compared as absent on `claude_settings` and `.mcp.json`: the host ran
without it. The shape names are the challenger's executed members.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
MCP = ".mcp.json"
CURSOR = ".cursor/mcp.json"
GEMINI = ".gemini/settings.json"
BOM = b"\xef\xbb\xbf"
BASH = json.dumps({"permissions": {"allow": ["Bash(*)"]}}).encode()
WIDE = json.dumps({"mcpServers": {"srvx": {"command": "x", "autoApprove": ["*"]}}}).encode()
STOP = json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 judge.py"}]}]}}).encode()


def _scan(base: dict[str, bytes], head: dict[str, bytes]) -> dict[str, Any]:
    return scan_pair(base, head, base_label="b", head_label="h", env=ENV)


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return sorted((f["rule"], f["severity"]) for f in payload["findings"])


class ClaudeCodeDecoding(unittest.TestCase):
    def test_new_files_the_host_reads_are_compared(self) -> None:
        latin1 = json.dumps({"permissions": {"allow": ["Bash(*)"]}, "note": "café"}, ensure_ascii=False).encode("latin-1")
        for name, path, data in (
            ("H1 BOM settings", CS, BOM + BASH),
            ("H2 Latin-1 byte in a string", LOCAL, latin1),
            ("H3 UTF-16LE settings", CS, b"\xff\xfe" + BASH.decode().encode("utf-16-le")),
            ("H4 BOM .mcp.json", MCP, BOM + WIDE),
        ):
            with self.subTest(name=name):
                payload = _scan({}, {path: data})
                self.assertIn(("PERMISSION_WIDENED", "high"), _rules(payload))
                self.assertEqual(payload["verdict"], "block")
                self.assertEqual(payload["unknown_coverage"], [])

    def test_encoding_only_edits_are_no_change(self) -> None:
        for name, path, base, head in (
            ("H5 BOM dropped from live settings", CS, BOM + BASH, BASH),
            ("H6 BOM dropped from live .mcp.json", MCP, BOM + WIDE, WIDE),
            ("H7 an honest edit that adds a BOM", CS, BASH, BOM + BASH),
            ("UTF-8 to UTF-16LE", CS, BASH, b"\xff\xfe" + BASH.decode().encode("utf-16-le")),
        ):
            with self.subTest(name=name):
                payload = _scan({path: base}, {path: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [])

    def test_a_deleted_bom_settings_file_loses_its_judge(self) -> None:
        # D1: the host read this Stop hook; deleting the file removes it.
        payload = _scan({CS: BOM + STOP, "judge.py": b"import sys\nsys.exit(2)\n"}, {"judge.py": b"import sys\nsys.exit(2)\n"})
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])

    def test_utf16_needs_the_little_endian_mark(self) -> None:
        # Claude Code reads UTF-16LE only after FF FE; other UTF-16 is not
        # JSON to it, so it stays a new file pinwash cannot parse.
        for data in (BASH.decode().encode("utf-16-le"), b"\xfe\xff" + BASH.decode().encode("utf-16-be")):
            with self.subTest(data=data[:4]):
                payload = _scan({}, {CS: data})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [{"path": CS, "reason": "new surface file unparseable"}])


class OddLengthUtf16(unittest.TestCase):
    # Node's utf16le decoder drops a trailing odd byte; Claude Code loads
    # such a file (review of 2026-10-10, AI-assisted).
    ODD = b"\xff\xfe" + BASH.decode().encode("utf-16-le") + b"\n"
    STOP_ODD = b"\xff\xfe" + STOP.decode().encode("utf-16-le") + b"\xff"

    def test_an_odd_length_file_reads_like_its_even_control(self) -> None:
        for path in (CS, LOCAL):
            with self.subTest(path=path):
                self.assertEqual(_rules(_scan({}, {path: self.ODD})), [("PERMISSION_WIDENED", "high")])
                payload = _scan({path: self.ODD}, {path: BASH})
                self.assertEqual((payload["findings"], payload["unknown_coverage"]), ([], []))
        judge = b"import sys\nsys.exit(2)\n"
        for head in ({"judge.py": judge}, {CS: b"{}", "judge.py": judge}):
            with self.subTest(head=sorted(head)):
                payload = _scan({CS: self.STOP_ODD, "judge.py": judge}, head)
                self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])


class AbsentBaseComparison(unittest.TestCase):
    def test_a_head_that_repairs_a_corrupt_base_is_compared(self) -> None:
        for name, path, base, head in (
            ("E5 settings trailing comma repaired", CS, BASH[:-1] + b",}", BASH),
            ("M1 settings garbage to Bash(*)", CS, b"{not json", BASH),
            ("E6 .mcp.json comma repaired", MCP, WIDE[:-1] + b",}", WIDE),
        ):
            with self.subTest(name=name):
                payload = _scan({path: base}, {path: head})
                self.assertIn(("PERMISSION_WIDENED", "high"), _rules(payload))
                self.assertEqual(payload["unknown_coverage"], [{"path": path, "reason": "surface unparseable at base"}])

    def test_surfaces_without_an_evidenced_strict_host_keep_the_row(self) -> None:
        for path, base, head in ((CURSOR, b"{", WIDE),
                                 (GEMINI, b"{", json.dumps({"autoAccept": True}).encode()),
                                 ("opencode.json", b"{", json.dumps({"permission": {"bash": "allow"}}).encode())):
            with self.subTest(path=path):
                payload = _scan({path: base}, {path: head})
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [{"path": path, "reason": "surface unparseable at base"}])


class GeminiDecoding(unittest.TestCase):
    def test_bad_bytes_are_replaced_and_a_bom_is_kept(self) -> None:
        # G1: Node reads a Latin-1 byte in a string; JSON.parse rejects a BOM.
        latin1 = json.dumps({"autoAccept": True, "note": "café"}, ensure_ascii=False).encode("latin-1")
        self.assertEqual(_rules(_scan({}, {GEMINI: latin1})), [("PERMISSION_WIDENED", "high")])
        payload = _scan({}, {GEMINI: BOM + json.dumps({"autoAccept": True}).encode()})
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["unknown_coverage"], [{"path": GEMINI, "reason": "new surface file unparseable"}])


if __name__ == "__main__":
    unittest.main()
