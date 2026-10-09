"""Engine fidelity to SPEC text as it stands (no spec bump).

Each class pins one engine behaviour that SPEC already states and the engine
did not hold. Frozen gates stay in tests/gates/.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any

from pinwash.engine import scan_pair
from pinwash.findings import fingerprint
from pinwash.hooks import extract_event_hooks
from pinwash.parse.jsonsurf import _C_PARSER_DEPTH, _json_int, _loads_iterative, json_load
from pinwash.parse.tomlsub import parse_checkwash_config
from pinwash.rules.required_check import ruleset_contexts
from pinwash.textutil import dump_json, sha256_text

ROOT = Path(__file__).resolve().parents[1]
TODAY = "2026-10-01"
SHA = "abcdef0123456789abcdef0123456789abcdef01"
SETTINGS = ".claude/settings.json"
STOP = json.dumps(
    {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python hooks/judge.py"}]}]}}
)
JUDGE = "import json\nprint(json.dumps({'decision': 'block'}))\n"


def _bytes(files: dict[str, str | bytes]) -> dict[str, bytes]:
    return {k: v if isinstance(v, bytes) else v.encode("utf-8") for k, v in files.items()}


def _pair(base: dict[str, str | bytes], head: dict[str, str | bytes]) -> dict[str, Any]:
    return scan_pair(
        _bytes(base), _bytes(head), base_label="base", head_label="head",
        env={"PINWASH_TODAY": TODAY},
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["rule"], item["severity"]) for item in payload["findings"]]


def _identities(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(f["rule"], f["severity"], f["fingerprint"]) for f in payload["findings"]]


def _nest(depth: int) -> str:
    """A JSON array nested exactly `depth` containers deep."""
    return "[" * depth + "]" * depth


def _depth(value: Any) -> int:
    """Container nesting depth of a parsed value, without recursion."""
    deepest, stack = 0, [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            node = list(node.values())
        if isinstance(node, list):
            deepest = max(deepest, depth + 1)
            stack.extend((child, depth + 1) for child in node)
    return deepest


def _stack_depth() -> int:
    frame, depth = sys._getframe(), 0
    while frame is not None:
        depth, frame = depth + 1, frame.f_back
    return depth


def _padded(doc: str, depth: int) -> str:
    """doc, a JSON object (or the pins.json array), with one more member that
    no rule reads, so that the whole document is `depth` containers deep."""
    body, close = doc.rstrip()[:-1], doc.rstrip()[-1]
    sep = "" if body.strip() in ("{", "[") else ", "
    member = _nest(depth - 1) if close == "]" else '"_pad": ' + _nest(depth - 1)
    return body + sep + member + close


def _outcome(load: Any, text: str) -> tuple[Any, ...]:
    """Accept/reject and the value with its types, for shallow documents."""

    def canon(v: Any) -> Any:
        if isinstance(v, float):
            return ("float", "nan" if math.isnan(v) else repr(v))
        if isinstance(v, list):
            return ("list", [canon(x) for x in v])
        if isinstance(v, dict):
            return ("dict", [(k, canon(x)) for k, x in v.items()])
        return (type(v).__name__, v)

    try:
        return ("ok", canon(load(text)))
    except ValueError:
        return ("rejected",)


class JsonNesting(unittest.TestCase):
    """SPEC §8 / §9: how deep a document nests is no part of whether a
    surface parses or what it holds. json.loads recursed once per level
    (RecursionError near 990 levels on 3.11, near 10000 on 3.12/3.13, then
    exit 2), and so did the hook and ruleset walkers. Deep documents now go
    through an iterative reader of the same grammar, and the walkers keep
    their own stack: every interpreter judges them, as it judges shallow
    ones."""

    def test_deep_documents_parse_and_keep_their_shape(self) -> None:
        for depth in (1, _C_PARSER_DEPTH, _C_PARSER_DEPTH + 1, 1000, 10000, 100000):
            with self.subTest(depth=depth):
                value, status = json_load(_nest(depth).encode())
                self.assertEqual(status, "ok")
                self.assertEqual(_depth(value), depth)
                obj = '{"a": ' * depth + "null" + "}" * depth
                value, status = json_load(obj.encode())
                self.assertEqual(status, "ok")
                self.assertEqual(_depth(value), depth)
        for bad in ("[" * 5000, "[" * 5000 + "]" * 4999, _nest(5000) + "]", "[" * 4999 + "{]" + "]" * 4999):
            with self.subTest(bad=bad[:12]):
                self.assertEqual(json_load(bad.encode()), (None, "unparseable"))

    CORPUS = (
        '{"a": 1, "b": [true, false, null], "a": 2}',
        ' \t\n\r[1, 2.5, -0, -1e3, 1E+2, "x"] \n',
        '"s"', "0", "-0.0", "1e400", "NaN", "[Infinity, -Infinity]",
        '"\\ud800\\udc00 \\ud800 \\u00e9 \\/ \\b \\\\"',
        '{"k\\u0000": "é\U0001f642", "": {}}',
        "{}", "[]", "[[], {}]", '{"s": "[{" , "t": ["]"]}', "9" * 5000, "-" + "9" * 700,
        "", " ", "﻿{}", "[1,]", '{"a": 1,}', "[1 2]", '{"a" 1}', "{'a': 1}", "[01]",
        "[1.]", "[.5]", "[+1]", "[1e]", "[1e+]", "[١]", "[1١]", "[1.١]",
        '"a\tb"', '"\\x"', '"\\u12"', '"unterminated', "[nan]", "[True]", "{} x",
        '{"a": 1} {}', "[ 1]", "[\x0b1]", '{"a":}', "{,}", "[,1]", '{"a":1 "b":2}',
        "{1: 2}", "-", "--1", "-Infinity1", "nul", "[null", '{"a": [1, 2}', "[1, 2]]",
    )

    def test_iterative_reader_accepts_and_builds_what_json_loads_does(self) -> None:
        def c_loads(text: str) -> Any:
            return json.loads(text, parse_int=_json_int)

        for text in self.CORPUS:
            with self.subTest(text=text[:40]):
                self.assertEqual(_outcome(_loads_iterative, text), _outcome(c_loads, text))
                # json_load hands a document deeper than _C_PARSER_DEPTH to
                # the iterative reader; json.loads still manages 200 here.
                deep = "[" * 200 + text + "]" * 200
                value, status = json_load(deep.encode())
                expected = _outcome(c_loads, deep)
                self.assertEqual(status, "ok" if expected[0] == "ok" else "unparseable")
                if status == "ok":
                    self.assertEqual(_outcome(lambda _t: value, deep), expected)

    def test_padding_at_any_depth_keeps_the_verdict(self) -> None:
        judge = {"hooks/judge.py": JUDGE}
        rs = {"required_status_checks": ["tripwire", "ci"]}
        weakenings = {
            SETTINGS: (STOP, json.dumps({"hooks": {}, "permissions": {"allow": ["Bash(*)"]}})),
            ".claude/settings.local.json": ("{}", '{"permissionMode": "dontAsk"}'),
            ".cursor/hooks.json": (
                json.dumps({"hooks": {"stop": [{"command": "python hooks/judge.py"}]}}),
                '{"hooks": {}}',
            ),
            ".cursor/mcp.json": ('{"mcpServers": {}}', '{"mcpServers": {"s": {"command": "x"}}}'),
            ".mcp.json": ('{"mcpServers": {}}', '{"mcpServers": {"s": {"command": "x"}}}'),
            ".github/required-ruleset.json": (json.dumps(rs), '{"required_status_checks": ["ci"]}'),
            ".github/rulesets/main.json": (
                json.dumps({"rules": [{"parameters": rs}]}),
                json.dumps({"rules": [{"parameters": {"required_status_checks": []}}]}),
            ),
            ".pinwash/pins.json": (
                '[{"locator": "g", "kind": "git_tag", "value": "v1.0.0"}]',
                '[{"locator": "g", "kind": "git_tag", "value": "main"}]',
            ),
            ".gemini/settings.json": ('{"approvalMode": "default"}', '{"approvalMode": "yolo"}'),
            "opencode.json": ('{"permission": {"bash": "ask"}}', '{"permission": {"bash": "allow"}}'),
        }
        for path, (base, head) in weakenings.items():
            expected = _identities(_pair({path: base, **judge}, {path: head, **judge}))
            self.assertTrue(expected, path)
            self.assertNotIn("SURFACE_UNPARSEABLE", [r for r, _s, _f in expected])
            for depth in (_C_PARSER_DEPTH, _C_PARSER_DEPTH + 1, 1000, 5000):
                for side in ("base", "head", "both"):
                    with self.subTest(path=path, depth=depth, side=side):
                        b = _padded(base, depth) if side != "head" else base
                        h = _padded(head, depth) if side != "base" else head
                        got = _pair({path: b, **judge}, {path: h, **judge})
                        self.assertEqual(_identities(got), expected)

    def test_deep_claude_hooks_json_is_no_parse_failure(self) -> None:
        path = ".claude/hooks/config.json"
        self.assertEqual(_pair({path: "{}"}, {path: _nest(5000)})["findings"], [])
        self.assertEqual(_rules(_pair({path: "{}"}, {path: "[" * 5000})), [("SURFACE_UNPARSEABLE", "high")])

    @staticmethod
    def _nested_hooks(levels: int) -> str:
        leaf = '{"type": "command", "command": "python hooks/judge.py"}'
        return '{"hooks": {"Stop": [' + '{"hooks": [' * levels + leaf + "]}" * levels + "]}}"

    @staticmethod
    def _deep_ruleset(levels: int) -> str:
        leaf = '{"required_status_checks": [{"context": "tripwire"}]}'
        return '{"x": ' * levels + leaf + "}" * levels

    def test_walkers_read_commands_and_contexts_at_any_depth(self) -> None:
        for levels in (1, 700, 1500, 5000):
            with self.subTest(levels=levels):
                doc, status = json_load(self._nested_hooks(levels).encode())
                self.assertEqual(status, "ok")
                events = extract_event_hooks(doc)
                self.assertEqual(events["Stop"]["commands"], ["python hooks/judge.py"])
                self.assertEqual(len(events["Stop"]["command_states"]), 1)
                base = {SETTINGS: self._nested_hooks(levels), "hooks/judge.py": JUDGE}
                payload = _pair(base, {SETTINGS: '{"hooks": {}}', "hooks/judge.py": JUDGE})
                self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        path = ".github/required-ruleset.json"
        for levels in (1, 1500, 5000):
            with self.subTest(levels=levels):
                doc, status = json_load(self._deep_ruleset(levels).encode())
                self.assertEqual(status, "ok")
                self.assertEqual(ruleset_contexts(doc), ["tripwire"])
                payload = _pair(
                    {path: self._deep_ruleset(levels)}, {path: '{"required_status_checks": []}'}
                )
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "critical")])

    def test_depth_costs_no_stack(self) -> None:
        # Measured, not assumed: with the recursion limit a hundred frames
        # above this test's own stack, documents 5000 deep on the walker
        # surfaces and on a padded MCP file are still judged.
        base = {
            SETTINGS: self._nested_hooks(5000),
            "hooks/judge.py": JUDGE,
            ".github/required-ruleset.json": self._deep_ruleset(5000),
        }
        head = {
            SETTINGS: '{"hooks": {}}',
            "hooks/judge.py": JUDGE,
            ".github/required-ruleset.json": '{"required_status_checks": []}',
            ".mcp.json": _padded('{"mcpServers": {"s": {"command": "x"}}}', 5000),
        }
        limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(_stack_depth() + 100)
            payload = _pair(base, head)
        finally:
            sys.setrecursionlimit(limit)
        self.assertEqual(
            sorted(_rules(payload)),
            [
                ("HOOK_REMOVED", "critical"),
                ("PERMISSION_WIDENED", "high"),
                ("REQUIRED_CHECK_DROPPED", "critical"),
            ],
        )


class JsonIntegers(unittest.TestCase):
    """SPEC §8 / §9: an integer literal of any length parses, to the same
    value whatever the process's int_max_str_digits. int() refused over 4300
    digits by default (exit 2), and a host that lowered the limit changed
    the result for shorter ones."""

    def test_values_match_int_up_to_the_default_limit(self) -> None:
        for digits in (1, 2, 639, 640, 641, 1000, 4299, 4300):
            for sign in ("", "-"):
                literal = sign + "9" * digits
                with self.subTest(literal=literal[:8], digits=digits):
                    value = _json_int(literal)
                    self.assertIs(type(value), int)
                    self.assertTrue(value == int(literal))
        self.assertEqual(json_load(b'{"n": 12, "m": -0}'), ({"n": 12, "m": 0}, "ok"))

    def test_longer_literals_parse_as_exact_decimals(self) -> None:
        for digits in (4301, 5000, 100000):
            for sign in ("", "-"):
                literal = sign + "9" * digits
                with self.subTest(digits=digits, sign=sign):
                    value, status = json_load(('{"n": %s}' % literal).encode())
                    self.assertEqual(status, "ok")
                    self.assertIsInstance(value["n"], Decimal)
                    self.assertTrue(str(value["n"]) == literal)
        self.assertEqual(json_load(("[1.%s]" % ("0" * 5000)).encode()), ([1.0], "ok"))

    def test_the_process_limit_changes_nothing(self) -> None:
        docs = [("[%s]" % ("9" * n)).encode() for n in (640, 641, 1000, 4300, 4301, 5000)]
        expected = [json_load(d) for d in docs]
        previous = sys.get_int_max_str_digits()
        try:
            for limit in (0, 640, 100000):
                sys.set_int_max_str_digits(limit)
                got = [json_load(d) for d in docs]
                # No assertEqual: a failure message would print the integers.
                self.assertTrue(got == expected, f"int_max_str_digits={limit}")
                self.assertEqual([type(v[0][0]) for v in got], [type(v[0][0]) for v in expected])
        finally:
            sys.set_int_max_str_digits(previous)

    def test_long_integer_keeps_the_verdict(self) -> None:
        # The control (last Stop removed) blocks; an MCP file holding a
        # 5000-digit number turned that block into exit 2.
        long_n = "9" * 5000
        base = {SETTINGS: STOP, ".mcp.json": '{"mcpServers": {}}'}
        payload = _pair(
            base, {SETTINGS: '{"hooks": {}}', ".mcp.json": '{"mcpServers": {}, "n": %s}' % long_n}
        )
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        created = _pair({}, {".mcp.json": '{"mcpServers": {"s": {"command": "x"}}, "n": %s}' % long_n})
        self.assertEqual(_rules(created), [("PERMISSION_WIDENED", "high")])


class LoneSurrogates(unittest.TestCase):
    """SPEC §7 / §8: a lone surrogate in subject data (JSON \\udXXX escape,
    non-UTF-8 path name) is reported, never an engine error."""

    def _assert_round_trip(self, payload: dict[str, Any], needle: str) -> None:
        blob = dump_json(payload)
        text = blob.decode("utf-8")  # strict: the bytes are valid UTF-8
        self.assertEqual(json.loads(text), payload)
        self.assertNotIn(needle, text)
        escaped = "\\u%04x" % ord(needle)
        self.assertIn(escaped, text)

    def test_json_escape_in_hook_event_name(self) -> None:
        extra = '"Ev\\ud800": [{"hooks": [{"type": "command", "command": "x"}]}]'
        base = {SETTINGS: STOP[:-2] + ", " + extra + "}}"}
        payload = _pair(base, {SETTINGS: STOP})
        removed = [f for f in payload["findings"] if f["rule"] == "HOOK_REMOVED"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["locator"], "Ev\ud800")
        self.assertEqual(removed[0]["message"], "hook event Ev\ud800 removed")
        self._assert_round_trip(payload, "\ud800")

    def test_json_escape_in_ruleset_context_and_stub_before(self) -> None:
        path = ".github/required-ruleset.json"
        payload = _pair(
            {path: '{"required_status_checks": ["a\\udcff", "b"]}'},
            {path: '{"required_status_checks": ["b"]}'},
        )
        self.assertEqual(payload["findings"][0]["before"], "a\udcff")
        self._assert_round_trip(payload, "\udcff")
        payload = _pair(
            {SETTINGS: '{"hooks": {"Stop": [{"hooks": [{"command": "judge \\udfff"}]}]}}'},
            {SETTINGS: '{"hooks": {"Stop": [{"hooks": [{"command": "true"}]}]}}'},
        )
        self.assertEqual(_rules(payload), [("GATE_STUBBED", "critical")])
        self._assert_round_trip(payload, "\udfff")

    def test_json_escape_in_server_and_pin_names(self) -> None:
        for path, base, head, rule in (
            (".mcp.json", '{"mcpServers": {}}', '{"mcpServers": {"s\\ud800": {"command": "x"}}}', "PERMISSION_WIDENED"),
            (".gemini/settings.json", "{}", '{"mcpServers": {"\\ud800": {"trust": true}}}', "PERMISSION_WIDENED"),
            ("opencode.json", "{}", '{"permission": {"\\ud800": "allow"}}', "PERMISSION_WIDENED"),
            (".pinwash/pins.json", '[{"locator": "g\\ud800", "kind": "git_tag", "value": "v1.0.0"}]', "[]", "JUDGE_UNPINNED"),
        ):
            with self.subTest(path=path):
                payload = _pair({path: base}, {path: head})
                self.assertEqual(_rules(payload), [(rule, "high")])
                self._assert_round_trip(payload, "\ud800")

    def test_non_utf8_path_name(self) -> None:
        # gitrepo decodes tree names with surrogateescape: b"x\xff" -> "x\udcff".
        path = "x\udcff/SKILL.md"
        payload = _pair({}, {path: "skip tripwire\n"})
        self.assertEqual(_rules(payload), [("SKILL_BYPASS", "warn")])
        self.assertEqual(payload["findings"][0]["path"], path)
        self._assert_round_trip(payload, "\udcff")

    def test_distinct_surrogates_keep_distinct_fingerprints(self) -> None:
        prints = {
            fingerprint("SKILL_BYPASS", p, "", "", "")
            for p in ("x\udcff/SKILL.md", "x\udcfe/SKILL.md", "x\ud800/SKILL.md", "x/SKILL.md")
        }
        self.assertEqual(len(prints), 4)


class FingerprintsUnchanged(unittest.TestCase):
    """SPEC §7 / §10: surrogatepass encodes every valid str exactly as strict
    UTF-8, so fingerprints (and the exemptions that name them) are unchanged.
    Expected values were computed by the engine at c71c468."""

    CASES: dict[str, tuple[dict[str, str], dict[str, str], list[str]]] = {
        "hook_removed_last_stop": (
            {SETTINGS: json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python hooks/判定.py"}]}]}}, ensure_ascii=False)},
            {SETTINGS: "{}"},
            ["HOOK_REMOVED/.claude/settings.json/v1:3e46175cd58bb27fb865f03bb050246c390fa02f36a008b16ba631ea4a85bbd9"],
        ),
        "gate_stubbed": (
            {SETTINGS: json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python 判定.py ✓"}]}]}}, ensure_ascii=False)},
            {SETTINGS: json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}]}})},
            ["GATE_STUBBED/.claude/settings.json/v1:db21f00884e5619cdea95337298551caa1eef4bbbbc896f73c2210cb796dc0a8"],
        ),
        "judge_unpinned": (
            {".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    steps:\n      - uses: org/tool@v1.2.3\n"},
            {".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    steps:\n      - uses: org/tool@main\n"},
            ["JUDGE_UNPINNED/.github/workflows/ci.yml/v1:c73d93c4a266c1025fdd4ca693592230f1e2deff7f438ca34101b637a598ea97"],
        ),
        "ruleset_drop_nonascii": (
            {".github/required-ruleset.json": json.dumps({"required_status_checks": ["检查✓", "b"]}, ensure_ascii=False)},
            {".github/required-ruleset.json": json.dumps({"required_status_checks": ["b"]})},
            ["REQUIRED_CHECK_DROPPED/.github/required-ruleset.json/v1:124ef9177bc3cc58cb21e7fc1bcc1d882cdad3eb29917606e5138c27dda19d76"],
        ),
        "mcp_astral": (
            {".mcp.json": '{"mcpServers": {}}'},
            {".mcp.json": json.dumps({"mcpServers": {"サーバー🙂": {"command": "x"}}}, ensure_ascii=False)},
            ["PERMISSION_WIDENED/.mcp.json/v1:a8622a20b1c3afbfc3e5c95de48cffbcc47ab23d2141938b1d9b9a883b723b8f"],
        ),
        "skill_bypass_nonascii": (
            {".agents/skills/技能/SKILL.md": "hello\n"},
            {".agents/skills/技能/SKILL.md": "hello\nskip tripwire — 跳过 🙂\n"},
            ["SKILL_BYPASS/.agents/skills/技能/SKILL.md/v1:ff6157da881192aa686b2e1b1f266cea57a7729cf9c5faa0c547c729033735d9"],
        ),
        "config_relaxed": (
            {".checkwash/config.toml": 'fail_on = "high"\n'},
            {".checkwash/config.toml": 'fail_on = "critical"\n'},
            ["CONFIG_RELAXED/.checkwash/config.toml/v1:d357466d82e49fc3a0bd5a3b073427df6335f8828edfd9559765bd6b7b90512d"],
        ),
        "claude_perm": (
            {SETTINGS: "{}"},
            {SETTINGS: json.dumps({"permissions": {"allow": ["Bash(*)"]}, "permissionMode": "dontAsk"})},
            [
                "PERMISSION_WIDENED/.claude/settings.json/v1:6e0433b8468ed22d43927229abe45009b6f284553409aa8a432787bb5702422d",
                "PERMISSION_WIDENED/.claude/settings.json/v1:b4be3929154e80cada9c2a29e2c097205c90427f64b1347c07958c8d8f03365f",
            ],
        ),
    }

    def test_representative_findings_keep_their_fingerprints(self) -> None:
        for name, (base, head, expected) in self.CASES.items():
            with self.subTest(case=name):
                payload = _pair(base, head)
                self.assertEqual(sorted(f["fingerprint"] for f in payload["findings"]), expected)

    def test_direct_fingerprints(self) -> None:
        self.assertEqual(
            fingerprint("SKILL_BYPASS", "docs/ü/SKILL.md", "loc✓", "before 🙂", "after 中文"),
            "SKILL_BYPASS/docs/ü/SKILL.md/v1:3dacf236ab0d1a11ab566175874a0617a65879fedb6070e41d7a6c74b219eced",
        )
        self.assertEqual(
            fingerprint("HOOK_REMOVED", ".claude/settings.json", "", "", ""),
            "HOOK_REMOVED/.claude/settings.json/v1:660b191cec628a607dd4309d30c443eaa825f7aaddb6608f1bdebe2376c3e833",
        )

    def test_valid_text_hashes_as_strict_utf8(self) -> None:
        import hashlib

        for text in ("", "ascii", "ü中✓", "🙂\U0010ffff", "\x00\n\r\t", "\ud7ff\ue000\uffff"):
            with self.subTest(text=text):
                self.assertEqual(sha256_text(text), hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_dump_json_bytes_unchanged_for_valid_text(self) -> None:
        obj = {"b": ["ü中✓", "🙂"], "a": "x\n\"\\"}
        expected = (json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.assertEqual(dump_json(obj), expected)


class TypeConfusion(unittest.TestCase):
    """SPEC §5.3 / §8: a value whose type the engine cannot interpret is an
    unknown value (no finding), never an engine error."""

    PATH = ".gemini/settings.json"

    def test_gemini_approval_mode_of_another_json_type(self) -> None:
        for value in ("[]", '["yolo"]', "{}", '{"yolo": 1}'):
            with self.subTest(value=value):
                head = _pair({self.PATH: '{"approvalMode": "default"}'}, {self.PATH: '{"approvalMode": %s}' % value})
                self.assertEqual(head["findings"], [])
                base = _pair({self.PATH: '{"approvalMode": %s}' % value}, {self.PATH: '{"approvalMode": "yolo"}'})
                self.assertEqual(base["findings"], [])

    def test_gemini_approval_mode_lattice_unchanged(self) -> None:
        for base, head, fires in (
            ("{}", '{"approvalMode": "yolo"}', True),
            ('{"approvalMode": "default"}', '{"approvalMode": "auto_edit"}', True),
            ('{"approvalMode": 5}', '{"approvalMode": "yolo"}', False),
            ('{"approvalMode": "yolo"}', '{"approvalMode": "default"}', False),
        ):
            with self.subTest(base=base, head=head):
                payload = _pair({self.PATH: base}, {self.PATH: head})
                self.assertEqual(bool(payload["findings"]), fires)


class FailOnCaseFolding(unittest.TestCase):
    """SPEC §8: re.IGNORECASE also matches U+0130 (İ) and U+0131 (ı) for
    "i", so `fail_on = "hİgh"` reached the severity lookup as "hi\u0307gh"
    and raised KeyError (exit 2, hiding every other finding). A value that
    is not one of the four severities is outside the §3.2 subset: not read."""

    C = ".checkwash/config.toml"
    ODD = ("h\u0130gh", "\u0131nfo", "cr\u0130t\u0130cal", "H\u0130GH")

    def test_value_outside_the_subset_is_not_read(self) -> None:
        for value in self.ODD:
            with self.subTest(value=value):
                self.assertIsNone(parse_checkwash_config(f'fail_on = "{value}"\n')["fail_on"])
        for line, value in (('FAIL_ON = "HIGH"', "high"), ("fail_on = 'Warn'", "warn")):
            with self.subTest(line=line):
                self.assertEqual(parse_checkwash_config(line + "\n")["fail_on"], value)

    def test_no_engine_error_on_any_side(self) -> None:
        high = 'fail_on = "high"\n'
        for value in self.ODD:
            odd = f'fail_on = "{value}"\n'
            for base, head in (
                ({self.C: high}, {self.C: odd}),
                ({}, {self.C: odd}),
                ({self.C: odd}, {self.C: high}),
                ({self.C: odd}, {}),
            ):
                with self.subTest(value=value, base=base, head=head):
                    self.assertEqual(_pair(base, head)["findings"], [])

    def test_other_findings_keep_their_verdict(self) -> None:
        payload = _pair(
            {SETTINGS: STOP},
            {SETTINGS: '{"hooks": {}}', self.C: 'fail_on = "h\u0131gh"\n'},
        )
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        self.assertEqual(payload["verdict"], "block")


class NonUtf8PathThroughGit(unittest.TestCase):
    """SPEC §8 through the public CLI: a tree name that is not UTF-8 keeps
    the block (exit 1) instead of exit 2. The tree is built with plumbing,
    so no file system has to accept the name."""

    def _git(self, repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        proc = subprocess.run(
            ["git", "-c", "user.name=pinwash", "-c", "user.email=pinwash@test",
             "-c", "commit.gpgsign=false", *args],
            cwd=repo, env=env, input=stdin, capture_output=True, check=True, timeout=60,
        )
        return proc.stdout.strip()

    def _blob(self, repo: Path, data: bytes) -> bytes:
        return self._git(repo, "hash-object", "-w", "--stdin", stdin=data)

    def _tree(self, repo: Path, entries: list[tuple[bytes, bytes, bytes]]) -> bytes:
        body = b"".join(mode + b" " + (b"tree" if mode == b"040000" else b"blob") + b" " + oid + b"\t" + name + b"\0"
                        for mode, oid, name in entries)
        return self._git(repo, "mktree", "-z", stdin=body)

    def test_non_utf8_tree_name_keeps_exit_one(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="pinwash-fidelity-")
        self.addCleanup(tmp.cleanup)
        repo = Path(tmp.name)
        self._git(repo, "init", "-q")
        judge = self._blob(repo, JUDGE.encode())
        hooks_dir = self._tree(repo, [(b"100644", judge, b"judge.py")])

        def commit(settings: str, extra: list[tuple[bytes, bytes, bytes]], parent: bytes | None) -> bytes:
            claude = self._tree(repo, [(b"100644", self._blob(repo, settings.encode()), b"settings.json")])
            root = self._tree(repo, [(b"040000", claude, b".claude"), (b"040000", hooks_dir, b"hooks"), *extra])
            args = ["commit-tree", root.decode(), "-m", "c"] + (["-p", parent.decode()] if parent else [])
            return self._git(repo, *args)

        base = commit(STOP, [], None)
        skill = self._tree(repo, [(b"100644", self._blob(repo, b"skip tripwire\n"), b"SKILL.md")])
        head = commit('{"hooks": {}}', [(b"040000", skill, b"x\xff")], base)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   PYTHONPATH=str(ROOT), PINWASH_TODAY=TODAY)
        proc = subprocess.run(
            [sys.executable, "-m", "pinwash", "check", f"{base.decode()}..{head.decode()}"],
            cwd=repo, env=env, capture_output=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr.decode("utf-8", "replace"))
        payload = json.loads(proc.stdout.decode("utf-8"))
        self.assertIn(("HOOK_REMOVED", "critical"), _rules(payload))
        skills = [f for f in payload["findings"] if f["rule"] == "SKILL_BYPASS"]
        self.assertEqual([f["path"] for f in skills], ["x\udcff/SKILL.md"])
        self.assertIn(b'"x\\udcff/SKILL.md"', proc.stdout)


class QuotedOnKey(unittest.TestCase):
    """SPEC §3.1 / §5: an on: block the bounded grammar cannot resolve is
    unknown `on triggers unresolved`, never an observed trigger removal.
    A quoted column-0 "on" / 'on' key is such a block; its triggers are
    not read (reading them would widen the grammar)."""

    WF = ".github/workflows/ci.yml"
    RULESET = json.dumps({"required_status_checks": ["tripwire"]})
    JOBS = "jobs:\n  tripwire:\n    name: tripwire\n    runs-on: ubuntu-latest\n"
    ON = {"path": WF, "reason": "on triggers unresolved"}

    def _scan(self, base_on: str, head_on: str) -> dict[str, Any]:
        rs = ".github/required-ruleset.json"
        return _pair(
            {self.WF: base_on + self.JOBS, rs: self.RULESET},
            {self.WF: head_on + self.JOBS, rs: self.RULESET},
        )

    def test_parse_records_a_seen_unresolved_block(self) -> None:
        from pinwash.parse.gha import ON_UNRESOLVED, parse_workflow

        for line in ('"on": push', "'on': [push]", '"on":', "'on' : push # why"):
            with self.subTest(line=line):
                parsed = parse_workflow(line + "\n  pull_request:\n" + self.JOBS)
                self.assertTrue(parsed.on_seen)
                self.assertEqual(parsed.triggers, set())
                self.assertIn(ON_UNRESOLVED, parsed.unknown)
                self.assertIn("tripwire", parsed.jobs)

    def test_honest_requote_is_not_a_trigger_removal(self) -> None:
        for head in ('"on": push\n', "'on': push\n", '"on":\n  push:\n'):
            with self.subTest(head=head):
                payload = self._scan("on: push\n", head)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [self.ON])
                self.assertEqual(payload["verdict"], "pass")

    def test_quoted_base_is_no_observation_but_visible(self) -> None:
        for base, head in (
            ('"on": [push, pull_request]\n', '"on": [workflow_dispatch]\n'),
            ("'on': push\n", "on: workflow_dispatch\n"),
            ("on: push\n", '"on":\n  workflow_dispatch:\n'),
        ):
            with self.subTest(base=base, head=head):
                payload = self._scan(base, head)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [self.ON])

    def test_partly_unresolved_head_is_no_observation(self) -> None:
        for head in (
            "on:\n  - workflow_dispatch\n  - {push: {}}\n",
            "on:\n  schedule:\n  - {cron: '0 0 * * *'}\n",
        ):
            with self.subTest(head=head):
                payload = self._scan("on: push\n", head)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [self.ON])

    def test_unresolved_base_items_cannot_hide_an_observed_loss(self) -> None:
        # The base resolved push; an unresolved base item could only add
        # triggers. The head is fully resolved without push or
        # pull_request, so the loss is observed on both sides.
        for base, head in (
            ("on:\n  - push\n  - {pull_request: {}}\n", "on: workflow_dispatch\n"),
            (
                "on:\n  push:\n  schedule:\n  - {cron: '0 0 * * *'}\n",
                "on:\n  schedule:\n    - cron: '0 0 * * *'\n",
            ),
        ):
            with self.subTest(base=base, head=head):
                payload = self._scan(base, head)
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
                self.assertEqual(payload["unknown_coverage"], [self.ON])

    def test_only_the_exact_quoted_key_is_recognised(self) -> None:
        # Not an on: key at all: the block is gone, as before.
        for head in ('"one": push\n', '"on_": push\n', ' "on": push\n'):
            with self.subTest(head=head):
                payload = self._scan("on: push\n", head)
                self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])

    def test_resolved_trigger_loss_still_fires(self) -> None:
        payload = self._scan("on: [push, pull_request]\n", "on: workflow_dispatch\n")
        self.assertEqual(_rules(payload), [("REQUIRED_CHECK_DROPPED", "high")])
        self.assertEqual(payload["findings"][0]["after"], "on: workflow_dispatch")

    def test_tab_handling_unchanged(self) -> None:
        payload = self._scan("on: push\n", '"on":\tpush\n')
        self.assertEqual(_rules(payload), [("SURFACE_UNPARSEABLE", "high")])

if __name__ == "__main__":
    unittest.main()
