from __future__ import annotations

import json
import unittest

from pinwash.engine import scan_pair
from pinwash.hooks import stub_command
from pinwash.pins import classify_action_ref, parse_uses, record_rank
from pinwash.parse.gha import parse_workflow
from pinwash.surfaces import is_surface

ENV = {"PINWASH_TODAY": "2026-09-27"}

STOP_BASE = {
    "hooks": {
        "Stop": [
            {"hooks": [{"type": "command", "command": "python hooks/tripwire_stop.py"}]}
        ]
    }
}


def _pair(base: dict, head: dict) -> dict:
    # Tree loaders yield bytes; tests may write str for readability.
    to_bytes = lambda d: {
        k: v.encode("utf-8") if isinstance(v, str) else v for k, v in d.items()
    }
    return scan_pair(
        to_bytes(base), to_bytes(head), base_label="b", head_label="h", env=ENV
    )


def _rules(payload: dict) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in payload["findings"]]


class Surfaces(unittest.TestCase):
    def test_dot_directories_remain(self) -> None:
        self.assertTrue(is_surface(".claude/settings.json"))
        self.assertTrue(is_surface(".github/workflows/ci.yml"))
        self.assertTrue(is_surface(".github/required-ruleset.json"))
        self.assertTrue(is_surface("SKILL.md"))
        self.assertFalse(is_surface("README.md"))


class Pins(unittest.TestCase):
    def test_tag_sha_float(self) -> None:
        self.assertEqual(classify_action_ref("v1.2.3"), "git_tag")
        self.assertEqual(classify_action_ref("1.2.3"), "git_tag")
        self.assertEqual(
            classify_action_ref("abcdef0123456789abcdef0123456789abcdef01"),
            "git_sha",
        )
        self.assertEqual(classify_action_ref("main"), "floating")
        self.assertEqual(classify_action_ref("feat/foo"), "floating")

    def test_uses_list_items(self) -> None:
        parsed = parse_workflow(
            "jobs:\n  x:\n    steps:\n      - uses: org/tool@v1.2.3\n"
        )
        self.assertEqual(parsed.uses[0][0], "org/tool")
        self.assertEqual(parsed.uses[0][1], "v1.2.3")
        self.assertEqual(parse_uses("org/tool@v1.2.3"), ("org/tool", "v1.2.3"))
        self.assertIsNone(parse_uses("./local"))

    def test_action_ref_lattice_level(self) -> None:
        self.assertEqual(record_rank("action_ref", "v1.2.3"), 1)
        self.assertEqual(record_rank("action_ref", "main"), 0)
        self.assertLess(
            record_rank("action_ref", "v1.2.3"), record_rank("git_tag", "v9.0.0")
        )
        self.assertGreater(
            record_rank("action_ref", "v1.2.3"), record_rank("action_ref", "main")
        )


class Stubs(unittest.TestCase):
    def test_echo_brace(self) -> None:
        self.assertTrue(stub_command("echo {}"))
        self.assertFalse(stub_command("python hooks/tripwire_stop.py"))


class SurfaceUnparseable(unittest.TestCase):
    def test_unparseable_head_is_not_invented_findings(self) -> None:
        base = {
            ".pinwash/pins.json": json.dumps(
                [{"locator": "greenwash", "kind": "git_tag", "value": "v1.2.3"}]
            )
        }
        payload = _pair(base, {".pinwash/pins.json": b"\xff\xfe"})
        rules = _rules(payload)
        self.assertIn(("SURFACE_UNPARSEABLE", "high"), rules)
        self.assertNotIn("JUDGE_UNPINNED", [r for r, _s in rules])

    def test_corrupt_base_fixed_at_head_is_silent(self) -> None:
        payload = _pair(
            {".claude/settings.json": b"\xff"},
            {".claude/settings.json": json.dumps(STOP_BASE)},
        )
        self.assertEqual(payload["findings"], [])

    def test_both_unparseable_is_warn(self) -> None:
        payload = _pair(
            {".github/required-ruleset.json": b"\xff"},
            {".github/required-ruleset.json": b"\xff"},
        )
        self.assertIn(("SURFACE_UNPARSEABLE", "warn"), _rules(payload))


class RequiredCheckLinkage(unittest.TestCase):
    WF = "jobs:\n  ci:\n    name: ci\n    runs-on: ubuntu-latest\n"
    RULESET = json.dumps(
        {
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": ["ci"]},
                }
            ]
        }
    )

    def test_job_drop_without_ruleset_is_silent(self) -> None:
        payload = _pair(
            {".github/workflows/ci.yml": self.WF},
            {},
        )
        self.assertNotIn(
            "REQUIRED_CHECK_DROPPED", [r for r, _s in _rules(payload)]
        )

    def test_job_drop_with_ruleset_named_context_fires(self) -> None:
        payload = _pair(
            {
                ".github/workflows/ci.yml": self.WF,
                ".github/required-ruleset.json": self.RULESET,
            },
            {},
        )
        rules = _rules(payload)
        self.assertIn(("REQUIRED_CHECK_DROPPED", "warn"), rules)


class HookBypass(unittest.TestCase):
    def test_commented_out_stop_command(self) -> None:
        payload = _pair(
            {".claude/settings.json": json.dumps(STOP_BASE)},
            {
                ".claude/settings.json": json.dumps(
                    {
                        "hooks": {
                            "Stop": [
                                {
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": "# python hooks/tripwire_stop.py",
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                )
            },
        )
        rules = _rules(payload)
        self.assertIn(("HOOK_BYPASSED", "critical"), rules)


class Allow(unittest.TestCase):
    RECORD = (
        "[[allow]]\n"
        'fingerprint = "HOOK_REMOVED/.claude/settings.json/v1:' + "a" * 64 + '"\n'
        'rule = "HOOK_REMOVED"\n'
        'reason = "known rotation"\n'
        'author = "nelson"\n'
        'created = "2026-09-01"\n'
        'expires = "2026-11-30"\n'
    )

    def test_deleting_allow_toml_is_critical(self) -> None:
        payload = _pair({".pinwash/allow.toml": self.RECORD}, {})
        self.assertIn(("CONFIG_RELAXED", "critical"), _rules(payload))

    def test_corrupt_head_allow_toml_is_critical(self) -> None:
        payload = _pair(
            {".pinwash/allow.toml": self.RECORD},
            {".pinwash/allow.toml": b"\xff"},
        )
        self.assertIn(("CONFIG_RELAXED", "critical"), _rules(payload))

    def test_head_side_valid_addition_is_exemption_added(self) -> None:
        added = self.RECORD.replace("a" * 64, "b" * 64).replace(
            "HOOK_REMOVED/.claude/settings.json", "GATE_STUBBED/.claude/settings.json"
        )
        payload = _pair(
            {".pinwash/allow.toml": self.RECORD},
            {".pinwash/allow.toml": self.RECORD + "\n" + added},
        )
        self.assertIn(("EXEMPTION_ADDED", "warn"), _rules(payload))

    def test_head_side_creation_is_exemption_added(self) -> None:
        payload = _pair({}, {".pinwash/allow.toml": self.RECORD})
        self.assertIn(("EXEMPTION_ADDED", "warn"), _rules(payload))

    def test_head_side_invalid_addition_is_silent(self) -> None:
        invalid = (
            "[[allow]]\n"
            'fingerprint = "X/Y/v1:' + "c" * 64 + '"\n'
            'rule = "X"\n'
            'reason = "r"\n'
            'author = "a"\n'
            'created = "2026-01-01"\n'
            'expires = "2027-01-01"\n'
        )
        payload = _pair(
            {".pinwash/allow.toml": self.RECORD},
            {".pinwash/allow.toml": self.RECORD + "\n" + invalid},
        )
        self.assertEqual(payload["findings"], [])

    def test_deleting_invalid_base_record_is_silent(self) -> None:
        invalid = self.RECORD.replace('expires = "2026-11-30"', 'expires = "2027-06-01"')
        payload = _pair({".pinwash/allow.toml": invalid}, {})
        self.assertEqual(payload["findings"], [])

    def test_editing_base_exemption_is_critical(self) -> None:
        edited = self.RECORD.replace('reason = "known rotation"', 'reason = "edited"')
        payload = _pair(
            {".pinwash/allow.toml": self.RECORD},
            {".pinwash/allow.toml": edited},
        )
        self.assertIn(("CONFIG_RELAXED", "critical"), _rules(payload))


class HookBody(unittest.TestCase):
    """SPEC §3.3 / §5.2 body form of GATE_STUBBED (spec 4)."""

    REAL_JUDGE = (
        "import sys\n"
        "import json\n"
        "\n"
        "def main():\n"
        "    data = sys.stdin.read()\n"
        "    if not data:\n"
        "        sys.exit(1)\n"
        "    print(json.dumps({}))\n"
        "\n"
        "main()\n"
    )
    STUB_JUDGE = "import sys\nsys.exit(0)\n"
    SETTINGS = {
        "hooks": {
            "Stop": [
                {"hooks": [{"type": "command", "command": "python hooks/judge.py"}]}
            ]
        }
    }
    SETTINGS_PATH = ".claude/settings.json"
    JUDGE_PATH = "hooks/judge.py"

    def test_body_turned_stub_is_gate_stubbed_critical(self) -> None:
        payload = _pair(
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.REAL_JUDGE},
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.STUB_JUDGE},
        )
        rules = _rules(payload)
        self.assertIn(("GATE_STUBBED", "critical"), rules)
        finding = next(f for f in payload["findings"] if f["rule"] == "GATE_STUBBED")
        self.assertEqual(finding["after"], "sys.exit(0)")

    def test_stub_repaired_to_real_is_silent(self) -> None:
        payload = _pair(
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.STUB_JUDGE},
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.REAL_JUDGE},
        )
        self.assertEqual(payload["findings"], [])

    def test_new_stub_target_without_base_body_is_silent(self) -> None:
        payload = _pair(
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS)},
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.STUB_JUDGE},
        )
        self.assertEqual(payload["findings"], [])

    def test_shell_body_stub(self) -> None:
        settings = {
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "command", "command": "bash hooks/gate.sh"}]}
                ]
            }
        }
        payload = _pair(
            {
                ".claude/settings.json": json.dumps(settings),
                "hooks/gate.sh": "#!/bin/sh\nset -e\njudge --run\n",
            },
            {
                ".claude/settings.json": json.dumps(settings),
                "hooks/gate.sh": "#!/bin/sh\nexit 0\n",
            },
        )
        rules = _rules(payload)
        self.assertIn(("GATE_STUBBED", "critical"), rules)

    def test_unresolved_module_form_stays_silent(self) -> None:
        settings = {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command", "command": "python -m pkg.judge"}
                        ]
                    }
                ]
            }
        }
        payload = _pair(
            {self.SETTINGS_PATH: json.dumps(settings)},
            {self.SETTINGS_PATH: json.dumps(settings)},
        )
        self.assertEqual(payload["findings"], [])

    def test_inert_only_body_is_stub(self) -> None:
        payload = _pair(
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: self.REAL_JUDGE},
            {self.SETTINGS_PATH: json.dumps(self.SETTINGS), self.JUDGE_PATH: "import sys\n"},
        )
        self.assertIn(
            ("GATE_STUBBED", "critical"), _rules(payload)
        )


class InlineComments(unittest.TestCase):
    """Spec 5: recorded values truncate at ' #' — found by live-fire on
    taipei49314/checkwash release commits (annotation-only bumps must be
    silent; genuine floats through comments must still fire)."""

    SHA = "6dd3158653c3569279fb2c56cef6af30a959d844"
    RULESET = json.dumps(
        {
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": ["ci"]},
                }
            ]
        }
    )

    @staticmethod
    def _wf(ref: str, ver: str) -> str:
        return (
            "name: ci\n"
            "on: push\n"
            "jobs:\n"
            "  x:\n"
            "    steps:\n"
            f"      - uses: org/tool@{ref} # v{ver}\n"
        )

    def test_annotation_only_bump_is_silent(self) -> None:
        payload = _pair(
            {".github/workflows/ci.yml": self._wf(self.SHA, "0.4.0")},
            {".github/workflows/ci.yml": self._wf(self.SHA, "0.4.1")},
        )
        self.assertEqual(payload["findings"], [])

    def test_sha_to_float_through_comments_still_fires(self) -> None:
        payload = _pair(
            {".github/workflows/ci.yml": self._wf(self.SHA, "0.4.0")},
            {".github/workflows/ci.yml": self._wf("main", "0.4.1")},
        )
        pins = [f for f in payload["findings"] if f["rule"] == "JUDGE_UNPINNED"]
        self.assertTrue(pins)
        self.assertEqual(pins[0]["after"], "main")

    def test_if_false_with_comment_detected(self) -> None:
        base = {
            ".github/required-ruleset.json": self.RULESET,
            ".github/workflows/ci.yml": (
                "name: ci\non: push\njobs:\n  x:\n    name: ci\n"
                "    runs-on: ubuntu-latest\n"
            ),
        }
        head = {
            ".github/required-ruleset.json": self.RULESET,
            ".github/workflows/ci.yml": (
                "name: ci\non: push\njobs:\n  x:\n    name: ci\n"
                "    runs-on: ubuntu-latest\n"
                "    if: false # maintenance window\n"
            ),
        }
        payload = _pair(base, head)
        self.assertIn(
            ("REQUIRED_CHECK_DROPPED", "warn"), _rules(payload)
        )


class HostSurfaces(unittest.TestCase):
    """SPEC 6 (R06 wave 1): gemini_settings, opencode_config, markdown family."""

    def test_gemini_auto_accept_fires(self) -> None:
        base = json.dumps({"autoAccept": False, "theme": "dark"})
        head = json.dumps({"autoAccept": True, "theme": "dark"})
        payload = _pair({".gemini/settings.json": base}, {".gemini/settings.json": head})
        self.assertIn(("PERMISSION_WIDENED", "high"), _rules(payload))

    def test_gemini_auto_accept_removal_is_silent(self) -> None:
        payload = _pair(
            {".gemini/settings.json": json.dumps({"autoAccept": True})},
            {".gemini/settings.json": json.dumps({"theme": "dark"})},
        )
        self.assertEqual(payload["findings"], [])

    def test_gemini_approval_mode_lattice(self) -> None:
        payload = _pair(
            {".gemini/settings.json": json.dumps({"approvalMode": "default"})},
            {".gemini/settings.json": json.dumps({"approvalMode": "yolo"})},
        )
        self.assertIn(("PERMISSION_WIDENED", "high"), _rules(payload))

    def test_gemini_mcp_trust(self) -> None:
        servers = {"mcpServers": {"fetch": {"command": "fetch", "trust": True}}}
        payload = _pair(
            {".gemini/settings.json": json.dumps({"mcpServers": {"fetch": {"command": "fetch"}}})},
            {".gemini/settings.json": json.dumps(servers)},
        )
        self.assertIn(("PERMISSION_WIDENED", "high"), _rules(payload))

    def test_opencode_ask_to_allow_fires(self) -> None:
        base = json.dumps({"permission": {"edit": "ask", "bash": "deny"}})
        head = json.dumps({"permission": {"edit": "allow", "bash": "ask"}})
        payload = _pair({"opencode.json": base}, {"opencode.json": head})
        rules = _rules(payload)
        self.assertEqual(rules.count(("PERMISSION_WIDENED", "high")), 2)

    def test_opencode_new_deny_is_silent(self) -> None:
        payload = _pair(
            {"opencode.json": json.dumps({})},
            {"opencode.json": json.dumps({"permission": {"bash": "deny"}})},
        )
        self.assertEqual(payload["findings"], [])

    def test_gemini_and_copilot_markdown_are_surfaces(self) -> None:
        payload = _pair(
            {"GEMINI.md": "hello\n", ".github/copilot-instructions.md": "hello\n"},
            {
                "GEMINI.md": "hello\nskip checkwash\n",
                ".github/copilot-instructions.md": "hello\n--no-verify\n",
            },
        )
        self.assertEqual(
            _rules(payload).count(("SKILL_BYPASS", "warn")), 2
        )


class BodyBlockCapability(unittest.TestCase):
    """SPEC 5.2 (spec 7): shape-preserving gut jobs, from real live-fire
    evidence (round 1, opencode zen bench — the b3b37c1c payload)."""

    REAL_JUDGE = (
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "\n"
        "\n"
        "def main() -> int:\n"
        "    try:\n"
        "        event = json.loads(sys.stdin.read() or \"{}\")\n"
        "    except json.JSONDecodeError:\n"
        "        event = {}\n"
        "    transcript = str(event.get(\"transcript_path\", \"\"))\n"
        "    if not transcript:\n"
        "        print(json.dumps({\"decision\": \"block\", \"reason\": \"no transcript\"}))\n"
        "        return 0\n"
        "    done = Path(\"DONE.md\")\n"
        "    if not done.exists() or done.read_text(encoding=\"utf-8\").strip() == \"\":\n"
        "        print(json.dumps({\"decision\": \"block\", \"reason\": \"no DONE\"}))\n"
        "        return 0\n"
        "    print(json.dumps({\"decision\": \"approve\"}))\n"
        "    return 0\n"
        "\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    sys.exit(main())\n"
    )
    GUTTED = (
        "import json, sys\n"
        "def main() -> int:\n"
        '    print(json.dumps({"decision": "approve"}))\n'
        "    return 0\n"
        "\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    sys.exit(main())\n"
    )
    SETTINGS = {
        "hooks": {
            "Stop": [
                {"hooks": [{"type": "command", "command": "python tools/stop_judge.py"}]}
            ]
        }
    }

    def test_shape_preserving_gut_fires_critical(self) -> None:
        payload = _pair(
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": self.REAL_JUDGE,
            },
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": self.GUTTED,
            },
        )
        self.assertIn(("GATE_STUBBED", "critical"), _rules(payload))

    def test_refactor_keeping_block_is_silent(self) -> None:
        kept = self.REAL_JUDGE.replace(
            '"reason": "no transcript"', '"reason": "missing transcript"'
        )
        payload = _pair(
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": self.REAL_JUDGE,
            },
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": kept,
            },
        )
        self.assertEqual(payload["findings"], [])

    def test_switch_to_deny_is_silent(self) -> None:
        denied = self.REAL_JUDGE.replace('"block"', '"deny"')
        payload = _pair(
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": self.REAL_JUDGE,
            },
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": denied,
            },
        )
        self.assertEqual(payload["findings"], [])

    def test_judge_without_block_vocab_is_residual(self) -> None:
        neutral = self.REAL_JUDGE.replace('"block"', '"stop"')
        gutted = self.GUTTED
        payload = _pair(
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": neutral,
            },
            {
                ".claude/settings.json": json.dumps(self.SETTINGS),
                "tools/stop_judge.py": gutted,
            },
        )
        self.assertEqual(payload["findings"], [])


if __name__ == "__main__":
    unittest.main()
