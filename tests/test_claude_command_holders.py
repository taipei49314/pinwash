"""#44: Claude runs commands in hooks[] handlers, not matcher groups."""
import json
import unittest
from pinwash.engine import scan_pair

P = ".claude/settings.json"
C = "python hooks/judge.py"
J = b"print({'decision': 'block'})\n"

def scan(b, h):
    return scan_pair({P: json.dumps(b).encode(), "hooks/judge.py": J}, {P: json.dumps(h).encode(), "hooks/judge.py": J}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})

class ClaudeCommandHolders(unittest.TestCase):
    def test_move_to_group_does_not_keep_live_stop(self):
        b = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": C}]}]}}
        h = {"hooks": {"Stop": [{"command": C, "hooks": []}]}}
        self.assertIn(("HOOK_REMOVED", "critical"), [(f["rule"], f["severity"]) for f in scan(b, h)["findings"]])

    def test_group_command_never_resolves_a_gutted_body(self):
        from pinwash.parse.hookcmd import command_body_map
        doc = {"hooks": {"Stop": [{"command": C, "hooks": []}]}}
        bodies, targets = command_body_map({P: json.dumps(doc).encode(), "hooks/judge.py": J}, claude=True)
        self.assertEqual((bodies, targets), ({}, set()))

    def test_prompt_type_with_command_does_not_make_command_live(self):
        from pinwash.hooks import extract_event_hooks
        from pinwash.parse.hookcmd import command_body_map
        for kind in ("prompt", "agent"):
            with self.subTest(kind=kind):
                handler = {"type": kind, "prompt": "Check completion", "command": C}
                doc = {"hooks": {"Stop": [{"hooks": [handler]}]}}
                info = extract_event_hooks(doc, claude=True)["Stop"]
                self.assertEqual(info["commands"], [])
                self.assertEqual(info["non_commands"], [handler])
                bodies, targets = command_body_map({P: json.dumps(doc).encode(), "hooks/judge.py": J}, claude=True)
                self.assertEqual((bodies, targets), ({}, set()))

    def test_nested_and_unknown_type_commands_do_not_keep_last_stop(self):
        b = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": C}]}]}}
        for holder in ({"hooks": [{"type": "command", "command": C}]},
                       {"type": "unknown", "command": C}):
            with self.subTest(holder=holder):
                h = {"hooks": {"Stop": [{"hooks": [holder]}]}}
                self.assertIn(("HOOK_REMOVED", "critical"),
                              [(f["rule"], f["severity"]) for f in scan(b, h)["findings"]])

    def test_absent_type_compatibility_stays_direct_only(self):
        from pinwash.hooks import extract_event_hooks
        doc = {"hooks": {"Stop": [{"hooks": [{"command": C}]}]}}
        self.assertEqual(extract_event_hooks(doc, claude=True)["Stop"]["commands"], [C])
        doc = {"hooks": [{"event": "Stop", "hooks": [{"command": C}]}]}
        self.assertEqual(extract_event_hooks(doc, claude=True), {})
