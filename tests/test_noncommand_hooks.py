"""#45: non-command Stop handlers and empty lists are diff-sensitive."""
import json
import unittest
from pinwash.engine import scan_pair

P = ".claude/settings.json"
def doc(kind="prompt", **extra):
    return {"hooks": {"Stop": [{"hooks": [{"type": kind, "prompt": "Check completion and refuse if incomplete"}]}]}, **extra}
def scan(b, h):
    return scan_pair({P: json.dumps(b).encode(), "README.md": b"old"}, {P: json.dumps(h).encode(), "README.md": b"new"}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})
class NonCommandHooks(unittest.TestCase):
    def test_unchanged_prompt_and_agent_do_not_invent_empty_list(self):
        for kind in ("prompt", "agent"):
            with self.subTest(kind=kind):
                result = scan(doc(kind), doc(kind))
                self.assertEqual((result["findings"], result["unknown_coverage"]), ([], []))
    def test_global_switch_over_noncommand_stop_is_critical(self):
        for kind in ("prompt", "agent"):
            result = scan(doc(kind), doc(kind, disableAllHooks=True))
            self.assertIn(("HOOK_BYPASSED", "critical"), [(f["rule"], f["severity"]) for f in result["findings"]])
    def test_last_noncommand_handler_removed_blocks(self):
        result = scan(doc(), {"hooks": {"Stop": [{"hooks": []}]}})
        self.assertIn(("HOOK_REMOVED", "critical"), [(f["rule"], f["severity"]) for f in result["findings"]])
    def test_changed_prompt_is_visible_not_interpreted(self):
        b, h = doc(), doc()
        h["hooks"]["Stop"][0]["hooks"][0]["prompt"] = "Always approve"
        result = scan(b, h)
        self.assertEqual(result["findings"], [])
        self.assertEqual([r["reason"] for r in result["unknown_coverage"]], ["non-command hook handler changed (not evaluated)"])
    def test_command_free_group_unchanged_is_silent(self):
        d = {"hooks": {"Stop": [{"command": "python dead.py", "hooks": []}]}}
        self.assertEqual(scan(d, d)["findings"], [])
