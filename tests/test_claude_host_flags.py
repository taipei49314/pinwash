"""Spec 28, #42: host-neutral Claude flags are not command bypasses."""
import json
import unittest
from pinwash.engine import scan_pair

P = ".claude/settings.json"
C = "python hooks/judge.py"
J = b"print({'decision': 'block'})\n"

def doc(**flags):
    return json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": C, **flags}]}]}}).encode()

def pair(base, head):
    return scan_pair({P: base, "hooks/judge.py": J}, {P: head, "hooks/judge.py": J}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})

class ClaudeHostFlags(unittest.TestCase):
    def test_host_neutral_flags_do_not_bypass(self):
        for key, value in (("disabled", True), ("hookEnabled", False), ("continueOnError", True), ("failOpen", True), ("enabled", False)):
            with self.subTest(key=key):
                self.assertEqual(pair(doc(), doc(**{key: value}))["findings"], [])

    def test_flags_do_not_hide_global_switch_off(self):
        base = doc(disabled=True)
        head = json.loads(base)
        head["disableAllHooks"] = True
        result = pair(base, json.dumps(head).encode())
        self.assertEqual([(f["rule"], f["severity"]) for f in result["findings"]], [("HOOK_BYPASSED", "critical")])

    def test_nonboolean_ignored_flags_do_not_create_skip_rows(self):
        self.assertEqual(pair(doc(), doc(disabled="true"))["unknown_coverage"], [])

    def test_flags_do_not_hide_selector_observation(self):
        base = json.loads(doc(disabled=True))
        head = json.loads(doc(disabled=True))
        base["hooks"]["Stop"][0]["matcher"] = "*"
        head["hooks"]["Stop"][0]["matcher"] = "Narrow"
        self.assertIn("hook selector changed (not evaluated)", [r["reason"] for r in pair(json.dumps(base).encode(), json.dumps(head).encode())["unknown_coverage"]])
