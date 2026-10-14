"""#44: event-key compatibility and non-boolean async are visibility only."""
import json
import unittest
from pinwash.engine import scan_pair
P = ".claude/settings.json"
def scan(b, h):
    return scan_pair({P: json.dumps(b).encode()}, {P: json.dumps(h).encode()}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})
class HookEventCoverage(unittest.TestCase):
    def test_event_additions_are_visible_without_version_guess(self):
        for event in ("Zzz", "stop", "WorktreeCreate", "Stop"):
            result = scan({"hooks": {}}, {"hooks": {event: []}})
            self.assertEqual(result["findings"], [])
            self.assertIn("hook event keys changed (host validity not evaluated)", [r["reason"] for r in result["unknown_coverage"]])
    def test_unchanged_unknown_key_is_not_standing_noise(self):
        d = {"hooks": {"Zzz": []}}
        self.assertEqual(scan(d, d)["unknown_coverage"], [])
    def test_nonboolean_async_is_not_coerced_to_a_bypass(self):
        b = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "judge"}]}]}}
        h = json.loads(json.dumps(b))
        h["hooks"]["Stop"][0]["hooks"][0]["async"] = "true"
        result = scan(b, h)
        self.assertEqual(result["findings"], [])
        self.assertIn("hook async value not boolean", [r["reason"] for r in result["unknown_coverage"]])
