"""#44: Stop async runs, but does not preserve a blocking judge."""
import json
import unittest
from pinwash.engine import scan_pair
P = ".claude/settings.json"
C = "python hooks/judge.py"
J = b"print({'decision': 'block'})\n"
def doc(items, **group):
    return {"hooks": {"Stop": [{"hooks": items, **group}]}}
def command(**extra):
    return {"type": "command", "command": C, **extra}
def scan(b, h):
    return scan_pair({P: json.dumps(b).encode(), "hooks/judge.py": J}, {P: json.dumps(h).encode(), "hooks/judge.py": J}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})
class StopAsync(unittest.TestCase):
    def test_sync_to_async_last_stop_blocks(self):
        r = scan(doc([command()]), doc([command(**{"async": True})]))
        self.assertIn(("HOOK_BYPASSED", "critical"), [(f["rule"], f["severity"]) for f in r["findings"]])
    def test_group_async_is_not_inherited(self):
        self.assertEqual(scan(doc([command()]), doc([command()], **{"async": True}))["findings"], [])
    def test_added_notifier_and_unchanged_true_do_not_bypass(self):
        base = doc([command()])
        head = doc([command(), {"type": "command", "command": "echo notification", "async": True}])
        self.assertEqual(scan(base, head)["findings"], [])
        d = doc([command(**{"async": True})])
        self.assertEqual(scan(d, d)["findings"], [])
        self.assertEqual(scan(d, doc([command()]))["findings"], [])
    def test_sync_sibling_keeps_bypass_warn(self):
        b = doc([command(), {"type": "command", "command": "other"}])
        h = doc([command(**{"async": True}), {"type": "command", "command": "other"}])
        self.assertIn(("HOOK_BYPASSED", "warn"), [(f["rule"], f["severity"]) for f in scan(b, h)["findings"]])
    def test_async_copy_cannot_hide_removal(self):
        b = doc([command(), {"type": "command", "command": "other", "async": True}])
        h = doc([{ "type": "command", "command": "other", "async": True}])
        self.assertIn(("HOOK_REMOVED", "critical"), [(f["rule"], f["severity"]) for f in scan(b, h)["findings"]])
