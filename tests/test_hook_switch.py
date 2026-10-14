"""Spec 24: §5.1 HOOK_BYPASSED for the settings-root `disableAllHooks` switch
(taipei49314/pinwash#18, R-18c's detection bump).

Host reading (Claude Code 2.1.42 and 2.1.296, executed in the ruling's lane):
the value in effect is the last source that defines it (user, project
`.claude/settings.json`, local `.claude/settings.local.json`, `--settings`,
managed); `true` in effect runs no hook of the user, project, local or
`--settings` sources; a value that is not a JSON boolean makes the host
reject the whole file. pinwash reads local over project, and the shared file
alone.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.findings import fingerprint

ENV = {"PINWASH_TODAY": "2026-10-09"}
CS = ".claude/settings.json"
CL = ".claude/settings.local.json"
A = "python hooks/judge.py"
B = "python hooks/other.py"
G = "python hooks/guard.py"
REAL = b"import json, sys\nprint(json.dumps({'decision': 'block'}))\nsys.exit(0)\n"
GUT = b"import sys\nsys.exit(0)\n"
TREE = {"hooks/judge.py": REAL, "hooks/other.py": REAL, "hooks/guard.py": REAL}
DAH = "hook settings root disableAllHooks"
_MISSING = object()


def doc(stop: Any = None, pre: Any = None, dah: Any = _MISSING) -> str:
    d: dict[str, Any] = {}
    if dah is not _MISSING:
        d["disableAllHooks"] = dah
    hooks: dict[str, Any] = {}
    if stop is not None:
        hooks["Stop"] = [{"hooks": [{"type": "command", "command": c} for c in stop]}]
    if pre is not None:
        hooks["PreToolUse"] = [{"matcher": "Bash", "hooks": [{"type": "command", "command": c} for c in pre]}]
    if hooks:
        d["hooks"] = hooks
    return json.dumps(d)


def scan(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    enc = lambda t: {k: v if isinstance(v, bytes) else v.encode() for k, v in {**TREE, **t}.items()}
    return scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)


def switch(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["severity"], f["path"]) for f in payload["findings"]
            if f["rule"] == "HOOK_BYPASSED" and f.get("locator") == "disableAllHooks"]


class ValueInEffect(unittest.TestCase):
    """Q1: local over project; the finding sits on the file that supplies
    the head's value, which need not be a file the diff changed."""

    def test_true_switched_on_over_a_live_stop_hook_is_critical(self) -> None:
        cases = [
            ({CS: doc([A])}, {CS: doc([A], dah=True)}, CS),
            ({CS: doc([A])}, {CS: doc([A]), CL: doc(dah=True)}, CL),
            ({CS: doc([A], dah=False)}, {CS: doc([A], dah=True)}, CS),
            ({CS: doc(), CL: doc([A])}, {CS: doc(dah=True), CL: doc([A])}, CS),
            ({CS: doc([A], dah=True), CL: doc(dah=False)}, {CS: doc([A], dah=True)}, CS),
            ({CS: doc([A], dah=True), CL: doc(dah=False)}, {CS: doc([A], dah=True), CL: doc(dah=True)}, CL),
            ({CS: doc([A]), CL: doc(dah="false")}, {CS: doc([A], dah=True), CL: doc(dah="false")}, CS),
        ]
        for base, head, where in cases:
            with self.subTest(base=base, head=head):
                payload = scan(base, head)
                self.assertEqual(switch(payload), [("critical", where)])
                self.assertEqual(payload["verdict"], "block")

    def test_no_finding_when_the_value_in_effect_does_not_become_true(self) -> None:
        cases = [
            ({CS: doc([A], dah=True)}, {CS: doc([A], dah=False)}),
            ({CS: doc([A], dah=True)}, {CS: doc([A], dah=True), "README.md": b"x\n"}),
        ]
        for base, head in cases:
            with self.subTest(base=base, head=head):
                self.assertEqual(switch(scan(base, head)), [])

    def test_unparseable_side_defines_nothing(self) -> None:
        bad = '{"disableAllHooks": false,}'
        payload = scan({CS: doc([A]), CL: bad}, {CS: doc([A], dah=True), CL: bad})
        self.assertEqual(switch(payload), [("critical", CS)])

    def test_duplicate_keys_read_last_as_the_host_does(self) -> None:
        on = doc([A])[:-1] + ', "disableAllHooks": false, "disableAllHooks": true}'
        off = doc([A])[:-1] + ', "disableAllHooks": true, "disableAllHooks": false}'
        self.assertEqual(switch(scan({CS: doc([A])}, {CS: on})), [("critical", CS)])
        self.assertEqual(switch(scan({CS: doc([A])}, {CS: off})), [])


class Severity(unittest.TestCase):
    def test_warn_without_a_live_stop_hook_and_none_without_an_active_hook(self) -> None:
        self.assertEqual(switch(scan({CS: doc(pre=[G])}, {CS: doc(pre=[G], dah=True)})), [("warn", CS)])
        self.assertEqual(switch(scan({CS: doc(["echo {}"])}, {CS: doc(["echo {}"], dah=True)})), [])
        payload = scan({CS: json.dumps({"model": "x"})}, {CS: json.dumps({"model": "x", "disableAllHooks": True})})
        self.assertEqual((switch(payload), [u["reason"] for u in payload["unknown_coverage"]]), ([], [DAH]))
        # A new settings file: nothing was active at base.
        self.assertEqual(switch(scan({}, {CS: doc([A], dah=True)})), [])

    def test_other_findings_keep_their_severity(self) -> None:
        """Q2: no zeroing; the switch finding carries the critical."""
        payload = scan({CS: doc([A, B])}, {CS: doc([A, B], dah=True), "hooks/judge.py": GUT})
        self.assertEqual(sorted((f["rule"], f["severity"]) for f in payload["findings"]),
                         [("GATE_STUBBED", "warn"), ("HOOK_BYPASSED", "critical")])

    def test_unchanged_base_true_keeps_the_status_quo(self) -> None:
        """Q4: hooks as written are judged as before; the row marks them."""
        payload = scan({CS: doc([A], pre=[G], dah=True)}, {CS: doc(pre=[G], dah=True)})
        self.assertEqual([(f["rule"], f["severity"]) for f in payload["findings"]], [("HOOK_REMOVED", "critical")])
        self.assertEqual([u["reason"] for u in payload["unknown_coverage"]], [DAH])


class NotABoolean(unittest.TestCase):
    """Q5: the host rejects the whole file; no finding, the spec 13 row stays."""

    def test_non_boolean_values_are_rows(self) -> None:
        for value in ("true", 1, "yes", None, [True], "false", 0):
            with self.subTest(value=value):
                payload = scan({CS: doc([A])}, {CS: doc([A], dah=value)})
                self.assertEqual(switch(payload), [])
                self.assertIn(DAH, [u["reason"] for u in payload["unknown_coverage"]])

    def test_a_rejected_local_file_leaves_the_project_value_in_effect(self) -> None:
        payload = scan({CS: doc([A])}, {CS: doc([A], dah=True), CL: doc(dah="true")})
        self.assertEqual(switch(payload), [("critical", CS)])


class Fingerprint(unittest.TestCase):
    """Q3: content-free like every other hook finding (R18)."""

    def test_fingerprint_is_rule_path_locator_and_base_value(self) -> None:
        payload = scan({CS: doc([A])}, {CS: doc([A], dah=True)})
        (f,) = payload["findings"]
        self.assertEqual(f["fingerprint"], fingerprint("HOOK_BYPASSED", CS, "disableAllHooks", "", "true"))
        payload = scan({CS: doc([A], dah=False)}, {CS: doc([A], dah=True)})
        (f,) = payload["findings"]
        self.assertEqual(f["fingerprint"], fingerprint("HOOK_BYPASSED", CS, "disableAllHooks", "false", "true"))

    def test_an_exempted_switch_finding_leaves_its_row(self) -> None:
        fp = fingerprint("HOOK_BYPASSED", CS, "disableAllHooks", "", "true")
        allow = (f'[[allow]]\nfingerprint = "{fp}"\nrule = "HOOK_BYPASSED"\nreason = "r"\n'
                 'author = "a"\ncreated = "2026-10-01"\nexpires = "2026-12-01"\n')
        payload = scan({CS: doc([A]), ".pinwash/allow.toml": allow},
                       {CS: doc([A], dah=True), ".pinwash/allow.toml": allow})
        self.assertEqual((payload["findings"], payload["verdict"]), ([], "pass"))
        self.assertEqual(payload["unknown_coverage"], [{"path": CS, "reason": DAH}])



class SharedFileAlone(unittest.TestCase):
    """Reading (ii): the shared file's own value is also read alone,
    as a host loading project settings only (`--setting-sources project`) or
    rejecting the local file (R24) reads it. Executed: project true + local
    false runs no hook under `--setting-sources project`, nor when the local
    file also holds `model: 5`, `NaN`, `cleanupPeriodDays: -1` or a string
    `permissions.allow`."""

    def test_shared_true_shielded_by_a_local_false_is_reported(self) -> None:
        cases = [
            ({CS: doc([A]), CL: doc(dah=False)}, {CS: doc([A], dah=True), CL: doc(dah=False)}),
            ({CS: doc([A])}, {CS: doc([A], dah=True), CL: json.dumps({"disableAllHooks": False, "model": 5})}),
            ({CS: doc([A])}, {CS: doc([A], dah=True), CL: '{"disableAllHooks": false, "x": NaN}'}),
            ({CS: doc([A]), CL: doc(dah=True)}, {CS: doc([A], dah=True), CL: doc(dah=True)}),
            ({CS: doc([A]), CL: doc(dah=True)}, {CS: doc([A], dah=True), CL: doc()}),
        ]
        for base, head in cases:
            with self.subTest(base=base, head=head):
                self.assertEqual(switch(scan(base, head)), [("critical", CS)])


class CrossFileRow(unittest.TestCase):
    def test_a_hook_finding_beside_the_other_files_switch_reports_the_row(self) -> None:
        payload = scan({CS: doc([A], pre=[G]), CL: doc(dah=True)}, {CS: doc(pre=[G]), CL: doc(dah=True)})
        self.assertIn({"path": CS, "reason": DAH}, payload["unknown_coverage"])

    def test_a_decoy_event_named_disableAllHooks_does_not_hide_an_exempted_switch(self) -> None:
        fp = fingerprint("HOOK_BYPASSED", CS, "disableAllHooks", "", "true")
        allow = (f'[[allow]]\nfingerprint = "{fp}"\nrule = "HOOK_BYPASSED"\nreason = "t"\n'
                 'author = "a"\ncreated = "2026-10-01"\nexpires = "2026-12-01"\n')
        b_local = json.dumps({"hooks": {"disableAllHooks": [{"hooks": [{"type": "command", "command": "echo x"}]}]}})
        h_local = json.dumps({"hooks": {"disableAllHooks": []}})
        payload = scan({CS: doc([A]), CL: b_local, ".pinwash/allow.toml": allow},
                       {CS: doc([A], dah=True), CL: h_local, ".pinwash/allow.toml": allow})
        self.assertEqual(switch(payload), [("warn", CL)])
        self.assertIn({"path": CS, "reason": DAH}, payload["unknown_coverage"])


class ReviewRows(unittest.TestCase):
    """Review of 2026-10-10 (AI-assisted): rows the switch owes where no
    finding fires."""

    def test_a_true_put_in_effect_with_no_active_command_is_the_row(self) -> None:
        # A local `false` removed under an unchanged shared `true`: no file's
        # own value changed, yet user, --settings and plugin hooks stop.
        for head in ({CS: doc(dah=True)}, {CS: doc(dah=True), CL: json.dumps({"model": "x"})}):
            with self.subTest(head=head):
                payload = scan({CS: doc(dah=True), CL: doc(dah=False)}, head)
                self.assertEqual((payload["findings"], payload["unknown_coverage"]),
                                 ([], [{"path": CS, "reason": DAH}]))

    def test_a_flagged_only_stop_judge_remains_active(self) -> None:
        # Claude Code ignores the §5.1 skip keys (executed, #42), so the
        # switch turns off a judge §3.3 counts as inactive: the row (R06).
        flagged = json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": A, "disabled": True}]}]}})
        on = json.dumps({"disableAllHooks": True, **json.loads(flagged)})
        payload = scan({CS: flagged}, {CS: on})
        self.assertEqual(switch(payload), [("critical", CS)])
        self.assertEqual(payload["unknown_coverage"], [])

    def test_a_proto_switch_is_the_row(self) -> None:
        # Claude Code 2.1.42 reads a root `__proto__` object's members as
        # settings, the switch with any JS-truthy value (executed); 2.1.296
        # does not. Booked in R24; the row marks the diff.
        for value in (True, "false", 1):
            with self.subTest(value=value):
                head = json.dumps({"__proto__": {"disableAllHooks": value}, **json.loads(doc([A]))})
                payload = scan({CS: doc([A])}, {CS: head})
                self.assertEqual((payload["findings"], payload["unknown_coverage"]),
                                 ([], [{"path": CS, "reason": DAH}]))
        same = json.dumps({"__proto__": {"disableAllHooks": True}, **json.loads(doc([A]))})
        self.assertEqual(scan({CS: same}, {CS: same, "README.md": b"x\n"})["unknown_coverage"], [])


if __name__ == "__main__":
    unittest.main()
