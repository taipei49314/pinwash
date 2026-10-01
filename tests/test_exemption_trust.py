"""Exemption trust (issue #17, spec 11): S1 self-exemption and S2 future `created`.

Adding a record whose `created` is after today blocks, and a base record is not
in force while another for the same key is dated after today, so per-record
windows planted in one change cannot be chained (spec 11). Renewing later with
a fresh record stays an ordinary warn addition.

Issue #17's A12 (plant then weaken), S3 and S4 keep their classification and
are not pinned here; tests/test_alpha2_git_cli.py keeps the plant-then-weaken
shape (test_base_exact_fingerprint_exemption_suppresses_finding).
"""

from __future__ import annotations

import json
import unittest
from datetime import date, timedelta
from typing import Any

from pinwash.engine import scan_pair

TODAY = date(2026, 10, 1)
SETTINGS = ".claude/settings.json"
ALLOW = ".pinwash/allow.toml"
CONFIG = ".checkwash/config.toml"
STOP = json.dumps(
    {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python hooks/judge.py"}]}]}}
)
EMPTY = json.dumps({"hooks": {}})


def _day(offset: int) -> str:
    return (TODAY + timedelta(days=offset)).isoformat()


def _scan(base: dict[str, Any], head: dict[str, Any], today: date = TODAY) -> dict[str, Any]:
    to_bytes = lambda files: {
        path: text.encode("utf-8") if isinstance(text, str) else text
        for path, text in files.items()
    }
    return scan_pair(
        to_bytes(base), to_bytes(head), base_label="base", head_label="head",
        env={"PINWASH_TODAY": today.isoformat()},
    )


def _rules(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["rule"], item["severity"]) for item in payload["findings"]]


def _record(
    fingerprint: str,
    rule: str,
    *,
    created: str | None = None,
    expires: str | None = None,
    reason: str = "planned migration",
) -> str:
    lines = [
        "[[allow]]",
        f'fingerprint = "{fingerprint}"',
        f'rule = "{rule}"',
        f'reason = "{reason}"',
        'author = "fixture"',
    ]
    if created != "":
        lines.append(f'created = "{created or _day(-30)}"')
    lines.append(f'expires = "{expires or _day(30)}"')
    return "\n".join(lines) + "\n"


def _only(payload: dict[str, Any], rule: str, path: str) -> str:
    found = [f for f in payload["findings"] if f["rule"] == rule and f["path"] == path]
    if len(found) != 1:
        raise AssertionError(f"expected one {rule} at {path}: {payload['findings']}")
    return found[0]["fingerprint"]


class _Fingerprints(unittest.TestCase):
    """Fingerprints are read from engine output, never computed by the test."""

    @classmethod
    def setUpClass(cls) -> None:
        removal = _scan({SETTINGS: STOP}, {SETTINGS: EMPTY})
        if _rules(removal) != [("HOOK_REMOVED", "critical")]:
            raise AssertionError(f"unexpected removal findings: {removal['findings']}")
        cls.hook_fp = _only(removal, "HOOK_REMOVED", SETTINGS)
        cls.hook_record = _record(cls.hook_fp, "HOOK_REMOVED")
        cls.relaxed_fp = _only(_scan({ALLOW: cls.hook_record}, {}), "CONFIG_RELAXED", ALLOW)
        cls.added_fp = _only(_scan({}, {ALLOW: cls.hook_record}), "EXEMPTION_ADDED", ALLOW)
        config = _scan({CONFIG: 'fail_on = "high"\n'}, {CONFIG: 'fail_on = "critical"\n'})
        cls.config_fp = _only(config, "CONFIG_RELAXED", CONFIG)

    def _removal_with(self, allow_text: str, today: date = TODAY) -> dict[str, Any]:
        files = {SETTINGS: STOP, ALLOW: allow_text}
        return _scan(files, {SETTINGS: EMPTY, ALLOW: allow_text}, today)


class SelfExemption(_Fingerprints):
    """S1: the exemption channel never exempts its own findings."""

    def test_relaxed_record_cannot_silence_edits_or_deletions(self) -> None:
        self_record = _record(self.relaxed_fp, "CONFIG_RELAXED")
        base = {ALLOW: self.hook_record + "\n" + self_record}
        edited_hook = _record(self.hook_fp, "HOOK_REMOVED", reason="edited")
        edited_self = _record(self.relaxed_fp, "CONFIG_RELAXED", reason="edited")
        heads = {
            "delete the other record": {ALLOW: self_record},
            "edit the other record": {ALLOW: edited_hook + "\n" + self_record},
            "edit the self record": {ALLOW: self.hook_record + "\n" + edited_self},
            "delete the self record": {ALLOW: self.hook_record},
            "delete the file": {},
            "corrupt the file": {ALLOW: b"\xff"},
        }
        for name, head in heads.items():
            with self.subTest(head=name):
                payload = _scan(base, head)
                self.assertEqual(_rules(payload), [("CONFIG_RELAXED", "critical")])
                self.assertEqual(payload["verdict"], "block")

    def test_added_record_cannot_hide_additions(self) -> None:
        self_record = _record(self.added_fp, "EXEMPTION_ADDED")
        payload = _scan(
            {ALLOW: self_record}, {ALLOW: self_record + "\n" + self.hook_record}
        )
        self.assertEqual(_rules(payload), [("EXEMPTION_ADDED", "warn")])
        self.assertEqual(payload["verdict"], "pass")

    def test_planted_self_records_stay_visible_across_runs(self) -> None:
        planted = (
            _record(self.relaxed_fp, "CONFIG_RELAXED") + "\n"
            + _record(self.added_fp, "EXEMPTION_ADDED")
        )
        self.assertEqual(_rules(_scan({}, {ALLOW: planted})), [("EXEMPTION_ADDED", "warn")])
        self.assertEqual(
            _rules(_scan({ALLOW: planted}, {})), [("CONFIG_RELAXED", "critical")]
        )
        self.assertEqual(
            _rules(_scan({ALLOW: planted}, {ALLOW: planted + "\n" + self.hook_record})),
            [("EXEMPTION_ADDED", "warn")],
        )

    def test_ordinary_exemption_still_applies_next_to_self_records(self) -> None:
        allow_text = (
            self.hook_record + "\n"
            + _record(self.relaxed_fp, "CONFIG_RELAXED") + "\n"
            + _record(self.added_fp, "EXEMPTION_ADDED")
        )
        payload = self._removal_with(allow_text)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "pass")

    def test_checkwash_config_relaxation_stays_exemptible(self) -> None:
        base_config, head_config = 'fail_on = "high"\n', 'fail_on = "critical"\n'
        bare = _scan({CONFIG: base_config}, {CONFIG: head_config})
        self.assertEqual(_rules(bare), [("CONFIG_RELAXED", "high")])
        allow_text = _record(self.config_fp, "CONFIG_RELAXED")
        exempted = _scan(
            {CONFIG: base_config, ALLOW: allow_text}, {CONFIG: head_config, ALLOW: allow_text}
        )
        self.assertEqual(exempted["findings"], [])


class FutureCreated(_Fingerprints):
    """S2: the 180 days run from min(created, today), never from a future `created`."""

    def test_far_future_created_does_not_exempt(self) -> None:
        record = _record(self.hook_fp, "HOOK_REMOVED", created="9999-01-01", expires="9999-06-30")
        payload = self._removal_with(record)
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_window_boundaries_from_today(self) -> None:
        cases = [
            (_day(0), _day(180), True),
            (_day(0), _day(181), False),
            (_day(1), _day(181), False),  # in force under spec 10's created anchor
            (_day(1), _day(180), True),
            (_day(-1), _day(179), True),
            (_day(-30), _day(30), True),
        ]
        for created, expires, exempt in cases:
            with self.subTest(created=created, expires=expires):
                record = _record(self.hook_fp, "HOOK_REMOVED", created=created, expires=expires)
                payload = self._removal_with(record)
                expected = [] if exempt else [("HOOK_REMOVED", "critical")]
                self.assertEqual(_rules(payload), expected)

    def test_future_record_comes_into_force_180_days_before_expiry(self) -> None:
        record = _record(self.hook_fp, "HOOK_REMOVED", created=_day(30), expires=_day(200))
        for offset, exempt in ((0, False), (19, False), (20, True), (200, True), (201, False)):
            with self.subTest(today=_day(offset)):
                payload = self._removal_with(record, TODAY + timedelta(days=offset))
                expected = [] if exempt else [("HOOK_REMOVED", "critical")]
                self.assertEqual(_rules(payload), expected)

    def test_future_records_block_when_added_and_stay_visible(self) -> None:
        for created, expires in ((_day(30), _day(200)), ("9999-01-01", "9999-06-30")):
            with self.subTest(created=created, expires=expires):
                record = _record(self.hook_fp, "HOOK_REMOVED", created=created, expires=expires)
                added = _scan({}, {ALLOW: record})
                self.assertEqual(_rules(added), [("EXEMPTION_ADDED", "critical")])
                self.assertEqual(added["verdict"], "block")
                self.assertEqual(
                    _rules(_scan({ALLOW: record}, {})), [("CONFIG_RELAXED", "critical")]
                )
                edited = _record(
                    self.hook_fp, "HOOK_REMOVED", created=created, expires=expires, reason="edited"
                )
                self.assertEqual(
                    _rules(_scan({ALLOW: record}, {ALLOW: edited})), [("CONFIG_RELAXED", "critical")]
                )

    def test_any_future_dated_addition_blocks(self) -> None:
        honest = _record(self.hook_fp, "HOOK_REMOVED", created=_day(0), expires=_day(180))
        self.assertEqual(_rules(_scan({}, {ALLOW: honest})), [("EXEMPTION_ADDED", "warn")])
        future = _record(self.hook_fp, "HOOK_REMOVED", created=_day(1), expires=_day(181))
        payload = _scan({ALLOW: honest}, {ALLOW: honest + "\n" + future})
        self.assertEqual(_rules(payload), [("EXEMPTION_ADDED", "critical")])

    def test_chained_windows_block_when_planted(self) -> None:
        """Per-record windows that follow one another would keep one fingerprint
        exempt past 180 days; the plant needs future dates, so it blocks."""
        chain = "\n".join(
            _record(self.hook_fp, "HOOK_REMOVED", created=_day(start), expires=_day(start + 180))
            for start in (0, 180, 360)
        )
        payload = _scan({SETTINGS: STOP}, {SETTINGS: STOP, ALLOW: chain})
        self.assertEqual(_rules(payload), [("EXEMPTION_ADDED", "critical")])
        self.assertEqual(payload["verdict"], "block")

    def test_chain_already_in_base_shrinks_to_its_last_record(self) -> None:
        chain = "\n".join(
            _record(self.hook_fp, "HOOK_REMOVED", created=_day(start), expires=_day(start + 180))
            for start in (0, 180, 360)
        )
        for offset, exempt in ((0, False), (200, False), (359, False), (400, True), (540, True), (541, False)):
            with self.subTest(today=_day(offset)):
                payload = self._removal_with(chain, TODAY + timedelta(days=offset))
                expected = [] if exempt else [("HOOK_REMOVED", "critical")]
                self.assertEqual(_rules(payload), expected)

    def test_overlapping_renewal_stays_in_force(self) -> None:
        renewal = "\n".join([
            _record(self.hook_fp, "HOOK_REMOVED", created=_day(-170), expires=_day(10)),
            _record(self.hook_fp, "HOOK_REMOVED", created=_day(-5), expires=_day(175)),
        ])
        for offset in (0, 10, 11, 175):
            with self.subTest(today=_day(offset)):
                payload = self._removal_with(renewal, TODAY + timedelta(days=offset))
                self.assertEqual(payload["findings"], [])
        self.assertEqual(
            _rules(self._removal_with(renewal, TODAY + timedelta(days=176))),
            [("HOOK_REMOVED", "critical")],
        )

    def test_created_near_the_last_date_does_not_error(self) -> None:
        record = _record(self.hook_fp, "HOOK_REMOVED", created="9999-12-01", expires="9999-12-31")
        payload = self._removal_with(record)
        self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])

    def test_malformed_or_missing_created_never_exempts(self) -> None:
        for created in ("2026-13-01", "soon", ""):
            with self.subTest(created=created or "missing"):
                record = _record(self.hook_fp, "HOOK_REMOVED", created=created)
                if created == "":
                    self.assertNotIn("created", record)
                payload = self._removal_with(record)
                self.assertEqual(_rules(payload), [("HOOK_REMOVED", "critical")])


if __name__ == "__main__":
    unittest.main()
