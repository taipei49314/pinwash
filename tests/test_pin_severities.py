"""Spec 15: pin severities and declared-pin values (SPEC §4, §6.3; R04, R15;
#26 items 1 and 7, AI-assisted rulings R-26.1, R-26.1b and R-26.7).

A workflow pin escalates only when a non-floating pin (`git_sha` or `git_tag`
by the §4 table) is floated, or removed while its workflow remains and the
head file then keeps no non-floating pin. Every declared-pin unpin event is
high. A declared record whose kind or value changes off the unpin list is a
`warn` row, and a `digest_sha256` value is non-floating only in its closed
form.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

ENV = {"PINWASH_TODAY": "2026-10-09"}
W = ".github/workflows/ci.yml"
P = ".pinwash/pins.json"
SHA_A = "b4ffde65f46336ab88eb53be808477a3936bae11"
SHA_B = "6dd3158653c3569279fb2c56cef6af30a959d844"


def _pair(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair(
        {k: v.encode("utf-8") for k, v in base.items()},
        {k: v.encode("utf-8") for k, v in head.items()},
        base_label="base", head_label="head", env=ENV,
    )


def _wf(*uses: str) -> str:
    steps = "".join(f"      - uses: {u}\n" for u in uses)
    return f"name: ci\non: push\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n{steps}      - run: make test\n"


def _pins(*records: tuple[str, str, str]) -> str:
    return json.dumps([{"locator": loc, "kind": k, "value": v} for loc, k, v in records])


def _unpinned(base: dict[str, str], head: dict[str, str]) -> list[tuple[str, str, str]]:
    return [
        (f["rule"], f["severity"], f["message"])
        for f in _pair(base, head)["findings"]
        if f["rule"] == "JUDGE_UNPINNED"
    ]


class WorkflowPinSeverities(unittest.TestCase):
    """SPEC §6.3 (R-26.1, option C as amended)."""

    def test_non_floating_pin_removed(self) -> None:
        # Critical when the head file keeps no non-floating pin; warn while
        # another stays (R15 books that removal).
        for kept, severity in ((f"actions/checkout@{SHA_A}", "warn"), ("actions/checkout@v4", "critical")):
            for ref in (SHA_B, "v1.2.0"):
                with self.subTest(kept=kept, ref=ref):
                    self.assertEqual(
                        _unpinned({W: _wf(kept, f"org/tool@{ref}")}, {W: _wf(kept)}),
                        [("JUDGE_UNPINNED", severity, "action pin removed while workflow remains")],
                    )

    def test_floating_ref_removed_stays_warn(self) -> None:
        for ref in ("v1", "main"):
            with self.subTest(ref=ref):
                self.assertEqual(
                    _unpinned({W: _wf("actions/checkout@v4", f"org/tool@{ref}")}, {W: _wf("actions/checkout@v4")}),
                    [("JUDGE_UNPINNED", "warn", "action pin removed while workflow remains")],
                )

    def test_non_floating_pin_moved_to_floating(self) -> None:
        for before in (SHA_B, "v1.2.3"):
            for kept, severity in ((f"actions/checkout@{SHA_A}", "high"), ("actions/checkout@v4", "critical")):
                with self.subTest(before=before, kept=kept):
                    self.assertEqual(
                        _unpinned({W: _wf(kept, f"org/tool@{before}")}, {W: _wf(kept, "org/tool@main")}),
                        [("JUDGE_UNPINNED", severity, "action pin weakened")],
                    )

    def test_floating_to_floating_and_kind_drop_stay_warn(self) -> None:
        # R-26.1b: a workflow sha -> dotted tag stays warn (a declared one is
        # high, below).
        for before, after in (("v3", "v4"), ("v1", "main"), (SHA_B, "v1.2.0")):
            with self.subTest(before=before, after=after):
                self.assertEqual(
                    _unpinned({W: _wf(f"org/tool@{before}")}, {W: _wf(f"org/tool@{after}")}),
                    [("JUDGE_UNPINNED", "warn", "action pin weakened")],
                )

    def test_sha_bump_and_file_deletion_are_silent(self) -> None:
        base = {W: _wf(f"org/tool@{SHA_A}")}
        self.assertEqual(_unpinned(base, {W: _wf(f"org/tool@{SHA_B}")}), [])
        self.assertEqual(_unpinned(base, {}), [])


class DeclaredPinSeverities(unittest.TestCase):
    """SPEC §6.3: every declared-pin unpin event is high."""

    def test_unpin_events_are_high(self) -> None:
        sha = "a" * 40
        digest = "sha256:" + "a" * 64
        for base, head, message in (
            (_pins(("j", "git_sha", sha), ("k", "git_tag", "v1.0.0")), _pins(("k", "git_tag", "v1.0.0")),
             "declared pin j removed"),
            (_pins(("j", "git_sha", sha)), None, "declared pin j removed"),
            (_pins(("j", "digest_sha256", digest)), _pins(("j", "git_sha", sha)), "declared pin j lost digest"),
            (_pins(("j", "git_sha", sha)), _pins(("j", "git_tag", "v1.0.0")), "declared pin j kind weakened"),
            (_pins(("j", "git_tag", "v1.0.0")), _pins(("j", "git_tag", "main")), "declared pin j value floated"),
        ):
            with self.subTest(base=base, head=head):
                h = {} if head is None else {P: head}
                self.assertEqual(_unpinned({P: base}, h), [("JUDGE_UNPINNED", "high", message)])


class DeclaredPinValues(unittest.TestCase):
    """SPEC §4 (R-26.7, option B as amended): value changes off the unpin
    list are warn; a digest value floats unless it is `sha256:` and 64
    lowercase hex; the last head record of a locator is compared."""

    SHA_A, SHA_B = "a" * 40, "b" * 40
    DIG_A, DIG_B = "sha256:" + "a" * 64, "sha256:" + "b" * 64

    def _run(self, base: tuple[str, str], head: tuple[str, str]) -> list[tuple[str, str, str]]:
        return _unpinned({P: _pins(("j",) + base)}, {P: _pins(("j",) + head)})

    def test_same_kind_value_change_is_warn(self) -> None:
        for base, head in (
            (("git_tag", "v1.0.0"), ("git_tag", "v1.1.0")),
            (("git_tag", "v1.0.0"), ("git_tag", "v0.1.0")),
            (("git_sha", self.SHA_A), ("git_sha", self.SHA_B)),
            (("action_ref", "v1.2.3"), ("action_ref", "v1.3.0")),
            (("digest_sha256", self.DIG_A), ("digest_sha256", self.DIG_B)),
        ):
            with self.subTest(base=base, head=head):
                self.assertEqual(self._run(base, head), [("JUDGE_UNPINNED", "warn", "declared pin j value changed")])

    def test_tightening_is_silent_a_digest_included(self) -> None:
        for base, head in (
            (("git_tag", "v1.0.0"), ("git_sha", self.SHA_A)),
            (("git_sha", self.SHA_A), ("digest_sha256", self.DIG_A)),
            (("git_tag", "v1.0.0"), ("digest_sha256", self.DIG_A)),
            # R04: tightening whose new value names other content.
            (("git_tag", "v1.4.0"), ("git_sha", self.SHA_B)),
        ):
            with self.subTest(base=base, head=head):
                self.assertEqual(self._run(base, head), [])

    def test_unchanged_record_and_label_edit_are_silent(self) -> None:
        self.assertEqual(self._run(("git_sha", self.SHA_A), ("git_sha", self.SHA_A)), [])
        base = json.dumps([{"locator": "j", "kind": "git_sha", "value": self.SHA_A, "product": "a"}])
        head = json.dumps([{"locator": "j", "kind": "git_sha", "value": self.SHA_A, "product": "b"}])
        self.assertEqual(_pair({P: base}, {P: head})["findings"], [])

    def test_floats_stay_high_junk_digests_included(self) -> None:
        for base, head in (
            (("git_tag", "v1.0.0"), ("git_tag", "main")),
            (("git_sha", self.SHA_A), ("git_sha", self.SHA_A[:12])),
            (("digest_sha256", self.DIG_A), ("digest_sha256", "latest")),
            (("git_sha", self.SHA_A), ("digest_sha256", "none")),
            (("git_tag", "v1.0.0"), ("digest_sha256", "TODO")),
            (("digest_sha256", self.DIG_A), ("digest_sha256", "x")),
            # Stated cost: an uppercase-hex digest is not the closed form.
            (("digest_sha256", self.DIG_A), ("digest_sha256", "sha256:" + "A" * 64)),
        ):
            with self.subTest(base=base, head=head):
                self.assertEqual(self._run(base, head), [("JUDGE_UNPINNED", "high", "declared pin j value floated")])

    def test_a_relabel_to_the_digest_kind_is_ranked_by_its_value(self) -> None:
        # A digest record off the closed form ranks as floating (review of
        # 2026-10-10): keeping a non-digest value is no tightening.
        for base, head, expected in (
            (("git_sha", self.SHA_A), ("digest_sha256", self.SHA_A),
             [("JUDGE_UNPINNED", "high", "declared pin j kind weakened")]),
            (("git_tag", "v1.2.3"), ("digest_sha256", "v1.2.3"),
             [("JUDGE_UNPINNED", "high", "declared pin j kind weakened")]),
            (("action_ref", "v1.2.3"), ("digest_sha256", "v1.2.3"),
             [("JUDGE_UNPINNED", "high", "declared pin j kind weakened")]),
            (("action_ref", "main"), ("digest_sha256", "main"),
             [("JUDGE_UNPINNED", "warn", "declared pin j value changed")]),
            (("digest_sha256", "x"), ("digest_sha256", self.DIG_A), []),
            (("git_sha", self.SHA_A), ("digest_sha256", " " + self.DIG_A + "\n"), []),
            (("digest_sha256", "none"), ("digest_sha256", "none"), []),
        ):
            with self.subTest(base=base, head=head):
                self.assertEqual(self._run(base, head), expected)

    def test_the_last_head_record_of_a_locator_is_compared(self) -> None:
        # R04: a duplicate head locator is read last-wins, so a floating
        # record ahead of the kept one is not read.
        base = {P: _pins(("j", "git_sha", self.SHA_A))}
        shadow = {P: _pins(("j", "git_tag", "main"), ("j", "git_sha", self.SHA_A))}
        self.assertEqual(_unpinned(base, shadow), [])
        last = {P: _pins(("j", "git_sha", self.SHA_A), ("j", "git_tag", "main"))}
        self.assertEqual(_unpinned(base, last), [("JUDGE_UNPINNED", "high", "declared pin j value floated")])


if __name__ == "__main__":
    unittest.main()
