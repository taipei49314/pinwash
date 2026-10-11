"""Spec 19: `checkwash_config` read as checkwash reads it, and CONFIG_RELAXED
on the config in force (SPEC §3.2, §5; R22; #22, AI-assisted ruling R-22b
with the challenger's amendments).

Per side the config in force is the first of `.checkwash/config.toml`,
`.greenwash/config.toml` that exists (an empty file exists); none means the
defaults (`fail_on` high, nothing disabled). Bytes are decoded as UTF-8 with
a leading BOM dropped and bad bytes replaced, then parsed with tomllib; a
text tomllib rejects is the defaults. Only `gate.fail_on` and
`detectors.disable` are read. The expected values follow checkwash's
config.load_config and read_base_config_file. The review of 2026-10-10
(AI-assisted) added the exact path spelling, the fixed bounds of §3.2, the
row for a config checkwash cannot load, and the worktree symlink.
"""

from __future__ import annotations

import os
import sys
import unittest
from typing import Any

from pinwash.engine import scan_pair
from pinwash.rules.config_rule import NOT_LOADED, checkwash_read
from tests.test_alpha2_git_cli import _CLIIntegration

ENV = {"PINWASH_TODAY": "2026-10-09"}
C = ".checkwash/config.toml"
G = ".greenwash/config.toml"


def _cfg(fail_on: str | None = None, disable: list[str] | None = None) -> str:
    out = ""
    if fail_on is not None:
        out += f'[gate]\nfail_on = "{fail_on}"\n'
    if disable is not None:
        out += "[detectors]\ndisable = [" + ", ".join(f'"{d}"' for d in disable) + "]\n"
    return out


def _relaxed(base: dict[str, Any], head: dict[str, Any]) -> list[tuple[str, str]]:
    enc = lambda t: {k: v if isinstance(v, bytes) else v.encode() for k, v in t.items()}
    payload = scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)
    return sorted((f["path"], f["message"]) for f in payload["findings"] if f["rule"] == "CONFIG_RELAXED")


class CheckwashRead(unittest.TestCase):
    def test_values_read_as_checkwash_reads_them(self) -> None:
        for data, expected in (
            (None, ("high", [])),
            (b"", ("high", [])),
            (b"# nothing\n", ("high", [])),
            (b'[gate]\nfail_on = "warn"\n', ("warn", [])),
            (b'\xef\xbb\xbf[gate]\nfail_on = "info"\n', ("info", [])),
            (b'gate.fail_on = "critical"\n', ("critical", [])),
            (b'fail_on = "warn"\n', ("high", [])),
            (b'[gate]\nfail_on = "Warn"\n', ("high", [])),
            (b'[gate]\nfail_on = 1\n', ("high", [])),
            (b'gate = "x"\n', ("high", [])),
            (b'[detectors]\ndisable = ["A", "B"]\n', ("high", ["A", "B"])),
            (b'[detectors]\ndisable = [\n  "A",\n]\n', ("high", ["A"])),
            (b'[detectors]\ndisable = ["A", 1]\n', ("high", [])),
            (b'[detectors]\ndisable = "A"\n', ("high", [])),
            (b'disable = ["A"]\ndetect_x = false\n', ("high", [])),
            (b'[gate]\nfail_on = "warn"\n\xff\n', ("high", [])),
            (b'[gate]\nfail_on = "warn"\nfail_on = "info"\n', ("high", [])),
            (b'[gate]\nfail_on = "w\xffrn"\n', ("high", [])),
        ):
            with self.subTest(data=data):
                self.assertEqual(checkwash_read(data), expected)

    def test_configs_checkwash_cannot_load_are_rows(self) -> None:
        # checkwash exits 2 on each of these instead of running (R22): past
        # 500 levels of nesting, a key of more than 1000 parts (3.11, 3.13),
        # a decimal integer of more than 4300 digits, an array or table
        # `fail_on` (its `in` test raises).
        gate = b'[gate]\nfail_on = "critical"\n'
        for name, data in (
            ("nesting", gate + b"x = " + b"[" * 501 + b"]" * 501 + b"\n"),
            ("table nesting", gate + b"x = " + b"{a = " * 501 + b"1" + b"}" * 501 + b"\n"),
            ("deep", b"a = " + b"[" * 20000 + b"]" * 20000 + b"\n"),
            ("key parts", gate + b".".join([b"k"] * 1001) + b" = 1\n"),
            ("integer", gate + b"x = " + b"1" * 4301 + b"\n"),
            ("array fail_on", b'[gate]\nfail_on = ["warn"]\n'),
            ("table fail_on", b'gate.fail_on = { a = "warn" }\n'),
        ):
            with self.subTest(name=name):
                self.assertIsNone(checkwash_read(data))
                payload = scan_pair({C: _cfg("info").encode()}, {C: data}, base_label="b", head_label="h", env=ENV)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [{"path": C, "reason": NOT_LOADED}])
                # At base, the head is compared against the defaults.
                payload = scan_pair({C: data}, {C: _cfg("critical").encode()}, base_label="b", head_label="h", env=ENV)
                self.assertEqual([f["message"] for f in payload["findings"]], ["fail_on raised high -> critical"])
                self.assertEqual(payload["unknown_coverage"], [{"path": C, "reason": NOT_LOADED}])
                self.assertEqual(_relaxed({C: data}, {C: _cfg("warn")}), [])

    def test_the_bounds_hold_on_every_stack_and_environment(self) -> None:
        # Up to the bounds the config is read wherever the caller sits, so
        # output never depends on the interpreter or the call depth.
        gate = b'[gate]\nfail_on = "critical"\n'
        cases = (
            gate + b"x = " + b"[" * 500 + b"]" * 500 + b"\n",
            gate + b"x = " + b"{a = " * 500 + b"1" + b"}" * 500 + b"\n",
            gate + b".".join([b"k"] * 1000) + b" = 1\n",
            gate + b"x = " + b"1" * 4300 + b"\n",
            gate + b'x = "' + b"[" * 900 + b'"\ny = \'\'\'' + b"{" * 900 + b"\'\'\'\n# " + b"[" * 900 + b"\n",
        )

        def deep(n: int, data: bytes) -> Any:
            return checkwash_read(data) if n == 0 else deep(n - 1, data)

        digits = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(0)
        try:
            for data in cases:
                with self.subTest(data=data[:40]):
                    self.assertEqual(checkwash_read(data), ("critical", []))
                    self.assertEqual(deep(800, data), ("critical", []))
            self.assertIsNone(checkwash_read(gate + b"x = " + b"1" * 4301 + b"\n"))
        finally:
            sys.set_int_max_str_digits(digits)

    def test_an_error_before_a_bound_is_the_defaults(self) -> None:
        # tomllib stops at the first error, as checkwash does.
        for data in (
            b'[gate]\nfail_on = "critical"\nbad = "x\ny = ' + b"[" * 600 + b"]" * 600 + b"\n",
            b'[gate]\nfail_on = "critical"\ny = ' + b"[" * 500 + b"1[" + b"]" * 501 + b"\n",
        ):
            with self.subTest(data=data[:60]):
                self.assertEqual(checkwash_read(data), ("high", []))


class ConfigInForce(unittest.TestCase):
    def test_only_the_exact_path_is_the_config(self) -> None:
        # A file named `.checkwash\\config.toml` is not the one checkwash's
        # `git show REV:.checkwash/config.toml` reads (spec 19 review).
        for real, decoy in ((C, ".checkwash\\config.toml"), (G, ".greenwash\\config.toml")):
            with self.subTest(real=real):
                self.assertEqual(
                    _relaxed({real: _cfg("info")}, {real: _cfg("critical"), decoy: _cfg("info")}),
                    [(real, "fail_on raised info -> critical")],
                )

    def test_deleting_a_stricter_config_relaxes(self) -> None:
        for path in (C, G):
            with self.subTest(path=path):
                self.assertEqual(_relaxed({path: _cfg("warn")}, {}), [(path, "fail_on raised warn -> high")])
                self.assertEqual(_relaxed({path: _cfg(disable=[])}, {}), [])

    def test_a_rename_is_compared_like_an_edit(self) -> None:
        self.assertEqual(_relaxed({G: _cfg("critical")}, {C: _cfg("critical")}), [])
        self.assertEqual(_relaxed({G: _cfg(disable=["X"])}, {C: _cfg(disable=["X"])}), [])
        self.assertEqual(_relaxed({G: _cfg("warn")}, {C: _cfg(disable=["X"])}),
                         [(C, "detector X disabled"), (C, "fail_on raised warn -> high")])

    def test_checkwash_reads_the_first_file_that_exists(self) -> None:
        # Editing the shadowed .greenwash file changes nothing checkwash reads.
        self.assertEqual(_relaxed({C: _cfg("warn"), G: _cfg("info")}, {C: _cfg("warn"), G: _cfg("critical")}), [])
        # Deleting .checkwash wakes the .greenwash file behind it.
        self.assertEqual(_relaxed({C: _cfg("warn"), G: _cfg("critical", ["X"])}, {G: _cfg("critical", ["X"])}),
                         [(G, "detector X disabled"), (G, "fail_on raised warn -> critical")])
        # A new .checkwash, even an empty one, shadows the .greenwash file.
        for new in ("", "[roles]\ndocs = ['*.md']\n"):
            with self.subTest(new=new):
                self.assertEqual(_relaxed({G: _cfg("warn")}, {G: _cfg("warn"), C: new}),
                                 [(C, "fail_on raised warn -> high")])
        # Deleting a shadowed file is silent.
        self.assertEqual(_relaxed({C: _cfg("warn"), G: _cfg("info")}, {C: _cfg("warn")}), [])

    def test_a_config_checkwash_cannot_parse_is_the_defaults(self) -> None:
        self.assertEqual(_relaxed({C: b"\xff"}, {C: _cfg(disable=["X"])}), [(C, "detector X disabled")])
        self.assertEqual(_relaxed({C: _cfg("warn")}, {C: b"\xff"}), [(C, "fail_on raised warn -> high")])
        self.assertEqual(_relaxed({C: _cfg("high")}, {C: b"\xff"}), [])

    def test_tightening_and_unchanged_values_are_silent(self) -> None:
        for base, head in (({C: _cfg("high")}, {C: _cfg("warn")}), ({C: _cfg(disable=["X", "Y"])}, {C: _cfg(disable=["Y"])}),
                           ({}, {C: _cfg("info")}), ({}, {C: _cfg(disable=[])}), ({}, {})):
            with self.subTest(base=base, head=head):
                self.assertEqual(_relaxed(base, head), [])

    def test_a_detector_listed_twice_is_one_finding(self) -> None:
        self.assertEqual(_relaxed({}, {C: _cfg(disable=["X", "X"])}), [(C, "detector X disabled")])

    def test_a_checkwash_config_has_no_parse_status(self) -> None:
        # It is never unparseable (§3): no SURFACE_UNPARSEABLE and no row.
        for base, head in (({C: _cfg("high")}, {C: b"\xff"}), ({}, {C: b"\xff"}), ({C: b"\xff"}, {C: _cfg("high")}),
                           ({C: b"\xff"}, {})):
            with self.subTest(base=base, head=head):
                enc = lambda t: {k: v if isinstance(v, bytes) else v.encode() for k, v in t.items()}
                payload = scan_pair(enc(base), enc(head), base_label="b", head_label="h", env=ENV)
                self.assertEqual(payload["findings"], [])
                self.assertEqual(payload["unknown_coverage"], [])


if __name__ == "__main__":
    unittest.main()



class WorktreeSymlink(_CLIIntegration):
    """In worktree mode a symlink at a config path is read as git stores
    it, its link text, because checkwash reads its config from git."""

    @unittest.skipUnless(os.name == "posix", "posix symlinks")
    def test_a_config_swapped_for_a_symlink_is_its_link_text(self) -> None:
        repo = self._repo({C: _cfg("info"), "conf/strict.toml": _cfg("info")})
        base = self._git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        (repo / C).unlink()
        (repo / C).symlink_to("../conf/strict.toml")
        for range_arg in (None, f"{base}..WORKTREE"):
            with self.subTest(range_arg=range_arg):
                proc, payload = self._check(repo, range_arg)
                self._assert_exit(proc, payload, 1)
                self.assertEqual(
                    [(f["path"], f["message"]) for f in payload["findings"]],
                    [(C, "fail_on raised info -> high")],
                )
