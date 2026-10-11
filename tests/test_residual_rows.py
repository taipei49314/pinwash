"""SPEC §11 / THREATMODEL residual rows (spec 12).

SPEC §11 says "A row marked Closed without a fixture fails the suite", and
THREATMODEL says a Closed row without a fixture is invalid. Until spec 12 no
test enforced either sentence. This module holds the two tables to one ID
set numbered in order from R01 (no booked row dropped), every THREATMODEL
Status to Open or Closed, and every Closed row to
fixtures that are test ids in this suite (backticked in the Fixture column,
as unittest names them: tests.<module>.<Class>.<test>).

No row is Closed today, so the last check passes vacuously on the real
tables; a synthetic table shows that it rejects what it must.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC_HEADER = ("ID", "Residual")
THREATMODEL_HEADER = ("ID", "Status", "Fixture", "Residual")
STATUSES = frozenset({"Open", "Closed"})
# Residual rows booked through spec 12 (R01-R21).
BOOKED = 24

# A markdown table cell boundary is a pipe not escaped as `\|`.
_CELL_BOUNDARY = re.compile(r"(?<!\\)\|")
_ROW_ID = re.compile(r"R[0-9]{2,}")
_FIXTURE = re.compile(r"`([^`]+)`")


def _cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if len(stripped) < 2 or not (stripped.startswith("|") and stripped.endswith("|")):
        return None
    return [cell.strip() for cell in _CELL_BOUNDARY.split(stripped[1:-1])]


def table_rows(text: str, header: tuple[str, ...]) -> list[list[str]]:
    """Body rows of the first markdown table whose header cells are `header`."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if _cells(line) != list(header):
            continue
        rows: list[list[str]] = []
        for body in lines[i + 2 :]:
            cells = _cells(body)
            if cells is None:
                break
            rows.append(cells)
        return rows
    raise ValueError(f"no table with header {header!r}")


def section(text: str, heading: str) -> str:
    """The text of the `## ` section whose heading starts with `heading`."""
    start = text.index("\n## " + heading)
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def spec_rows() -> list[list[str]]:
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    return table_rows(section(spec, "11. Residuals"), SPEC_HEADER)


def threatmodel_rows() -> list[list[str]]:
    text = (ROOT / "THREATMODEL.md").read_text(encoding="utf-8")
    return table_rows(text, THREATMODEL_HEADER)


def closed_row_problems(rows: list[list[str]], test_ids: set[str]) -> list[str]:
    """Each Closed row must name at least one fixture, and each named
    fixture must be a test id in the suite."""
    problems: list[str] = []
    for cells in rows:
        row_id, status, fixture = cells[0], cells[1], cells[2]
        if status != "Closed":
            continue
        names = _FIXTURE.findall(fixture)
        if not names:
            problems.append(f"{row_id}: Closed without a fixture")
        for name in names:
            if name not in test_ids:
                problems.append(f"{row_id}: fixture {name} is not a test id in the suite")
    return problems


def _flatten(suite: Any) -> list[Any]:
    found: list[Any] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            found.extend(_flatten(item))
        else:
            found.append(item)
    return found


def suite_test_ids() -> set[str]:
    """Every test id this package's suite discovers (nothing is run)."""
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT / "tests"), top_level_dir=str(ROOT))
    return {test.id() for test in _flatten(suite)}


class ResidualRows(unittest.TestCase):
    def test_spec_and_threatmodel_list_the_same_ids(self) -> None:
        spec_ids = [cells[0] for cells in spec_rows()]
        tm_ids = [cells[0] for cells in threatmodel_rows()]
        self.assertTrue(spec_ids)
        for ids in (spec_ids, tm_ids):
            self.assertEqual(len(ids), len(set(ids)), ids)
            for row_id in ids:
                self.assertRegex(row_id, _ROW_ID.pattern + r"\Z")
        self.assertEqual(set(spec_ids), set(tm_ids))

    def test_ids_run_in_order_from_r01_and_keep_every_booked_row(self) -> None:
        # A row leaves the table only by being Closed with a fixture (or, at
        # 1.0, signed Permanent); deleting it from both tables would pass the
        # set check above. A booking bump that adds rows raises BOOKED.
        for ids in ([c[0] for c in spec_rows()], [c[0] for c in threatmodel_rows()]):
            self.assertEqual(ids, [f"R{n:02d}" for n in range(1, len(ids) + 1)])
            self.assertGreaterEqual(len(ids), BOOKED)

    def test_rows_routed_since_spec_12_have_one_wording(self) -> None:
        # THREATMODEL says the rows booked in spec 12 use SPEC §11's wording;
        # the routing bumps (spec 13: R06, R07, R12, R13; spec 14: R03, R14,
        # R15, R16, R20; spec 16: R06, R17-R19, R21, and R22-R23 booked)
        # rewrite rows in both tables at once. R07 keeps
        # THREATMODEL's own prefix ("the SPEC §5.2 closed body lists").
        spec = {cells[0]: cells[1] for cells in spec_rows()}
        tm = {cells[0]: cells[3] for cells in threatmodel_rows()}
        same = ["R03", "R06"] + [f"R{n}" for n in range(11, BOOKED + 1)]
        for row_id in same:
            self.assertEqual(spec[row_id], tm[row_id], row_id)

    def test_rows_have_their_table_width(self) -> None:
        # An unescaped `|` inside a residual (a shell `||`, a matcher list)
        # would split the row; the tables must keep their column count.
        for cells in spec_rows():
            self.assertEqual(len(cells), len(SPEC_HEADER), cells[0])
        for cells in threatmodel_rows():
            self.assertEqual(len(cells), len(THREATMODEL_HEADER), cells[0])

    def test_every_status_is_open_or_closed(self) -> None:
        for cells in threatmodel_rows():
            self.assertIn(cells[1], STATUSES, cells[0])

    def test_every_closed_row_names_a_fixture_in_the_suite(self) -> None:
        self.assertEqual(closed_row_problems(threatmodel_rows(), suite_test_ids()), [])

    def test_closed_row_rule_rejects_a_missing_or_unknown_fixture(self) -> None:
        known = suite_test_ids()
        real = f"tests.test_residual_rows.ResidualRows.{self._testMethodName}"
        self.assertIn(real, known)
        rows = [
            ["R96", "Open", "—", "open rows need no fixture"],
            ["R97", "Closed", f"`{real}`", "names a real test"],
            ["R98", "Closed", "—", "names nothing"],
            ["R99", "Closed", f"`{real}`, `tests.nowhere.Case.test_x`", "one unknown"],
        ]
        self.assertEqual(
            closed_row_problems(rows, known),
            [
                "R98: Closed without a fixture",
                "R99: fixture tests.nowhere.Case.test_x is not a test id in the suite",
            ],
        )

    def test_escaped_pipes_stay_inside_a_cell(self) -> None:
        text = "| ID | Status | Fixture | Residual |\n|---|---|---|---|\n| R01 | Open | — | `a \\|\\| true`, `b \\| c` |\n\nafter\n"
        self.assertEqual(
            table_rows(text, THREATMODEL_HEADER),
            [["R01", "Open", "—", "`a \\|\\| true`, `b \\| c`"]],
        )


if __name__ == "__main__":
    unittest.main()
