"""SPEC §5.2 (spec 25, AI-assisted ruling on the spec 7 exit-2 refactor
false positive, hook-project-dir Q3, #11): a head judge body that mentions the
closed exit-2 forms more often than its base keeps block capability."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pinwash.engine import scan_pair

SET = ".claude/settings.json"
ENV = {"PINWASH_TODAY": "2026-10-09"}


def _settings(cmd: str, event: str = "Stop") -> str:
    return json.dumps({"hooks": {event: [{"hooks": [{"type": "command", "command": cmd}]}]}})


def _scan(base: dict[str, str], head: dict[str, str]) -> dict[str, Any]:
    return scan_pair({k: v.encode() for k, v in base.items()}, {k: v.encode() for k, v in head.items()},
                     base_label="b", head_label="h", env=ENV)


def _messages(payload: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["severity"], f["message"]) for f in payload["findings"]]


JSON_JUDGE = {
    "sh": "#!/usr/bin/env bash\nif ! make test >/dev/null 2>&1; then\n  echo '{\"decision\": \"block\", \"reason\": \"tests failing\"}'\nfi\n",
    "py": "import json, subprocess, sys\nr = subprocess.run(['make', 'test'])\nif r.returncode != 0:\n    print(json.dumps({'decision': 'block'}))\nsys.exit(0)\n",
    "js": "const { execSync } = require('child_process');\ntry { execSync('npm test'); }\ncatch (e) { console.log(JSON.stringify({ decision: 'block' })); }\n",
    "ps1": "$r = & make test\nif ($LASTEXITCODE -ne 0) { Write-Output '{\"decision\": \"block\"}' }\n",
}
EXIT2_JUDGE = {
    "sh": "#!/usr/bin/env bash\nif ! make test >/dev/null 2>&1; then\n  echo 'tests failing' >&2\n  exit 2\nfi\n",
    "py": "import subprocess, sys\nr = subprocess.run(['make', 'test'])\nif r.returncode != 0:\n    print('tests failing', file=sys.stderr)\n    sys.exit(2)\n",
    "js": "const { execSync } = require('child_process');\ntry { execSync('npm test'); }\ncatch (e) { console.error('tests failing'); process.exitCode = 2; }\n",
    "ps1": "$r = & make test\nif ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine('tests failing'); exit 2 }\n",
}
RUN = {"sh": "bash hooks/judge.sh", "py": "python hooks/judge.py", "js": "node hooks/judge.js", "ps1": "pwsh -File hooks/judge.ps1"}


class ExitTwoKeepsCapability(unittest.TestCase):
    def test_block_to_exit2_refactor_is_not_lost_capability(self) -> None:
        for ext in RUN:
            with self.subTest(ext=ext):
                path = f"hooks/judge.{ext}"
                base = {SET: _settings(RUN[ext]), path: JSON_JUDGE[ext]}
                head = {SET: _settings(RUN[ext]), path: EXIT2_JUDGE[ext]}
                payload = _scan(base, head)
                self.assertEqual(payload["verdict"], "pass")
                self.assertEqual(_messages(payload), [])

    def test_every_closed_form_keeps_capability(self) -> None:
        # Review of 2026-10-10: one subtest per form and host spelling.
        base_body = JSON_JUDGE["js"]
        for tail in ("process.exitCode=2;", "process.exitCode = 2;", "process.exit(2);",
                     "require('os'); process.exit(2)>0;", "EXIT 2", "os._exit(2)",
                     "[Environment]::Exit(2)", "$host.SetShouldExit(2)", "exit 2\r\n"):
            with self.subTest(tail=tail):
                head_body = "const { execSync } = require('child_process');\ntry { execSync('npm test'); }\ncatch (e) { " + tail + " }\n"
                payload = _scan({SET: _settings(RUN["js"]), "hooks/judge.js": base_body},
                                {SET: _settings(RUN["js"]), "hooks/judge.js": head_body})
                self.assertEqual(_messages(payload), [])

    def test_exit_paren_counts_wherever_it_occurs(self) -> None:
        # `exit(2)` is not subject to the digit / `>` / `<` rule: its `)`
        # closes the argument (executed: `process.exit(2)>0` refuses).
        for tail in ("sys.exit(2)0", "exit(2)>x", "exit(2)<y"):
            with self.subTest(tail=tail):
                head_body = f"import sys\nsubprocess_ok = True\n# {tail}\n"
                payload = _scan({SET: _settings(RUN["py"]), "hooks/judge.py": JSON_JUDGE["py"]},
                                {SET: _settings(RUN["py"]), "hooks/judge.py": head_body})
                self.assertEqual(_messages(payload), [])

    def test_a_refactor_that_does_not_raise_the_count_still_fires(self) -> None:
        # Residual false positive (§5.2): the refusal routed through an
        # exit-2 helper the base already held.
        base_body = ("#!/usr/bin/env bash\ndie() { echo \"$1\" >&2; exit 2; }\n[ -f x ] || die usage\n"
                     "if ! make test; then echo '{\"decision\": \"block\"}'; fi\n")
        head_body = "#!/usr/bin/env bash\ndie() { echo \"$1\" >&2; exit 2; }\n[ -f x ] || die usage\nmake test || die failing\n"
        payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": base_body},
                        {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
        self.assertEqual(_messages(payload), [("critical", "hook command for Stop lost block capability")])

    def test_gut_that_keeps_exit2_boilerplate_still_loses_capability(self) -> None:
        base_body = ("#!/usr/bin/env bash\ncd \"$(dirname \"$0\")\" || exit 2\n"
                     "if ! make test >/dev/null 2>&1; then\n  echo '{\"decision\": \"block\"}'\nfi\n")
        head_body = "#!/usr/bin/env bash\ncd \"$(dirname \"$0\")\" || exit 2\nmake test >/dev/null 2>&1 || true\n"
        payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": base_body},
                        {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
        self.assertEqual(payload["verdict"], "block")
        self.assertEqual(_messages(payload), [("critical", "hook command for Stop lost block capability")])

    def test_exit_20_is_not_an_exit2_form(self) -> None:
        head_body = "#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || exit 20\n"
        payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": JSON_JUDGE["sh"]},
                        {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
        self.assertEqual(_messages(payload), [("critical", "hook command for Stop lost block capability")])

    def test_a_redirection_is_not_an_exit2_form(self) -> None:
        # `exit 2>/dev/null` is bash `exit` with fd 2 redirected: it exits
        # with the last status, not 2 (executed on both hosts: no refusal).
        for tail in ("exit 2>/dev/null", "exit 2<&-", "exit 2>&1"):
            with self.subTest(tail=tail):
                head_body = f"#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || true\n{tail}\n"
                payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": JSON_JUDGE["sh"]},
                                {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
                self.assertEqual(_messages(payload), [("critical", "hook command for Stop lost block capability")])

    def test_exit2_refactors_outside_the_closed_forms_still_fire(self) -> None:
        # Residual false positives (R07): two spaces, an exit through a
        # variable or a function's return status.
        for tail in ("exit  2", "return 2\nexit $?", "exit $CODE"):
            with self.subTest(tail=tail):
                head_body = f"#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || {tail}\n"
                payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": JSON_JUDGE["sh"]},
                                {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
                self.assertEqual(_messages(payload), [("critical", "hook command for Stop lost block capability")])

    def test_gut_with_an_added_exit2_comment_is_residual(self) -> None:
        # R07 (#11): a marker kept or added anywhere defeats the shape, as a
        # kept `block` comment does; pinned so a change is deliberate.
        head_body = "#!/usr/bin/env bash\n# exit 2 used to refuse here\nmake test >/dev/null 2>&1 || true\n"
        payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": JSON_JUDGE["sh"]},
                        {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
        self.assertEqual(_messages(payload), [])

    def test_exit2_only_base_is_not_block_capable(self) -> None:
        # Unchanged: a base that refuses only through exit 2 is not
        # block-capable (R07); its gut is not this shape.
        head_body = "#!/usr/bin/env bash\nmake test >/dev/null 2>&1 || true\n"
        payload = _scan({SET: _settings(RUN["sh"]), "hooks/judge.sh": EXIT2_JUDGE["sh"]},
                        {SET: _settings(RUN["sh"]), "hooks/judge.sh": head_body})
        self.assertEqual(_messages(payload), [])


if __name__ == "__main__":
    unittest.main()
