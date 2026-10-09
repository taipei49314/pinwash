"""CONFIG_RELAXED (SPEC §5): checkwash config disable / fail_on, high per §6."""

from __future__ import annotations

from typing import Any

from pinwash.escalate import SEVERITY_RANK
from pinwash.findings import FAIL_ON_DEFAULT
from pinwash.parse.tomlsub import parse_checkwash_config

# A side without a config file runs on the defaults.
_DEFAULTS: dict[str, Any] = {"disabled": [], "fail_on": None, "fail_on_unread": False}


def detect(
    path: str, base_txt: str | None, head_txt: str | None, add: Any
) -> None:
    if head_txt is None:
        return
    head_c = parse_checkwash_config(head_txt)
    base_c = parse_checkwash_config(base_txt) if base_txt is not None else _DEFAULTS
    # SPEC §5: an edit that raises the effective fail_on fires. A head that
    # has no fail_on line runs on the default (high), so removing a stricter
    # `fail_on` line raises it as much as writing `fail_on = "high"` would.
    # A head fail_on line the §3.2 single-line subset does not read (an
    # inline comment, a BOM, a multi-line or unknown value) is a residual:
    # its value is not observed, so it is never taken for the default.
    if head_c["fail_on"] is not None or not head_c["fail_on_unread"]:
        base_fail = base_c["fail_on"] or FAIL_ON_DEFAULT
        head_fail = head_c["fail_on"] or FAIL_ON_DEFAULT
        if SEVERITY_RANK[head_fail] > SEVERITY_RANK[base_fail]:
            add(
                rule="CONFIG_RELAXED",
                severity="high",
                message=f"fail_on raised {base_fail} -> {head_fail}",
                path=path,
                before=base_fail,
                after=head_fail,
            )
    base_dis = set(base_c["disabled"])
    for name in head_c["disabled"]:
        if name not in base_dis:
            add(
                rule="CONFIG_RELAXED",
                severity="high",
                message=f"detector {name} disabled",
                path=path,
                after=name,
            )
