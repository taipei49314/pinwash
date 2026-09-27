"""CONFIG_RELAXED (SPEC §5): checkwash config disable / fail_on, high per §6."""

from __future__ import annotations

from typing import Any

from pinwash.escalate import SEVERITY_RANK
from pinwash.parse.tomlsub import parse_checkwash_config


def detect(
    path: str, base_txt: str | None, head_txt: str | None, add: Any
) -> None:
    if head_txt is None:
        return
    head_c = parse_checkwash_config(head_txt)
    base_c = parse_checkwash_config(base_txt) if base_txt is not None else {
        "disabled": [],
        "fail_on": None,
    }
    base_fail = base_c["fail_on"] or "high"
    head_fail = head_c["fail_on"]
    if head_fail and SEVERITY_RANK[head_fail] > SEVERITY_RANK[base_fail]:
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
