"""JUDGE_UNPINNED: workflow `uses:` pins (§4) and declared pins (§4)."""

from __future__ import annotations

from typing import Any

from pinwash.escalate import pin_float_severity, pin_removed_severity
from pinwash.pins import classify_action_ref, kind_rank, record_rank


def detect_workflow_pins(path: str, base_g: Any, head_g: Any, add: Any) -> None:
    if base_g is None:
        return
    if getattr(base_g, "unparseable", False):
        return
    base_uses = {(loc, n): ref for loc, ref, n in base_g.uses}
    head_uses = (
        {(loc, n): ref for loc, ref, n in head_g.uses}
        if head_g is not None and not head_g.unparseable
        else {}
    )
    head_non_floating = 0
    if head_g is not None and not head_g.unparseable:
        for loc, ref, _n in head_g.uses:
            if classify_action_ref(ref) != "floating":
                head_non_floating += 1
    consumer_exists = head_g is not None and not getattr(head_g, "unparseable", False)

    for key, ref in base_uses.items():
        loc, n = key
        locator = f"gha_workflow:{path}:uses:{loc}#{n}"
        base_kind = classify_action_ref(ref)
        head_ref = head_uses.get(key)
        if head_ref is None:
            if consumer_exists:
                add(
                    rule="JUDGE_UNPINNED",
                    severity=pin_removed_severity(head_non_floating),
                    message="action pin removed while workflow remains",
                    path=path,
                    before=ref,
                    after="",
                    locator=locator,
                )
            continue
        head_kind = classify_action_ref(head_ref)
        unpinned = False
        if kind_rank(head_kind) < kind_rank(base_kind):
            unpinned = True
        if head_ref != ref and head_kind == "floating":
            unpinned = True
        if base_kind == "git_sha" and head_kind == "git_sha" and len(head_ref) < 40:
            unpinned = True
        if not unpinned:
            continue
        add(
            rule="JUDGE_UNPINNED",
            severity=pin_float_severity(head_kind, head_non_floating),
            message="action pin weakened",
            path=path,
            before=ref,
            after=head_ref,
            locator=locator,
        )


def detect_declared_pins(path: str, base_doc: Any, head_doc: Any, add: Any) -> None:
    if not isinstance(base_doc, list):
        return
    base_pins: dict[str, dict[str, str]] = {}
    for item in base_doc:
        if isinstance(item, dict) and all(
            isinstance(item.get(k), str) for k in ("locator", "kind", "value")
        ):
            base_pins[item["locator"]] = {
                "kind": item["kind"],
                "value": item["value"],
            }
    head_pins: dict[str, dict[str, str]] = {}
    if isinstance(head_doc, list):
        for item in head_doc:
            if isinstance(item, dict) and all(
                isinstance(item.get(k), str) for k in ("locator", "kind", "value")
            ):
                head_pins[item["locator"]] = {
                    "kind": item["kind"],
                    "value": item["value"],
                }
    for loc, rec in base_pins.items():
        head = head_pins.get(loc)
        if head is None:
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} removed",
                path=path,
                locator=f"declared_pins:{loc}",
                before=rec["value"],
            )
            continue
        base_kind = rec["kind"]
        head_kind = head["kind"]
        if base_kind == "digest_sha256" and head_kind != "digest_sha256":
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} lost digest",
                path=path,
                locator=f"declared_pins:{loc}",
            )
            continue
        if rec["value"] != head["value"] and classify_action_ref(head["value"]) == "floating":
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} value floated",
                path=path,
                locator=f"declared_pins:{loc}",
                before=rec["value"],
                after=head["value"],
            )
            continue
        if record_rank(head_kind, head["value"]) < record_rank(base_kind, rec["value"]):
            add(
                rule="JUDGE_UNPINNED",
                severity="high",
                message=f"declared pin {loc} kind weakened",
                path=path,
                locator=f"declared_pins:{loc}",
                before=base_kind,
                after=head_kind,
            )
