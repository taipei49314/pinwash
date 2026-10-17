"""Plain text presentation. Raw engine results remain available in JSON."""
from __future__ import annotations

import unicodedata
from typing import Any

EXPLANATIONS = {
    "HOOK_REMOVED": ("A verification hook was removed.", "Review the removed hook; restore it or document its replacement."),
    "HOOK_BYPASSED": ("A hook may no longer run or block completion.", "Review the changed hook configuration and restore the intended checks."),
    "GATE_STUBBED": ("A checking command may have been replaced with a non-checking body.", "Inspect the command and restore the intended verification."),
    "JUDGE_UNPINNED": ("A verification dependency's pin changed.", "Review the old and new identity; restore the approved pin if the change was unintended."),
    "PERMISSION_WIDENED": ("The agent may have broader permissions.", "Review the new permissions and keep only those needed for this task."),
    "REQUIRED_CHECK_DROPPED": ("A required check or its producer may have been removed or weakened.", "Review both the required-check declaration and its workflow."),
    "CONFIG_RELAXED": ("Verification settings or existing exemptions changed.", "Review the change against the original baseline; do not automatically ignore it."),
    "EXEMPTION_ADDED": ("A new exemption could suppress a future finding.", "A human must review its scope, reason and expiry before accepting a new baseline."),
    "SKILL_BYPASS": ("Instructions may encourage bypassing verification.", "Read the changed instruction and remove unintended bypass directions."),
    "SURFACE_UNPARSEABLE": ("PinWash could not read a verification configuration as expected.", "Inspect the syntax and unsupported format before relying on this result."),
}


def safe(value: object, limit: int = 500) -> str:
    """Escape terminal controls (including bidi) from untrusted file contents."""
    text = str(value)
    rendered = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C")
        or c in "\u2028\u2029" else c for c in text
    )
    return rendered if len(rendered) <= limit else rendered[:limit] + "... [see JSON]"


def render(report: dict[str, Any]) -> str:
    headlines = {
        "pass": "No blocking in-scope weakening was found.",
        "block": "Changes need attention: a blocking weakening was found.",
        "held": "Human review needed: an exemption was added.",
        "not_judged": "Review unfinished. This is not a pass.",
    }
    lines = ["PinWash review", headlines[report["status"]],
             "Execution: " + ("all comparisons finished" if report["execution_complete"] else "unfinished"),
             f"Findings: {len(report['findings'])} | Unassessed items: {len(report['unknown_coverage'])}"]
    if "base" in report:
        lines.append(f"Baseline: {safe(report['base'])}")
    if report.get("quiescence"):
        lines.append("Stopped writers: confirmed by the caller, not verified by PinWash.")
    for f in report["findings"]:
        impact, next_step = EXPLANATIONS.get(f["rule"], (f["message"], "Review this change against the baseline."))
        lines += ["", f"[{safe(f['severity'])}] {safe(f['path'])}",
                  f"  Change: {safe(f['message'])}", f"  Why: {safe(impact)}"]
        if f.get("locator"):
            lines.append(f"  Location: {safe(f['locator'])}")
        lines += [f"  Before: {safe(f['before'])}", f"  After:  {safe(f['after'])}",
                  f"  Next: {safe(next_step)}", f"  Rule: {safe(f['rule'])}"]
    if report["unknown_coverage"]:
        lines += ["", "Not assessed (these are not passes):"]
        lines += [f"  {safe(row['path'])}: {safe(row['reason'])}" for row in report["unknown_coverage"]]
    for error in report["config_errors"]:
        lines.append(f"Configuration needs review: {safe(error)}")
    for error in report["errors"]:
        lines.append(f"Unfinished: {safe(error)}")
    if report.get("report_path"):
        lines += ["", f"Saved report: {safe(report['report_path'])}"]
    lines += ["", "Scope: supported repository files only; home-directory and service settings are outside this review.",
              "This does not prove that checks ran or that the product works."]
    return "\n".join(lines) + "\n"
