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


def _priority(report: dict[str, Any]) -> list[str]:
    lines = ["", "Priority summary:"]
    if not report["execution_complete"]:
        lines.append("  1. Finish the review: resolve the Unfinished errors below. This result cannot be accepted as a pass.")
        lines.append("     Findings already observed still need attention.")
    if report["status"] == "block":
        lines.append("  Blocking result: review the highest-severity changes first.")
    ranks = {"critical": 0, "high": 1, "warn": 2, "info": 3}
    ordered = sorted(report["findings"], key=lambda f: (ranks[f["severity"]], f["path"], f["rule"], f["fingerprint"]))
    for finding in ordered[:3]:
        _, action = EXPLANATIONS.get(finding["rule"], ("", "Review this change against the baseline."))
        lines.append(f"  [{safe(finding['severity'])}] {safe(finding['path'])} ({safe(finding['rule'])}): {safe(action)}")
    if len(ordered) > 3:
        lines.append(f"  {len(ordered) - 3} more finding(s); see the full details below.")
    exemptions = sum(f["rule"] == "EXEMPTION_ADDED" for f in ordered)
    if exemptions:
        lines.append(f"  Human decision: review {exemptions} new exemption(s), including scope, reason and expiry; none is automatically approved.")
    if report["config_errors"]:
        lines.append(f"  Configuration: inspect {len(report['config_errors'])} error(s) below before relying on this review.")
    if report["unknown_coverage"]:
        lines.append(f"  Coverage: manually assess {len(report['unknown_coverage'])} unassessed item(s) below; these are not passes.")
    needs_attention = bool(ordered or report["errors"] or report["config_errors"] or report["unknown_coverage"])
    if not needs_attention:
        lines.append("  No in-scope issue was reported. Continue your normal code review and product checks.")
    elif report.get("session_id"):
        lines.append("  Next: address the items above, stop all writers, then run pinwash session review again with the same state directory and baseline.")
    else:
        lines.append("  Next: address the items above, stop all writers, then rerun the same review command and range.")
    return lines


def render(report: dict[str, Any]) -> str:
    headlines = {
        "pass": "No blocking in-scope weakening was found.",
        "block": "Changes need attention: a blocking weakening was found.",
        "held": "Human review needed: an exemption was added.",
        "not_judged": "Review unfinished. This is not a pass.",
    }
    headline = headlines[report["status"]] if report["execution_complete"] else headlines["not_judged"]
    lines = ["PinWash review", headline,
             "Execution: " + ("all comparisons finished" if report["execution_complete"] else "unfinished"),
             f"Findings: {len(report['findings'])} | Unassessed items: {len(report['unknown_coverage'])}"]
    if "base" in report:
        lines.append(f"Baseline: {safe(report['base'])}")
    if report.get("quiescence"):
        lines.append("Stopped writers: confirmed by the caller, not verified by PinWash.")
    lines += _priority(report)
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
