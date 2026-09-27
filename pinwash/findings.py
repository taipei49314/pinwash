"""Findings envelope and fingerprints (SPEC §7)."""

from __future__ import annotations

from typing import Any

from pinwash import FINDINGS_VERSION, SPEC_VERSION, __version__
from pinwash.escalate import SEVERITY_RANK
from pinwash.textutil import canonical_json, sha256_text

FAIL_ON_DEFAULT = "high"


def fingerprint(rule: str, path: str, locator: str, before: str, after: str) -> str:
    identity = {
        "after_digest": sha256_text(after),
        "before_digest": sha256_text(before),
        "locator": locator,
        "path": path,
        "rule": rule,
    }
    digest = sha256_text(canonical_json(identity))
    return f"{rule}/{path}/v1:{digest}"


def make_finding(
    *,
    rule: str,
    severity: str,
    message: str,
    path: str,
    before: str = "",
    after: str = "",
    locator: str = "",
) -> dict[str, Any]:
    finding = {
        "after": after,
        "before": before,
        "fingerprint": fingerprint(rule, path, locator, before, after),
        "message": message,
        "path": path,
        "rule": rule,
        "severity": severity,
    }
    if locator:
        finding["locator"] = locator
    return finding


def envelope(
    *,
    base_label: str,
    head_label: str,
    findings: list[dict[str, Any]],
    config_errors: list[str],
    unknown_coverage: list[dict[str, str]],
    fail_on: str = FAIL_ON_DEFAULT,
) -> dict[str, Any]:
    summary = {"critical": 0, "high": 0, "info": 0, "warn": 0}
    for item in findings:
        summary[item["severity"]] += 1
    threshold = SEVERITY_RANK[fail_on]
    blocking = [
        item for item in findings if SEVERITY_RANK[item["severity"]] >= threshold
    ]
    ordered = sorted(
        findings,
        key=lambda f: (f["rule"], f["path"], f.get("locator", ""), f["fingerprint"]),
    )
    unknown_ordered = sorted(
        unknown_coverage, key=lambda u: (u.get("path", ""), u.get("reason", ""))
    )
    return {
        "config_errors": sorted(config_errors),
        "findings": ordered,
        "pinwash_findings_version": FINDINGS_VERSION,
        "run": {
            "base": base_label,
            "head": head_label,
            "pinwash_version": __version__,
            "spec_version": SPEC_VERSION,
        },
        "summary": summary,
        "unknown_coverage": unknown_ordered,
        "verdict": "block" if blocking else "pass",
    }
