"""Exemption channel (SPEC §10): base-side .pinwash/allow.toml only."""

from __future__ import annotations

from datetime import date
from typing import Any

from pinwash.parse.jsonsurf import text_load
from pinwash.parse.tomlsub import allow_valid, parse_allow_toml
from pinwash.textutil import canonical_json


def detect_allow(
    base_files: dict[str, bytes],
    head_files: dict[str, bytes],
    today: date,
    add: Any,
    config_errors: list[str],
) -> None:
    path = ".pinwash/allow.toml"
    b_txt, b_st = text_load(base_files.get(path))
    h_txt, h_st = text_load(head_files.get(path))
    if b_st == "unparseable":
        config_errors.append("base allow.toml unreadable as utf-8")
    # SPEC §10: an exemption is a record satisfying the validity rule.
    # Invalid records are invisible to both checks.
    base_recs = [
        r for r in (parse_allow_toml(b_txt) if b_st == "ok" and b_txt else [])
        if allow_valid(r, today)
    ]
    # A head file that is missing or unparseable cannot confirm that a base
    # exemption still stands; the check below is fail-closed on that.
    head_recs = [
        r for r in (parse_allow_toml(h_txt) if h_st == "ok" and h_txt else [])
        if allow_valid(r, today)
    ]
    base_set = {canonical_json(r) for r in base_recs}
    head_set = {canonical_json(r) for r in head_recs}
    if base_set and not base_set.issubset(head_set):
        add(
            rule="CONFIG_RELAXED",
            severity="critical",
            message="base exemption deleted, edited, or unconfirmable at head",
            path=path,
        )
    elif head_set - base_set:
        add(
            rule="EXEMPTION_ADDED",
            severity="warn",
            message="head allow.toml append-only additions are visible, not trusted for this run",
            path=path,
        )


def apply_allow(
    findings: list[dict[str, Any]],
    base_files: dict[str, bytes],
    today: date,
) -> list[dict[str, Any]]:
    path = ".pinwash/allow.toml"
    text, status = text_load(base_files.get(path))
    if status != "ok" or text is None:
        return findings
    allowed = set()
    for rec in parse_allow_toml(text):
        if allow_valid(rec, today) and rec.get("fingerprint"):
            allowed.add((rec["fingerprint"], rec.get("rule", "")))
    kept: list[dict[str, Any]] = []
    for item in findings:
        key = (item["fingerprint"], item["rule"])
        if key in allowed:
            continue
        kept.append(item)
    return kept
