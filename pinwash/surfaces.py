"""v0 surface path membership. Closed set — adding a surface is a spec bump."""

from __future__ import annotations

import fnmatch

EXACT = frozenset(
    {
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".cursor/hooks.json",
        ".cursor/mcp.json",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "QWEN.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        ".github/copilot-instructions.md",
        ".github/required-ruleset.json",
        ".pinwash/pins.json",
        ".pinwash/allow.toml",
        ".checkwash/config.toml",
        ".greenwash/config.toml",
        ".gemini/settings.json",
        "opencode.json",
    }
)

SKILL_BYPASS_EXCLUDED_NAMES = frozenset({"SPEC.md", "THREATMODEL.md", "README.md"})


def norm(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def is_surface(path: str) -> bool:
    p = norm(path)
    if p in EXACT:
        return True
    if p.startswith(".claude/hooks/"):
        return True
    if p.startswith(".github/rulesets/") and p.endswith(".json"):
        return True
    if p.startswith(".github/workflows/") and p.count("/") == 2:
        if p.endswith(".yml") or p.endswith(".yaml"):
            return True
    if p.startswith(".cursor/rules/") and (p.endswith(".mdc") or p.endswith(".md")):
        return True
    if p.startswith(".agents/skills/") and p.endswith("SKILL.md"):
        return True
    if p.startswith(".cursor/skills/") and p.endswith("SKILL.md"):
        return True
    if p == "SKILL.md" or p.endswith("/SKILL.md"):
        return True
    return False


def skill_bypass_excluded(path: str) -> bool:
    name = norm(path).rsplit("/", 1)[-1]
    return name in SKILL_BYPASS_EXCLUDED_NAMES


def glob_skill(path: str) -> bool:
    p = norm(path)
    return p == "SKILL.md" or p.endswith("/SKILL.md") or fnmatch.fnmatch(p, "**/SKILL.md")


def is_agent_markdown(path: str) -> bool:
    p = norm(path)
    if p in {
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "QWEN.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        ".github/copilot-instructions.md",
    }:
        return True
    if p.startswith(".cursor/rules/") and (p.endswith(".mdc") or p.endswith(".md")):
        return True
    return False


def is_gemini_settings(path: str) -> bool:
    return norm(path) == ".gemini/settings.json"


def is_opencode_config(path: str) -> bool:
    return norm(path) == "opencode.json"


def is_claude_settings(path: str) -> bool:
    return norm(path) in {".claude/settings.json", ".claude/settings.local.json"}


def is_cursor_hooks(path: str) -> bool:
    return norm(path) == ".cursor/hooks.json"


def is_claude_hooks_file(path: str) -> bool:
    return norm(path).startswith(".claude/hooks/")


def is_cursor_mcp(path: str) -> bool:
    return norm(path) in {".cursor/mcp.json", ".mcp.json"}


def is_gha_workflow(path: str) -> bool:
    p = norm(path)
    return p.startswith(".github/workflows/") and p.count("/") == 2 and (
        p.endswith(".yml") or p.endswith(".yaml")
    )


def is_gha_ruleset(path: str) -> bool:
    p = norm(path)
    if p == ".github/required-ruleset.json":
        return True
    return p.startswith(".github/rulesets/") and p.endswith(".json")


def is_declared_pins(path: str) -> bool:
    return norm(path) == ".pinwash/pins.json"


def is_allow(path: str) -> bool:
    return norm(path) == ".pinwash/allow.toml"


def is_checkwash_config(path: str) -> bool:
    return norm(path) in {".checkwash/config.toml", ".greenwash/config.toml"}
