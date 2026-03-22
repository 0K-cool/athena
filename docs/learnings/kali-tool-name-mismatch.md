# Kali Tool Name Mismatch — naabu vs naabu_scan

**Created:** 2026-03-22
**Status:** Pending fix (Kali-side)
**Priority:** LOW — AR self-corrects at runtime

## Problem

Kali external health endpoint reports `naabu: True` but the ATHENA tool registry uses `naabu_scan`. The name mismatch causes the initial tool availability check to miss naabu on external. AR discovers it works at runtime via execute_command.

## Evidence

- Kali health: `{"naabu": true}` — uses short name
- Tool registry: `"naabu_scan"` — uses suffixed name
- Runtime: `mcp__kali_external__naabu_scan` works via `/api/command` path

## Fix Options

1. **Kali-side (preferred):** Update Kali health endpoint to report `naabu_scan` (matching registry)
2. **Registry-side:** Rename to `naabu` — but breaks MCP tool names in agent prompts
3. **Client-side:** Add name mapping in `kali_client.py` health check — `naabu` → `naabu_scan`

## Other Tools Potentially Affected

Check if other tools have similar name mismatches between Kali health and tool registry.
