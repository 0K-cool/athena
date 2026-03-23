# AR nmap Aggressive Retries — 16% Success Rate (19 Attempts)

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — wastes tool calls + time

## Problem

AR ran nmap_scan 19 times with only 16% success rate (3/19). AR keeps retrying failed scans without adjusting scope or flags. Meanwhile VF ran nmap once with 100% success by targeting specific ports.

## Root Cause

AR likely runs heavy scans (`-sV -sC` or `-A`) on all 31 ports at once. These timeout at 300s. AR retries the same scan instead of:
1. Splitting into smaller port ranges (10 ports at a time)
2. Using lighter flags first (`-sV` only, no scripts)
3. Adjusting timing (`-T3` instead of `-T4`)

## Fix

Add scan strategy guidance to AR prompt in agent_configs.py:

"NMAP STRATEGY: Do NOT scan all ports with -sV at once on targets with 20+ ports.
Split into batches of 10 ports. Use -sV first, add --script only on interesting services.
If nmap times out, reduce scope — don't retry the same heavy scan."

Also consider: AR should use naabu for fast port discovery, then targeted nmap -sV on discovered ports in small batches.
