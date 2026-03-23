# RAG Knowledge Base Endpoint Not Available on Dashboard Server

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — agents can't search RAG despite being told to

## Problem

Agent prompts tell agents to search the RAG knowledge base via:
```
curl -s "{dashboard_url}/api/knowledge/search?q=<query>&top_k=5"
```

But this endpoint does NOT exist on the ATHENA dashboard server (server.py). The RAG runs as a separate MCP server process. Agents get 404 when they try to search.

## Impact

- Agents told to "MANDATORY search before exploiting" — but search returns 404
- No RAG results → agents skip to guessing (no proven commands from Kali book)
- The entire RAG research pipeline is broken for agents

## Fix Options

1. **Proxy endpoint:** Add `/api/knowledge/search` to server.py that proxies to the RAG MCP server
2. **Direct MCP:** Agents use the RAG MCP tool (`mcp__athena_knowledge_base__search_kb`) instead of curl
3. **Embed RAG:** Run the RAG search function inside the dashboard server process

Option 2 is fastest — agents already have `mcp__athena_knowledge_base__search_kb` in their allowed tools. Just need to update the prompt to use the MCP tool instead of curl.
