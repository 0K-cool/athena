# ATHENA Configurable Settings — Portable Open Source Architecture

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** HIGH — required for open source release

## Vision

ATHENA should be plug-and-play. Users configure backends and services through the Settings page or a config file — no code changes needed.

## Configurable Components

### 1. Kali Backends
- Add/remove Kali backend URLs
- Set API keys per backend
- Test connectivity from Settings
- Already partially in Settings page (external/internal URLs)

### 2. RAG Knowledge Base
- Enable/disable RAG
- Set RAG MCP server URL
- Set RAG search endpoint
- Index new documents from Settings
- View KB stats (document count, index size)
- Currently: RAG runs as separate MCP server, not integrated

### 3. Neo4j Database
- Already configurable (URI, user, password in Settings)

### 4. AI Provider
- Model selection per agent (Opus, Sonnet, Haiku)
- API key / OIDC configuration
- Cost caps per engagement

### 5. Engagement Defaults
- Default backend (external/internal)
- Default scan types (PR→AR→EX or custom)
- HITL mode (required/optional/disabled)
- CTF/LAB mode toggle

### 6. Observability
- Langfuse (already in Settings)
- Graphiti (already in Settings)

## Config File Format

`athena-config.yaml` at project root:

```yaml
athena:
  version: "2.0"
  dashboard:
    url: "http://localhost:8080"
    port: 8080

  backends:
    kali_external:
      url: "http://kali.example.com:5000"
      api_key: "${KALI_EXTERNAL_API_KEY}"
      enabled: true
    kali_internal:
      url: "http://192.168.1.100:5000"
      api_key: "${KALI_INTERNAL_API_KEY}"
      enabled: true

  rag:
    enabled: true
    mcp_server_url: "http://localhost:8081"
    search_endpoint: "/api/search"
    index_path: "./lance_athena_kb"

  neo4j:
    uri: "bolt://localhost:7687"
    user: "neo4j"
    password: "${NEO4J_PASSWORD}"

  ai:
    provider: "anthropic"
    default_model: "claude-sonnet-4-6"
    st_model: "claude-opus-4-6"
    api_key: "${ANTHROPIC_API_KEY}"

  engagement:
    default_backend: "external"
    hitl_mode: "required"  # required | optional | disabled
    max_cost_usd: 25.0
    time_limit_minutes: 60
```

## Settings Page Enhancement

The Settings page should have sections for each configurable component with:
- Current value display
- Edit button
- Test/validate button (ping endpoint, test connection)
- Save to config file

## Environment Variable Support

All secrets use `${VAR}` syntax — loaded from environment or `.env` file.
No plaintext secrets in config files.

## Migration Path

1. Current: hardcoded in server.py + agent_configs.py
2. Next: read from `athena-config.yaml` with env var substitution
3. Future: Settings page writes to config file
