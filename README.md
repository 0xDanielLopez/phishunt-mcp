# phishunt-mcp

**Model Context Protocol (MCP) server for [phishunt.io](https://phishunt.io).**

Exposes the public phishing-domains feed as MCP tools so AI agents can look up
suspicious domains, list phishings by targeted brand, and sync detection deltas.

- **Endpoint**: `https://mcp.phishunt.io/` (HTTP JSON-RPC 2.0, POST)
- **Protocol version**: 2025-03-26
- **Auth**: none (data is CC0)
- **License (data)**: CC0-1.0 · **License (code)**: MIT

## Tools

| Name | Purpose |
|---|---|
| `check_domain` | Is this domain/URL substring in the active phishunt feed? |
| `list_brand_phishings` | List active phishings targeting a brand (e.g. `microsoft`). |
| `get_recent_detections` | Delta sync: detections since an ISO date. |

## Use with Claude Desktop / Claude.ai / other MCP clients

Add to your MCP client config:

```json
{
  "mcpServers": {
    "phishunt": {
      "url": "https://mcp.phishunt.io/"
    }
  }
}
```

## Quick test

```bash
curl -sX POST https://mcp.phishunt.io/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq .
```

## Develop

```bash
npm install
npm run dev          # wrangler dev on http://localhost:8787
MCP_URL=http://localhost:8787 npm test
```

## Deploy

```bash
npm run deploy       # wrangler deploy
MCP_URL=https://mcp.phishunt.io npm test
```
