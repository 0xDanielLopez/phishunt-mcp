# phishunt-mcp

**Model Context Protocol (MCP) server for [phishunt.io](https://phishunt.io).**

Exposes the public phishing-domains feed as MCP tools so AI agents can look up
suspicious domains, list phishings by targeted brand, and sync detection deltas.

- **Endpoint**: `https://mcp.phishunt.io/` (HTTP JSON-RPC 2.0, POST)
- **Protocol version**: 2025-11-25
- **Auth**: none (data is CC0)
- **License (data)**: CC0-1.0 · **License (code)**: MIT

## Tools

| Name | Purpose |
|---|---|
| `check_domain` | Is this domain/URL substring in the active phishunt feed? |
| `list_brand_phishings` | List active phishings targeting a brand (e.g. `microsoft`). |
| `get_recent_detections` | Delta sync: detections since an ISO date. |
| `get_brand_metadata` | Curated brand metadata (display name, category, AI characterisation, active count). |
| `get_cert_metadata` | Factual metadata for an abused TLS intermediate CA (operator, root, key type, siblings). |
| `search_phishings` | Free-text search across active phishing URLs/domains/IPs (min 3 chars). |
| `analyze_url` | Passive phishing-signal analysis of any URL/domain - returns a single adjudicated `verdict` (phishing / likely_phishing / suspicious / no_evidence / not_assessed) plus the supporting evidence (URL-shape heuristics, stored score/verdict if known, external-feed cross-reference, historical detections). Unknown suspicious domains are auto-queued for full analysis. |
| `analyze_url_deep` | ACTIVE deep analysis of a URL (contacts the target: HTTP + TLS cert + RDAP + NS + GeoIP, SOCKS5-isolated) and re-scores it with the full 5-layer engine. Slow (5-15s), token-gated, and rate-limited (shared 50/day budget, single-flight) — requires `DEEP_TOKEN` configured on this Worker; use only when `analyze_url` is inconclusive. |
| `get_related_infrastructure` | Find infrastructure/content overlap for a known indicator (shared IP, cert, nameservers, favicon, etc.); surfaces the possible campaign / suspected cluster it belongs to. |
| `get_campaigns` | List possible campaigns / suspected clusters (shared-infrastructure groupings), optionally filtered by brand or active-only. |
| `get_campaign` | Full detail for one possible campaign / suspected cluster: evidence breakdown, every member indicator, export links. |

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

## Secrets

`analyze_url_deep` needs a `DEEP_TOKEN` Worker secret (the backend's
`X-Phishunt-Deep-Token`). Without it configured, the tool still appears in
`tools/list` but fails clean on `tools/call` — it never reaches the backend.

```bash
wrangler secret put DEEP_TOKEN
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
