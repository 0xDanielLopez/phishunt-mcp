// phishunt MCP server — wraps the public phishunt.io API as MCP tools.
//
// Protocol: Model Context Protocol over HTTP (JSON-RPC 2.0, single-shot).
// Spec: https://spec.modelcontextprotocol.io/specification/2025-03-26/
// Deploy: wrangler deploy — routes mcp.phishunt.io/*
//
// Read-only. No auth. All data CC0 per phishunt TOS.

const API_BASE = "https://phishunt.io";
const UA = "phishunt-mcp/0.1";
const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "phishunt-mcp", version: "0.1.0" };

// ── JSON-RPC types ─────────────────────────────────────────────────────────
type RpcRequest = {
	jsonrpc: "2.0";
	method: string;
	params?: Record<string, unknown>;
	id?: string | number | null;
};

type RpcResponse = {
	jsonrpc: "2.0";
	id: string | number | null;
	result?: unknown;
	error?: { code: number; message: string; data?: unknown };
};

const ERR = {
	PARSE: -32700,
	INVALID_REQUEST: -32600,
	METHOD_NOT_FOUND: -32601,
	INVALID_PARAMS: -32602,
	INTERNAL: -32603,
};

// ── Tool definitions ───────────────────────────────────────────────────────
const TOOLS = [
	{
		name: "check_domain",
		description:
			"Check whether a domain (or URL substring) appears in the phishunt active phishing feed. Returns matching entries with detection metadata if found, or a 'not found' note otherwise.",
		inputSchema: {
			type: "object",
			properties: {
				domain: {
					type: "string",
					description:
						"Domain or URL substring to search (e.g. 'fake-bank.com'). Case-insensitive substring match against the feed.",
				},
			},
			required: ["domain"],
		},
	},
	{
		name: "list_brand_phishings",
		description:
			"List active phishing sites targeting a specific brand. Returns the most recent detections with URL, IP, country, cert issuer, hosting org, and detection source flags.",
		inputSchema: {
			type: "object",
			properties: {
				brand: {
					type: "string",
					description:
						"Brand slug (lowercase). Examples: 'microsoft', 'binance', 'spotify', 'paypal'. See https://phishunt.io/api/ for the full list.",
				},
				limit: {
					type: "number",
					description: "Max results (1-1000). Default 50.",
					default: 50,
				},
			},
			required: ["brand"],
		},
	},
	{
		name: "get_recent_detections",
		description:
			"Retrieve phishing detections since a given date. Useful for delta-syncing a blocklist or threat intel pipeline.",
		inputSchema: {
			type: "object",
			properties: {
				since: {
					type: "string",
					description: "ISO date (YYYY-MM-DD) for the lower bound. Example: '2026-04-15'.",
				},
				limit: {
					type: "number",
					description: "Max results (1-1000). Default 100.",
					default: 100,
				},
				brand: {
					type: "string",
					description: "Optional brand slug filter (e.g. 'amazon').",
				},
			},
			required: ["since"],
		},
	},
	{
		name: "get_brand_metadata",
		description:
			"Fetch curated metadata for a tracked brand: display name, category, primary domain, an AI-authored characterisation of why the brand tends to be targeted by phishing, and the current count of active phishings. Useful for adding context to brand-specific responses.",
		inputSchema: {
			type: "object",
			properties: {
				brand: {
					type: "string",
					description:
						"Brand slug (lowercase). Examples: 'amazon', 'binance', 'paypal', 'microsoft'. See https://phishunt.io/api/ for the full list.",
				},
			},
			required: ["brand"],
		},
	},
	{
		name: "get_cert_metadata",
		description:
			"Fetch factual metadata for a TLS intermediate CA seen on phishing sites: operator, root CA, key type (RSA/ECDSA), typical use case, related sibling intermediates, and the count of active phishings using this intermediate. Helps answer 'I saw cert X in my browser, what is it?' for the most-abused intermediates.",
		inputSchema: {
			type: "object",
			properties: {
				cert: {
					type: "string",
					description:
						"Intermediate CA common name as stored by phishunt (e.g. 'WE1', 'R10', 'GTS CA 1C3'). Case-sensitive exact match. See https://phishunt.io/cert/ for the list.",
				},
			},
			required: ["cert"],
		},
	},
	{
		name: "search_phishings",
		description:
			"Free-text search across active phishing URLs, domains, and IP addresses. Returns matching detections sorted by most recent first_seen. Use for queries like 'show me sites containing steamcommunity', 'phishing on 1.2.3.4', or 'sites with ingdirect in the URL'.",
		inputSchema: {
			type: "object",
			properties: {
				query: {
					type: "string",
					description: "Search string (min 3 chars). Case-insensitive substring match against URL, domain, or IP.",
				},
				limit: {
					type: "number",
					description: "Max results (1-200). Default 50.",
					default: 50,
				},
			},
			required: ["query"],
		},
	},
] as const;

// ── Tool implementations ───────────────────────────────────────────────────
async function callTool(name: string, args: Record<string, unknown>) {
	if (name === "check_domain") return await toolCheckDomain(args);
	if (name === "list_brand_phishings") return await toolListBrand(args);
	if (name === "get_recent_detections") return await toolRecent(args);
	if (name === "get_brand_metadata") return await toolBrandMeta(args);
	if (name === "get_cert_metadata") return await toolCertMeta(args);
	if (name === "search_phishings") return await toolSearch(args);
	throw { code: ERR.METHOD_NOT_FOUND, message: `Unknown tool: ${name}` };
}

async function toolCheckDomain(args: Record<string, unknown>) {
	const domain = String(args.domain ?? "").trim().toLowerCase();
	if (!domain) throw { code: ERR.INVALID_PARAMS, message: "'domain' is required" };

	// Use feed.json (cached at CF edge) and substring-match URLs.
	const r = await fetch(`${API_BASE}/feed.json`, { headers: { "User-Agent": UA } });
	if (!r.ok) throw { code: ERR.INTERNAL, message: `feed.json returned HTTP ${r.status}` };
	const rows = (await r.json()) as Array<Record<string, unknown>>;
	const matches = rows.filter((row) =>
		typeof row.url === "string" && row.url.toLowerCase().includes(domain),
	);
	if (matches.length === 0) {
		return textContent(`Domain "${domain}" NOT found in the active phishunt feed (${rows.length} entries scanned).`);
	}
	const preview = matches.slice(0, 20);
	return textContent(
		`Found ${matches.length} match(es) for "${domain}" in the phishunt feed.\n` +
			`Showing first ${preview.length}:\n\n` +
			JSON.stringify(preview, null, 2),
	);
}

async function toolListBrand(args: Record<string, unknown>) {
	const brand = String(args.brand ?? "").trim().toLowerCase();
	if (!brand) throw { code: ERR.INVALID_PARAMS, message: "'brand' is required" };
	const limit = clampInt(args.limit, 1, 1000, 50);

	const url = `${API_BASE}/api/v1/domains?company=${encodeURIComponent(brand)}&limit=${limit}&format=json`;
	const r = await fetch(url, { headers: { "User-Agent": UA } });
	if (!r.ok) throw { code: ERR.INTERNAL, message: `API returned HTTP ${r.status}` };
	const data = (await r.json()) as { count: number; results: unknown[] };
	if (data.count === 0) {
		return textContent(
			`No active phishings found for brand "${brand}".\n` +
				`If the brand slug is wrong, see https://phishunt.io/api/ for the valid list.`,
		);
	}
	return textContent(
		`${data.count} active phishing(s) targeting "${brand}":\n\n` +
			JSON.stringify(data.results, null, 2),
	);
}

async function toolRecent(args: Record<string, unknown>) {
	const since = String(args.since ?? "").trim();
	// Regex alone would accept calendar-impossible dates (e.g. "2026-02-30").
	// Round-trip through Date so the agent gets a clear error instead of a
	// silent "0 detections" from the backend filter.
	if (!since || !/^\d{4}-\d{2}-\d{2}$/.test(since) ||
		!Number.isFinite(new Date(since + "T00:00:00Z").getTime()) ||
		new Date(since + "T00:00:00Z").toISOString().slice(0, 10) !== since) {
		throw { code: ERR.INVALID_PARAMS, message: "'since' must be a valid ISO date (YYYY-MM-DD)" };
	}
	const limit = clampInt(args.limit, 1, 1000, 100);
	const brand = args.brand ? String(args.brand).trim().toLowerCase() : "";

	const params = new URLSearchParams({ since, limit: String(limit), format: "json" });
	if (brand) params.set("company", brand);
	const url = `${API_BASE}/api/v1/domains?${params}`;
	const r = await fetch(url, { headers: { "User-Agent": UA } });
	if (!r.ok) throw { code: ERR.INTERNAL, message: `API returned HTTP ${r.status}` };
	const data = (await r.json()) as { count: number; results: unknown[] };
	return textContent(
		`${data.count} detection(s) since ${since}${brand ? ` (brand="${brand}")` : ""}:\n\n` +
			JSON.stringify(data.results, null, 2),
	);
}

async function toolBrandMeta(args: Record<string, unknown>) {
	const brand = String(args.brand ?? "").trim().toLowerCase();
	if (!brand) throw { code: ERR.INVALID_PARAMS, message: "'brand' is required" };
	const r = await fetch(`${API_BASE}/api/v1/brands/${encodeURIComponent(brand)}.json`, {
		headers: { "User-Agent": UA },
	});
	if (r.status === 404) {
		const data = (await r.json().catch(() => ({}))) as { error?: string };
		throw { code: ERR.INVALID_PARAMS, message: data.error || `Unknown brand: ${brand}` };
	}
	if (!r.ok) throw { code: ERR.INTERNAL, message: `API returned HTTP ${r.status}` };
	const data = await r.json();
	return textContent(JSON.stringify(data, null, 2));
}

async function toolCertMeta(args: Record<string, unknown>) {
	const cert = String(args.cert ?? "").trim();
	if (!cert) throw { code: ERR.INVALID_PARAMS, message: "'cert' is required" };
	const r = await fetch(`${API_BASE}/api/v1/certs/${encodeURIComponent(cert)}.json`, {
		headers: { "User-Agent": UA },
	});
	if (r.status === 404) {
		const data = (await r.json().catch(() => ({}))) as { error?: string };
		throw { code: ERR.INVALID_PARAMS, message: data.error || `Unknown cert: ${cert}` };
	}
	if (!r.ok) throw { code: ERR.INTERNAL, message: `API returned HTTP ${r.status}` };
	const data = await r.json();
	return textContent(JSON.stringify(data, null, 2));
}

async function toolSearch(args: Record<string, unknown>) {
	const query = String(args.query ?? "").trim();
	if (!query || query.length < 3) {
		throw { code: ERR.INVALID_PARAMS, message: "'query' must be at least 3 characters" };
	}
	const limit = clampInt(args.limit, 1, 200, 50);
	const params = new URLSearchParams({ q: query, limit: String(limit) });
	const r = await fetch(`${API_BASE}/api/v1/search.json?${params}`, { headers: { "User-Agent": UA } });
	if (!r.ok) throw { code: ERR.INTERNAL, message: `API returned HTTP ${r.status}` };
	const data = (await r.json()) as { count: number; results: unknown[] };
	if (data.count === 0) {
		return textContent(`No active phishings match "${query}".`);
	}
	return textContent(
		`${data.count} match(es) for "${query}":\n\n` + JSON.stringify(data.results, null, 2),
	);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function textContent(text: string) {
	return { content: [{ type: "text", text }] };
}

function clampInt(v: unknown, min: number, max: number, dflt: number): number {
	const n = Number(v);
	if (!Number.isFinite(n)) return dflt;
	return Math.min(max, Math.max(min, Math.floor(n)));
}

// ── JSON-RPC dispatcher ────────────────────────────────────────────────────
async function handleRpc(req: RpcRequest): Promise<RpcResponse> {
	const id = req?.id ?? null;

	// JSON-RPC 2.0: a Request object MUST have method as a string.
	// Missing/non-string method → -32600 Invalid Request, not -32601.
	if (!req || typeof req !== "object" || typeof req.method !== "string") {
		return {
			jsonrpc: "2.0",
			id,
			error: { code: ERR.INVALID_REQUEST, message: "Invalid Request: 'method' must be a string" },
		};
	}

	try {
		if (req.method === "initialize") {
			return {
				jsonrpc: "2.0",
				id,
				result: {
					protocolVersion: PROTOCOL_VERSION,
					capabilities: { tools: {} },
					serverInfo: SERVER_INFO,
					instructions:
						"Query the phishunt.io public phishing-domains feed. Data is CC0 licensed, read-only, no auth. Updated hourly.",
				},
			};
		}

		if (req.method === "ping") {
			return { jsonrpc: "2.0", id, result: {} };
		}

		if (req.method === "notifications/initialized") {
			// Notification — no response expected, but we return empty ok for HTTP single-shot.
			return { jsonrpc: "2.0", id, result: {} };
		}

		if (req.method === "tools/list") {
			return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
		}

		if (req.method === "tools/call") {
			const params = (req.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
			if (!params.name) {
				return {
					jsonrpc: "2.0",
					id,
					error: { code: ERR.INVALID_PARAMS, message: "'name' is required" },
				};
			}
			const result = await callTool(params.name, params.arguments ?? {});
			return { jsonrpc: "2.0", id, result };
		}

		return {
			jsonrpc: "2.0",
			id,
			error: { code: ERR.METHOD_NOT_FOUND, message: `Method not found: ${req.method}` },
		};
	} catch (e: unknown) {
		if (e && typeof e === "object" && "code" in e && "message" in e) {
			return { jsonrpc: "2.0", id, error: e as { code: number; message: string } };
		}
		return {
			jsonrpc: "2.0",
			id,
			error: {
				code: ERR.INTERNAL,
				message: e instanceof Error ? e.message : "Internal error",
			},
		};
	}
}

// ── HTTP entrypoint ────────────────────────────────────────────────────────
export default {
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		// CORS preflight so browser-based MCP clients can POST from another origin.
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type",
					"Access-Control-Max-Age": "86400",
				},
			});
		}

		// GET at root: a human-readable note.
		if (request.method === "GET") {
			const body = {
				service: "phishunt-mcp",
				protocol: "Model Context Protocol (MCP)",
				protocolVersion: PROTOCOL_VERSION,
				transport: "HTTP JSON-RPC 2.0 (POST)",
				endpoint: `${url.origin}/`,
				tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
				docs: "https://phishunt.io/api/",
				license: "CC0-1.0 (data)",
				source: "https://github.com/0xDanielLopez/phishunt-mcp",
			};
			return Response.json(body, {
				headers: {
					"Cache-Control": "public, max-age=300",
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type",
				},
			});
		}

		if (request.method !== "POST") {
			return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST" } });
		}

		let req: RpcRequest;
		try {
			req = (await request.json()) as RpcRequest;
		} catch {
			return Response.json(
				{ jsonrpc: "2.0", id: null, error: { code: ERR.PARSE, message: "Parse error" } },
				{ status: 400 },
			);
		}

		// Handle batch (array of requests) per JSON-RPC 2.0 spec.
		if (Array.isArray(req)) {
			const out = await Promise.all(req.map(handleRpc));
			return Response.json(out);
		}

		const response = await handleRpc(req);
		return Response.json(response, {
			headers: {
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type",
			},
		});
	},
};
