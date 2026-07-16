#!/usr/bin/env node
// phishunt-mcp integration tests.
// Usage: MCP_URL=https://mcp.phishunt.io node test/test.mjs
//        (or MCP_URL=http://localhost:8787 for local dev)

const URL_ENDPOINT = process.env.MCP_URL || "http://localhost:8787";

// Against prod (mcp.phishunt.io) the Cloudflare rate-limit rule (>5 req/10s,
// tightened 2026-07-04) would otherwise fail most of the suite with HTTP 429
// even on a perfectly healthy server. Self-throttle below the limit and back
// off on 429 so the prod run is a trustworthy post-deploy gate. Local runs
// (wrangler dev) also need pacing since 2026-07-05: the same CF rule now
// covers phishunt.io/api/*, which the API-backed tools fetch upstream from
// the laptop's IP. Override with THROTTLE_MS=0 for offline-only runs.
const IS_PROD = /mcp\.phishunt\.io/.test(URL_ENDPOINT);
const THROTTLE_MS = Number(process.env.THROTTLE_MS ?? (IS_PROD ? 2200 : 2100));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function doFetch(url, opts) {
	for (let attempt = 0; ; attempt++) {
		if (THROTTLE_MS) await sleep(THROTTLE_MS);
		const r = await fetch(url, opts);
		if (r.status === 429 && attempt < 3) {
			const ra = Number(r.headers.get("retry-after")) || 11;
			console.log(`    (CF 429 rate-limit; waiting ${ra}s then retrying)`);
			await sleep(ra * 1000);
			continue;
		}
		return r;
	}
}

let passed = 0;
let failed = 0;
const failures = [];

async function rpc(method, params, id = 1) {
	const body = { jsonrpc: "2.0", method, params, id };
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	return { status: r.status, body: await r.json(), headers: Object.fromEntries(r.headers) };
}

function assert(cond, msg) {
	if (!cond) throw new Error(msg);
}

async function test(name, fn) {
	try {
		await fn();
		console.log(`  ✓ ${name}`);
		passed++;
	} catch (e) {
		console.log(`  ✗ ${name}\n      ${e.message}`);
		failed++;
		failures.push({ name, error: e.message });
	}
}

// ── Tests ───────────────────────────────────────────────────────────────────

console.log(`\nTarget: ${URL_ENDPOINT}\n`);

console.log("## Protocol handshake");

await test("initialize returns server info + protocol version + tools capability", async () => {
	const r = await rpc("initialize", {
		protocolVersion: "2025-11-25",
		capabilities: {},
		clientInfo: { name: "phishunt-mcp-test", version: "1" },
	});
	assert(r.status === 200, `HTTP ${r.status}`);
	assert(r.body.jsonrpc === "2.0", "missing jsonrpc version");
	assert(r.body.id === 1, `wrong id: ${r.body.id}`);
	assert(r.body.result, `no result: ${JSON.stringify(r.body.error)}`);
	assert(r.body.result.serverInfo?.name === "phishunt-mcp", "wrong server name");
	assert(r.body.result.protocolVersion === "2025-11-25", "wrong protocol version");
	assert(r.body.result.capabilities?.tools !== undefined, "missing tools capability");
});

await test("ping returns empty result", async () => {
	const r = await rpc("ping", {});
	assert(r.body.result !== undefined, `ping failed: ${JSON.stringify(r.body)}`);
});

await test("GET returns human-readable service card", async () => {
	const r = await doFetch(URL_ENDPOINT, { method: "GET" });
	assert(r.status === 200, `GET status ${r.status}`);
	const j = await r.json();
	assert(j.service === "phishunt-mcp", "wrong service name");
	assert(Array.isArray(j.tools), "tools array missing");
	assert(j.tools.length === 7, `expected 7 tools, got ${j.tools.length}`);
});

console.log("\n## Tools listing");

await test("tools/list returns 7 tools with proper schemas", async () => {
	const r = await rpc("tools/list", {});
	assert(r.body.result?.tools, "no tools in result");
	const tools = r.body.result.tools;
	assert(tools.length === 7, `expected 7 tools, got ${tools.length}`);
	const names = tools.map((t) => t.name).sort();
	assert(
		JSON.stringify(names) === JSON.stringify([
			"analyze_url",
			"check_domain",
			"get_brand_metadata",
			"get_cert_metadata",
			"get_recent_detections",
			"list_brand_phishings",
			"search_phishings",
		]),
		`wrong tool names: ${names.join(", ")}`,
	);
	for (const t of tools) {
		assert(typeof t.description === "string" && t.description.length > 10, `${t.name}: weak description`);
		assert(t.inputSchema?.type === "object", `${t.name}: missing inputSchema.type`);
		assert(Array.isArray(t.inputSchema.required), `${t.name}: missing required[]`);
	}
});

console.log("\n## Tool: check_domain");

await test("check_domain on a definitely-not-flagged domain returns 'not found'", async () => {
	const r = await rpc("tools/call", {
		name: "check_domain",
		arguments: { domain: "definitely-not-a-phishing-example-zzzz.com" },
	});
	assert(r.body.result, `no result: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.toLowerCase().includes("not found"), `expected 'not found' language: ${text.slice(0, 200)}`);
});

await test("check_domain requires 'domain' param", async () => {
	const r = await rpc("tools/call", { name: "check_domain", arguments: {} });
	assert(r.body.error, "expected error for missing domain");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
});

console.log("\n## Tool: list_brand_phishings");

await test("list_brand_phishings for 'microsoft' returns content", async () => {
	const r = await rpc("tools/call", {
		name: "list_brand_phishings",
		arguments: { brand: "microsoft", limit: 5 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.length > 0, "empty text");
});

await test("list_brand_phishings for nonsense-brand returns 'no active' text (not an error)", async () => {
	const r = await rpc("tools/call", {
		name: "list_brand_phishings",
		arguments: { brand: "nonsense-brand-that-doesnt-exist-zzzz", limit: 5 },
	});
	assert(r.body.result, "expected result, not error");
	const text = r.body.result.content[0].text.toLowerCase();
	assert(text.includes("no active") || text.includes("no ") || text.includes("0 "),
		`expected no-match text, got: ${text.slice(0, 200)}`);
});

console.log("\n## Tool: get_recent_detections");

await test("get_recent_detections since yesterday returns content", async () => {
	const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
	const r = await rpc("tools/call", {
		name: "get_recent_detections",
		arguments: { since: yesterday, limit: 10 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(/\d+ detection/.test(text), `expected '<N> detection(s)' format: ${text.slice(0, 200)}`);
});

await test("get_recent_detections with invalid date returns INVALID_PARAMS error", async () => {
	const r = await rpc("tools/call", {
		name: "get_recent_detections",
		arguments: { since: "not-a-date" },
	});
	assert(r.body.error, `expected error, got result: ${JSON.stringify(r.body.result)}`);
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
});

console.log("\n## Tool: get_brand_metadata");

await test("get_brand_metadata for 'amazon' returns curated note + active count", async () => {
	const r = await rpc("tools/call", {
		name: "get_brand_metadata",
		arguments: { brand: "amazon" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	const data = JSON.parse(text);
	assert(data.slug === "amazon", `wrong slug: ${data.slug}`);
	assert(data.name === "Amazon", `wrong name: ${data.name}`);
	assert(typeof data.notes === "string" && data.notes.length > 20, "missing notes");
	assert(Number.isInteger(data.active_phishings), "active_phishings not int");
});

await test("get_brand_metadata for unknown brand returns INVALID_PARAMS", async () => {
	const r = await rpc("tools/call", {
		name: "get_brand_metadata",
		arguments: { brand: "this-is-not-a-real-brand-zzzz" },
	});
	assert(r.body.error, `expected error, got: ${JSON.stringify(r.body.result)}`);
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
});

console.log("\n## Tool: get_cert_metadata");

await test("get_cert_metadata for 'WE1' returns operator + key_type", async () => {
	const r = await rpc("tools/call", {
		name: "get_cert_metadata",
		arguments: { cert: "WE1" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const data = JSON.parse(r.body.result.content[0].text);
	assert(data.cert === "WE1", `wrong cert: ${data.cert}`);
	assert(data.operator?.includes("Google"), `wrong operator: ${data.operator}`);
	assert(data.key_type === "ECDSA", `wrong key_type: ${data.key_type}`);
});

await test("get_cert_metadata for unknown intermediate returns INVALID_PARAMS", async () => {
	const r = await rpc("tools/call", {
		name: "get_cert_metadata",
		arguments: { cert: "NOT_A_REAL_INTERMEDIATE_ZZZZ" },
	});
	assert(r.body.error, `expected error, got: ${JSON.stringify(r.body.result)}`);
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
});

console.log("\n## Tool: search_phishings");

await test("search_phishings with valid query returns formatted results", async () => {
	const r = await rpc("tools/call", {
		name: "search_phishings",
		arguments: { query: "instagram", limit: 3 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	// Either matched (N match(es) for ...) or empty (No active phishings ...)
	assert(/match\(es\) for|No active phishings/.test(text), `unexpected text: ${text.slice(0, 200)}`);
});

await test("search_phishings rejects queries shorter than 3 chars", async () => {
	const r = await rpc("tools/call", {
		name: "search_phishings",
		arguments: { query: "ab" },
	});
	assert(r.body.error, "expected error for short query");
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
});

console.log("\n## Tool: analyze_url");

await test("analyze_url with a syntactically valid URL returns live_analysis JSON", async () => {
	const r = await rpc("tools/call", {
		name: "analyze_url",
		arguments: { url: "https://example-test-domain-phishunt.com" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	const data = JSON.parse(text);
	assert(data && typeof data === "object" && "live_analysis" in data, `expected 'live_analysis' key: ${text.slice(0, 200)}`);
});

await test("analyze_url requires 'url' param", async () => {
	const r = await rpc("tools/call", { name: "analyze_url", arguments: {} });
	assert(r.body.error, "expected error for missing url");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
});

await test("analyze_url with unsupported scheme returns INVALID_PARAMS", async () => {
	const r = await rpc("tools/call", {
		name: "analyze_url",
		arguments: { url: "ftp://x" },
	});
	assert(r.body.error, `expected error for unsupported scheme, got: ${JSON.stringify(r.body.result)}`);
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
});

console.log("\n## Error handling");

await test("unknown tool returns METHOD_NOT_FOUND (-32601)", async () => {
	const r = await rpc("tools/call", { name: "nonexistent_tool", arguments: {} });
	assert(r.body.error, "expected error");
	assert(r.body.error.code === -32601, `expected -32601, got ${r.body.error.code}`);
});

await test("unknown RPC method returns METHOD_NOT_FOUND", async () => {
	const r = await rpc("unknown/method", {});
	assert(r.body.error?.code === -32601, `expected -32601, got ${r.body.error?.code}`);
});

await test("missing method field returns INVALID_REQUEST (-32600)", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ jsonrpc: "2.0", id: 1, foo: "bar" }),
	});
	const j = await r.json();
	assert(j.error?.code === -32600, `expected -32600, got ${j.error?.code}`);
});

await test("malformed JSON in POST returns parse error HTTP 400", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: "{not valid json",
	});
	assert(r.status === 400, `expected 400, got ${r.status}`);
	const j = await r.json();
	assert(j.error?.code === -32700, `expected -32700, got ${j.error?.code}`);
});

console.log("\n## JSON-RPC 2.0 compliance");

await test("batch request returns array of responses", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify([
			{ jsonrpc: "2.0", method: "ping", id: 1 },
			{ jsonrpc: "2.0", method: "tools/list", id: 2 },
		]),
	});
	const arr = await r.json();
	assert(Array.isArray(arr), `expected array, got ${typeof arr}`);
	assert(arr.length === 2, `expected 2 responses, got ${arr.length}`);
	assert(arr[0].id === 1 && arr[1].id === 2, "ids not preserved");
});

await test("empty batch returns -32600 Invalid Request", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: "[]",
	});
	assert(r.status === 400, `expected 400, got ${r.status}`);
	const j = await r.json();
	assert(!Array.isArray(j), "expected single error object, got array");
	assert(j.error?.code === -32600, `expected -32600, got ${j.error?.code}`);
});

await test("mixed batch (requests + notifications) returns only request responses", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify([
			{ jsonrpc: "2.0", method: "ping", id: 1 },
			{ jsonrpc: "2.0", method: "notifications/initialized" }, // no id: notification
			{ jsonrpc: "2.0", method: "ping", id: 2 },
			{ jsonrpc: "2.0", method: "notifications/initialized", id: null }, // id:null: also a notification
		]),
	});
	assert(r.status === 200, `expected 200, got ${r.status}`);
	const arr = await r.json();
	assert(Array.isArray(arr), `expected array, got ${typeof arr}`);
	assert(arr.length === 2, `expected 2 responses (notifications dropped), got ${arr.length}: ${JSON.stringify(arr)}`);
	const ids = arr.map((x) => x.id).sort();
	assert(JSON.stringify(ids) === JSON.stringify([1, 2]), `expected ids [1,2], got ${JSON.stringify(ids)}`);
});

await test("all-notifications batch returns 202 with empty body", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify([
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			{ jsonrpc: "2.0", method: "ping", id: null },
		]),
	});
	assert(r.status === 202, `expected 202, got ${r.status}`);
	const text = await r.text();
	assert(text === "", `expected empty body, got: ${text.slice(0, 200)}`);
});

await test("normal batch of requests (no notifications) is unaffected", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify([
			{ jsonrpc: "2.0", method: "ping", id: "a" },
			{ jsonrpc: "2.0", method: "tools/list", id: "b" },
			{ jsonrpc: "2.0", method: "unknown/method", id: "c" },
		]),
	});
	assert(r.status === 200, `expected 200, got ${r.status}`);
	const arr = await r.json();
	assert(Array.isArray(arr) && arr.length === 3, `expected 3 responses, got ${JSON.stringify(arr)}`);
	const ids = arr.map((x) => x.id).sort();
	assert(JSON.stringify(ids) === JSON.stringify(["a", "b", "c"]), `ids not preserved: ${JSON.stringify(ids)}`);
	assert(arr.find((x) => x.id === "c").error?.code === -32601, "unknown method should still error inside batch");
});

await test("notifications/initialized returns 202 with empty body", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
	});
	assert(r.status === 202, `expected 202, got ${r.status}`);
	const text = await r.text();
	assert(text === "", `expected empty body, got: ${text.slice(0, 200)}`);
});

await test("CORS preflight allows MCP-Protocol-Version header", async () => {
	const r = await doFetch(URL_ENDPOINT, {
		method: "OPTIONS",
		headers: {
			Origin: "https://example.com",
			"Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": "content-type,mcp-protocol-version",
		},
	});
	assert(r.status === 204, `expected 204, got ${r.status}`);
	const allow = (r.headers.get("access-control-allow-headers") || "").toLowerCase();
	assert(allow.includes("mcp-protocol-version"), `Allow-Headers missing MCP-Protocol-Version: "${allow}"`);
	assert(r.headers.get("access-control-allow-origin") === "*", "missing ACAO on preflight");
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	console.log("\nFailures:");
	for (const f of failures) console.log(`  - ${f.name}: ${f.error}`);
	process.exit(1);
}
process.exit(0);
