#!/usr/bin/env node
// SDK-based integration test — uses @modelcontextprotocol/sdk as a real MCP
// client (StreamableHTTPClientTransport) to verify spec compliance beyond
// what the plain JSON-RPC tests in test.mjs cover.
//
// Usage: MCP_URL=https://mcp.phishunt.io node test/sdk-client.mjs

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const URL_ENDPOINT = process.env.MCP_URL || "http://localhost:8787";

// Against prod (mcp.phishunt.io) the CF rate-limit rule (>5 req/10s per IP,
// tightened 2026-07-04; CF Error 1015 / HTTP 429) trips fast: SDK operations
// fire 2-3 unpaced POSTs each (initialize + notified + call). Space tests
// wide when hitting prod, and retry once after the advertised backoff if a
// burst still trips the rule (mirrors test.mjs doFetch).
// Local runs also pace since 2026-07-05: the CF rule covers phishunt.io/api/*
// which the API-backed tools hit upstream. THROTTLE_MS=0 to force off.
const IS_PROD = /mcp\.phishunt\.io/.test(URL_ENDPOINT);
const THROTTLE_MS = Number(process.env.THROTTLE_MS ?? (IS_PROD ? 4000 : 2500));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let passed = 0;
let failed = 0;
const failures = [];

function assert(cond, msg) {
	if (!cond) throw new Error(msg);
}

async function test(name, fn) {
	if (THROTTLE_MS) await sleep(THROTTLE_MS);
	try {
		await fn();
		console.log(`  ✓ ${name}`);
		passed++;
	} catch (e) {
		if (IS_PROD && /rate.?limit|1015|429/i.test(e.message)) {
			console.log(`    (CF 429 rate-limit; waiting 31s then retrying "${name}")`);
			await sleep(31_000);
			try {
				await fn();
				console.log(`  ✓ ${name} (after retry)`);
				passed++;
				return;
			} catch (e2) {
				e = e2;
			}
		}
		console.log(`  ✗ ${name}\n      ${e.message}`);
		failed++;
		failures.push({ name, error: e.message });
	}
}

console.log(`\nSDK client test against ${URL_ENDPOINT}\n`);

// ── Connect ────────────────────────────────────────────────────────────────
console.log("## SDK handshake + capability discovery");

const transport = new StreamableHTTPClientTransport(new URL(URL_ENDPOINT));
const client = new Client(
	{ name: "phishunt-mcp-sdk-test", version: "0.1.0" },
	{ capabilities: {} },
);

let serverInfo;
await test("client.connect() succeeds via StreamableHTTPClientTransport", async () => {
	await client.connect(transport);
	serverInfo = client.getServerVersion();
	assert(serverInfo?.name === "phishunt-mcp", `wrong server name: ${serverInfo?.name}`);
});

await test("server advertises tools capability", async () => {
	const caps = client.getServerCapabilities();
	assert(caps?.tools !== undefined, "missing tools capability");
});

// ── Tools via SDK ──────────────────────────────────────────────────────────
console.log("\n## Tool invocation via SDK");

let tools;
await test("client.listTools() returns 10 tools", async () => {
	const r = await client.listTools();
	tools = r.tools;
	assert(tools.length === 10, `expected 10, got ${tools.length}`);
	const names = tools.map((t) => t.name).sort();
	assert(
		JSON.stringify(names) === JSON.stringify([
			"analyze_url",
			"check_domain",
			"get_brand_metadata",
			"get_campaign",
			"get_campaigns",
			"get_cert_metadata",
			"get_recent_detections",
			"get_related_infrastructure",
			"list_brand_phishings",
			"search_phishings",
		]),
		`wrong tool names: ${names.join(", ")}`,
	);
});

await test("client.callTool('check_domain') returns text content", async () => {
	const r = await client.callTool({
		name: "check_domain",
		arguments: { domain: "definitely-not-phishing-zzz.example" },
	});
	assert(Array.isArray(r.content), "content is not array");
	assert(r.content[0].type === "text", `expected text, got ${r.content[0].type}`);
	assert(r.content[0].text.toLowerCase().includes("not found"), "expected 'not found' text");
});

await test("client.callTool('list_brand_phishings') returns content", async () => {
	const r = await client.callTool({
		name: "list_brand_phishings",
		arguments: { brand: "microsoft", limit: 3 },
	});
	assert(Array.isArray(r.content), "content is not array");
	assert(r.content[0].type === "text", "expected text");
	assert(r.content[0].text.length > 10, "empty content");
});

await test("client.callTool('get_recent_detections') with yesterday returns content", async () => {
	const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
	const r = await client.callTool({
		name: "get_recent_detections",
		arguments: { since: yesterday, limit: 5 },
	});
	assert(Array.isArray(r.content), "content is not array");
	assert(/\d+ detection/.test(r.content[0].text), "expected detection count in text");
});

await test("client.callTool('get_brand_metadata') returns curated note", async () => {
	const r = await client.callTool({
		name: "get_brand_metadata",
		arguments: { brand: "amazon" },
	});
	assert(Array.isArray(r.content), "content is not array");
	const data = JSON.parse(r.content[0].text);
	assert(data.slug === "amazon", `wrong slug: ${data.slug}`);
	assert(typeof data.notes === "string", "notes missing");
});

await test("client.callTool('get_cert_metadata') returns operator info", async () => {
	const r = await client.callTool({
		name: "get_cert_metadata",
		arguments: { cert: "WE1" },
	});
	const data = JSON.parse(r.content[0].text);
	assert(data.cert === "WE1", `wrong cert: ${data.cert}`);
	assert(data.operator?.includes("Google"), `wrong operator: ${data.operator}`);
});

await test("client.callTool('search_phishings') with valid query returns content", async () => {
	const r = await client.callTool({
		name: "search_phishings",
		arguments: { query: "instagram", limit: 3 },
	});
	assert(Array.isArray(r.content), "content is not array");
	assert(r.content[0].text.length > 10, "empty content");
});

await test("client.callTool('analyze_url') returns live_analysis JSON", async () => {
	const r = await client.callTool({
		name: "analyze_url",
		arguments: { url: "https://example-test-domain-phishunt.com" },
	});
	assert(Array.isArray(r.content), "content is not array");
	const data = JSON.parse(r.content[0].text);
	assert(data && typeof data === "object" && "live_analysis" in data, "expected 'live_analysis' key");
});

// ── Error cases via SDK ────────────────────────────────────────────────────
console.log("\n## SDK error handling");

await test("unknown tool via SDK throws", async () => {
	let errored = false;
	try {
		await client.callTool({ name: "nonexistent_tool", arguments: {} });
	} catch (e) {
		errored = true;
		assert(String(e).match(/-32601|unknown tool|not found/i), `wrong error message: ${e}`);
	}
	assert(errored, "expected error, got success");
});

await test("invalid params (missing required) via SDK surfaces error", async () => {
	let errored = false;
	try {
		// get_recent_detections needs 'since'; omit it
		await client.callTool({ name: "get_recent_detections", arguments: {} });
	} catch (e) {
		errored = true;
	}
	assert(errored, "expected error for missing required param");
});

// ── Cleanup ────────────────────────────────────────────────────────────────
await test("client.close() cleans up transport", async () => {
	await client.close();
});

// ── Summary ────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	console.log("\nFailures:");
	for (const f of failures) console.log(`  - ${f.name}: ${f.error}`);
	process.exit(1);
}
process.exit(0);
