#!/usr/bin/env node
// SDK-based integration test — uses @modelcontextprotocol/sdk as a real MCP
// client (StreamableHTTPClientTransport) to verify spec compliance beyond
// what the plain JSON-RPC tests in test.mjs cover.
//
// Usage: MCP_URL=https://mcp.phishunt.io node test/sdk-client.mjs

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const URL_ENDPOINT = process.env.MCP_URL || "http://localhost:8787";

let passed = 0;
let failed = 0;
const failures = [];

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
await test("client.listTools() returns 3 tools", async () => {
	const r = await client.listTools();
	tools = r.tools;
	assert(tools.length === 3, `expected 3, got ${tools.length}`);
	const names = tools.map((t) => t.name).sort();
	assert(
		JSON.stringify(names) ===
			JSON.stringify(["check_domain", "get_recent_detections", "list_brand_phishings"]),
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
