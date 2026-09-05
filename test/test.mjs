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

// Registrar legal names legitimately contain "Group"/"LLC"/etc (e.g. "Global
// Domain Group LLC") - that's factual WHOIS metadata, not attribution
// language, so it must not trip the actor/group/operator ban below.
function stripRegistrarLines(text) {
	return text.replace(/^.*same_registrar:.*$/gm, "");
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
	assert(j.tools.length === 11, `expected 11 tools, got ${j.tools.length}`);
});

console.log("\n## Tools listing");

await test("tools/list returns 11 tools with proper schemas", async () => {
	const r = await rpc("tools/list", {});
	assert(r.body.result?.tools, "no tools in result");
	const tools = r.body.result.tools;
	assert(tools.length === 11, `expected 11 tools, got ${tools.length}`);
	const names = tools.map((t) => t.name).sort();
	assert(
		JSON.stringify(names) === JSON.stringify([
			"analyze_url",
			"analyze_url_deep",
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
	for (const t of tools) {
		assert(typeof t.description === "string" && t.description.length > 10, `${t.name}: weak description`);
		assert(t.inputSchema?.type === "object", `${t.name}: missing inputSchema.type`);
		assert(Array.isArray(t.inputSchema.required), `${t.name}: missing required[]`);
	}
});

await test("get_campaign declares an outputSchema (structured content, batch 4)", async () => {
	const r = await rpc("tools/list", {});
	const tool = r.body.result.tools.find((t) => t.name === "get_campaign");
	assert(tool, "get_campaign not found in tools/list");
	assert(tool.outputSchema?.type === "object", "get_campaign missing outputSchema.type === 'object'");
	assert(Array.isArray(tool.outputSchema.oneOf) && tool.outputSchema.oneOf.length === 2, "expected a live/archived oneOf split");
	// Other tools deliberately have no outputSchema yet - only get_campaign
	// gained one in this batch.
	const others = r.body.result.tools.filter((t) => t.name !== "get_campaign");
	assert(others.every((t) => t.outputSchema === undefined), "unexpected outputSchema on a tool other than get_campaign");
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

// feed.json is not rate-limited, so this plain fetch (outside doFetch's
// throttle/rpc machinery) is free to run once, up front, to source a real
// live domain and a real apex suffix for the host-exact-match tests below.
const liveFeedRows = await (await fetch("https://phishunt.io/feed.json")).json();
let live = liveFeedRows[0]?.domain;
let suffix = live ? live.split(".").slice(1).join(".") : "";
if (!suffix || suffix.split(".").length < 2) {
	const alt = liveFeedRows.find((row) => String(row.domain || "").split(".").length >= 3);
	assert(alt, "no feed row has a domain with >= 3 labels to test apex-suffix stripping");
	live = alt.domain;
	suffix = live.split(".").slice(1).join(".");
}

await test("check_domain: a live feed domain returns LISTED (exact host match)", async () => {
	const r = await rpc("tools/call", { name: "check_domain", arguments: { domain: live } });
	assert(r.body.result, `no result: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.includes("LISTED"), `expected LISTED: ${text.slice(0, 300)}`);
});

await test("check_domain: apex suffix of a listed subdomain is not found, but lists hosts under it", async () => {
	const r = await rpc("tools/call", { name: "check_domain", arguments: { domain: suffix } });
	assert(r.body.result, `no result: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.includes("not found"), `expected 'not found': ${text.slice(0, 300)}`);
	assert(text.includes("host(s) under it"), `expected 'host(s) under it': ${text.slice(0, 300)}`);

	const rf = await rpc("tools/call", { name: "check_domain", arguments: { domain: suffix, fuzzy: true } });
	assert(rf.body.result, `no result: ${JSON.stringify(rf.body)}`);
	const textFuzzy = rf.body.result.content[0].text;
	assert(textFuzzy.includes("FUZZY"), `expected FUZZY: ${textFuzzy.slice(0, 300)}`);
});

await test("check_domain: array input returns one line per host, in order, and caps at 20", async () => {
	const r = await rpc("tools/call", {
		name: "check_domain",
		arguments: { domain: [live, "definitely-not-a-phishing-example-zzzz.com", "www." + live] },
	});
	assert(r.body.result, `no result: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	const hostLines = text.split("\n").filter((line) => line.startsWith('"'));
	assert(hostLines.length === 3, `expected 3 host lines, got ${hostLines.length}: ${text.slice(0, 500)}`);
	assert(hostLines[1].includes("not found"), `line 2 should be a miss: ${hostLines[1]}`);
	assert(hostLines[2].includes("LISTED"), `line 3 (www. variant) should be LISTED: ${hostLines[2]}`);

	const rBig = await rpc("tools/call", {
		name: "check_domain",
		arguments: { domain: Array.from({ length: 21 }, (_, i) => "h" + i + ".example") },
	});
	assert(rBig.body.error, "expected error for a 21-item array");
	assert(rBig.body.error.code === -32602, `expected INVALID_PARAMS, got ${rBig.body.error.code}`);
});

await test("check_domain: a never-flagged domain reports its archive-check outcome", async () => {
	const r = await rpc("tools/call", {
		name: "check_domain",
		arguments: { domain: "definitely-not-a-phishing-example-zzzz.com" },
	});
	assert(r.body.result, `no result: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.includes("not found"), `expected 'not found': ${text.slice(0, 300)}`);
	assert(
		/no record, active or archived|archive not checked/.test(text),
		`expected archive outcome language: ${text.slice(0, 300)}`,
	);
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

console.log("\n## Tool: analyze_url_deep");

// analyze_url_deep is the token-gated ACTIVE sibling of analyze_url. Its
// param validation runs before the DEEP_TOKEN check and before any network
// call, so this is safe to run in every environment.
await test("analyze_url_deep requires 'url' param (no network touched)", async () => {
	const r = await rpc("tools/call", { name: "analyze_url_deep", arguments: {} });
	assert(r.body.error, "expected error for missing url");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
});

if (!IS_PROD) {
	// Local `wrangler dev` has no DEEP_TOKEN secret configured by default (no
	// .dev.vars checked into this repo), so this exercises the "fails clean
	// without ever calling the backend" path deterministically. Skipped
	// against prod: whether mcp.phishunt.io has DEEP_TOKEN configured is
	// unknown from here, and if it does, this call would trigger a REAL deep
	// analysis against the live backend (5-15s, consumes the shared
	// 50/day production budget) -- not something a test suite should risk.
	await test("analyze_url_deep fails clean when DEEP_TOKEN is unset (local dev)", async () => {
		const r = await rpc("tools/call", {
			name: "analyze_url_deep",
			arguments: { url: "https://example-test-domain-phishunt.com" },
		});
		assert(r.body.error, `expected error, got result: ${JSON.stringify(r.body.result)}`);
		assert(r.body.error.code === -32603, `expected INTERNAL, got ${r.body.error.code}`);
		assert(/DEEP_TOKEN/.test(r.body.error.message), `expected a DEEP_TOKEN mention: ${r.body.error.message}`);
	});
}

console.log("\n## Tool: get_related_infrastructure");

await test("get_related_infrastructure returns correlation text or 'not in feed' note", async () => {
	const r = await rpc("tools/call", {
		name: "get_related_infrastructure",
		arguments: { domain: "m4ntapaset" },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text.toLowerCase();
	// This tool hits two live upstream endpoints in sequence (search + related),
	// so whether the sample domain is currently in the feed is not guaranteed -
	// accept either outcome, same tolerance pattern as list_brand_phishings.
	assert(
		text.includes("related infrastructure") || text.includes("not in the active phishunt feed"),
		`unexpected text: ${text.slice(0, 200)}`,
	);
});

await test("get_related_infrastructure requires 'domain' param", async () => {
	const r = await rpc("tools/call", { name: "get_related_infrastructure", arguments: {} });
	assert(r.body.error, "expected error for missing domain");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
});

console.log("\n## Tool: get_campaigns");

await test("get_campaigns returns a list with disclaimer + algorithm/generated_at footer", async () => {
	const r = await rpc("tools/call", {
		name: "get_campaigns",
		arguments: { limit: 3 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(
		/not an attribution claim/i.test(text) || /No possible campaigns/.test(text),
		`missing disclaimer or empty-result text: ${text.slice(0, 200)}`,
	);
	assert(!/\bactor\b|\bgroup\b|\boperator\b/i.test(stripRegistrarLines(text)), `should never use actor/group/operator language: ${text.slice(0, 300)}`);
});

await test("get_campaigns with brand + active_only filters returns content (possibly empty)", async () => {
	const r = await rpc("tools/call", {
		name: "get_campaigns",
		arguments: { brand: "nonsense-brand-that-doesnt-exist-zzzz", active_only: true, limit: 2 },
	});
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text.toLowerCase();
	assert(text.includes("no possible campaigns"), `expected empty-result text, got: ${text.slice(0, 200)}`);
});

await test("get_campaigns notes total vs shown when more campaigns exist than this call's limit", async () => {
	// `total` is a phishunt-web batch-4 field this tool now reads off the
	// upstream JSON - not yet live on phishunt.io at the time this MCP
	// change was written (verify directly against the raw API, bypassing
	// this tool's own formatting, so the test isn't circular). Skips
	// gracefully pre-deploy rather than asserting behavior the upstream API
	// cannot yet produce; meaningful once phishunt-web batch 4 ships.
	const rawProbe = await doFetch("https://phishunt.io/api/v1/campaigns?limit=1");
	const rawJson = await rawProbe.json().catch(() => ({}));
	if (typeof rawJson.total !== "number") {
		console.log("    (skipped: upstream /api/v1/campaigns has no 'total' yet - phishunt-web batch 4 not deployed)");
		return;
	}
	if (rawJson.total < 2) {
		console.log(`    (skipped: only ${rawJson.total} live campaign(s) right now, nothing to truncate)`);
		return;
	}
	const r = await rpc("tools/call", { name: "get_campaigns", arguments: { limit: 1 } });
	const text = r.body.result?.content?.[0]?.text ?? "";
	assert(
		/showing 1 of \d+ total matching/.test(text),
		`expected a total-vs-shown truncation note: ${text.slice(0, 300)}`,
	);
});

console.log("\n## Tool: get_campaign");

await test("get_campaign for a real key returns evidence + members + export links", async () => {
	const list = await rpc("tools/call", { name: "get_campaigns", arguments: { limit: 1 } });
	const listText = list.body.result?.content?.[0]?.text ?? "";
	// Campaigns are addressed by their STABLE KEY (hex), not by the numeric
	// cluster id, which the correlation builder reissues on every daily
	// rebuild - a numeric id scraped today stops resolving tomorrow.
	const m = listText.match(/#([a-f0-9]{6,40})\b/);
	assert(m, `get_campaigns returned no campaign key to test get_campaign against: ${listText.slice(0, 200)}`);
	const key = m[1];

	const r = await rpc("tools/call", { name: "get_campaign", arguments: { campaign_id: key } });
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const text = r.body.result.content[0].text;
	assert(text.includes(`Campaign #${key}`), `missing campaign key header: ${text.slice(0, 200)}`);
	assert(text.includes(`/campaigns/${key}/export`), `export links should use the stable key: ${text.slice(0, 400)}`);
	assert(/ACTIVE|INACTIVE/.test(text), `missing ACTIVE/INACTIVE marker: ${text.slice(0, 200)}`);
	assert(/export\?format=json/.test(text), `missing export links: ${text.slice(0, 300)}`);
	assert(!/\bactor\b|\bgroup\b|\boperator\b/i.test(stripRegistrarLines(text)), `should never use actor/group/operator language: ${text.slice(0, 300)}`);
});

await test("get_campaign result carries structuredContent (batch 4) with no deprecated numeric id", async () => {
	const list = await rpc("tools/call", { name: "get_campaigns", arguments: { limit: 1 } });
	const listText = list.body.result?.content?.[0]?.text ?? "";
	const m = listText.match(/#([a-f0-9]{6,40})\b/);
	assert(m, `get_campaigns returned no campaign key to test get_campaign against: ${listText.slice(0, 200)}`);
	const key = m[1];

	const r = await rpc("tools/call", { name: "get_campaign", arguments: { campaign_id: key } });
	assert(r.body.result?.content, `no content: ${JSON.stringify(r.body)}`);
	const sc = r.body.result.structuredContent;
	assert(sc && typeof sc === "object", `expected structuredContent object: ${JSON.stringify(r.body.result).slice(0, 300)}`);
	assert(sc.key === key, `structuredContent.key mismatch: expected ${key}, got ${sc.key}`);
	assert(Array.isArray(sc.members), "structuredContent missing members[]");
	// `state` is a phishunt-web batch-3 field this tool passes through
	// as-is - tolerate it being absent (pre-deploy prod shape) but never
	// anything other than one of the two documented values when present.
	assert(sc.state === undefined || sc.state === "live" || sc.state === "archived", `unexpected state: ${sc.state}`);
	// This IS fully testable pre-deploy: the underlying HTTP API has always
	// emitted a numeric `id` (long predating `key`), and this server strips
	// it before it ever reaches structuredContent (batch 4 identity policy)
	// - `key` is the only identity this server's output carries.
	assert(!("id" in sc), `structuredContent must not carry the deprecated numeric id: ${JSON.stringify(sc).slice(0, 200)}`);
});

await test("get_campaign for unknown id returns INVALID_PARAMS with a get_campaigns pointer", async () => {
	const r = await rpc("tools/call", {
		name: "get_campaign",
		arguments: { campaign_id: 999999999 },
	});
	assert(r.body.error, `expected error, got: ${JSON.stringify(r.body.result)}`);
	assert(r.body.error.code === -32602, `expected -32602, got ${r.body.error.code}`);
	assert(/get_campaigns/.test(r.body.error.message), `expected pointer to get_campaigns: ${r.body.error.message}`);
});

await test("get_campaign requires 'campaign_id' param", async () => {
	const r = await rpc("tools/call", { name: "get_campaign", arguments: {} });
	assert(r.body.error, "expected error for missing campaign_id");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
});

await test("get_campaign rejects a non-numeric campaign_id", async () => {
	const r = await rpc("tools/call", {
		name: "get_campaign",
		arguments: { campaign_id: "not-a-number" },
	});
	assert(r.body.error, "expected error for non-numeric campaign_id");
	assert(r.body.error.code === -32602, `expected INVALID_PARAMS, got ${r.body.error.code}`);
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
