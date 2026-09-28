// Contract check for the `probability` block of GET /api/v1/analyze (and
// /analyze/deep), as documented in the analyze_url / analyze_url_deep tool
// descriptions. Pure functions, no network: test.mjs uses them both on fixtures
// (offline unit tests) and on the live analyze_url response (prod tests).

// [band, lower bound, upper bound] as fractions; edges are inclusive on both
// sides here because the backend's rounding decides which side an exact edge
// value lands on, and the test only needs to catch a wrong band, not an
// off-by-one-ulp one.
export const PROBABILITY_BANDS = [
	["very_unlikely", 0, 0.05],
	["unlikely", 0.05, 0.3],
	["uncertain", 0.3, 0.7],
	["likely", 0.7, 0.95],
	["very_likely", 0.95, 1],
];

export const PASSIVE_COVERAGE = ["passive_url_only", "known_record"];
export const ACTIVE_COVERAGE = ["active_no_render", "active_rendered"];
export const ALL_COVERAGE = [...PASSIVE_COVERAGE, ...ACTIVE_COVERAGE];
export const EVIDENCE_DIRECTIONS = ["toward_malicious", "toward_benign", "neutral"];

const isNum = (x) => typeof x === "number" && Number.isFinite(x);

// Returns a list of human-readable problems; empty means the block matches the
// documented contract. status "unavailable" only has to carry the status.
export function probabilityProblems(p, { coverage = ALL_COVERAGE } = {}) {
	const out = [];
	if (!p || typeof p !== "object" || Array.isArray(p)) return ["probability is not an object"];
	if (p.status !== "ok" && p.status !== "unavailable") {
		out.push(`status must be "ok" or "unavailable", got ${JSON.stringify(p.status)}`);
	}
	if (p.status !== "ok") return out;

	if (!isNum(p.p_malicious) || p.p_malicious < 0 || p.p_malicious > 1) {
		out.push(`p_malicious must be a number in [0,1], got ${JSON.stringify(p.p_malicious)}`);
	} else if (Math.abs(p.p_malicious * 1000 - Math.round(p.p_malicious * 1000)) > 1e-6) {
		out.push(`p_malicious must have at most 3 decimals, got ${p.p_malicious}`);
	}
	if (!Number.isInteger(p.percent) || p.percent < 0 || p.percent > 100) {
		out.push(`percent must be an integer in [0,100], got ${JSON.stringify(p.percent)}`);
	} else if (isNum(p.p_malicious) && Math.abs(p.percent - p.p_malicious * 100) > 1) {
		out.push(`percent ${p.percent} does not match p_malicious ${p.p_malicious}`);
	}
	const iv = p.interval_80;
	if (!Array.isArray(iv) || iv.length !== 2 || !iv.every(isNum)) {
		out.push(`interval_80 must be [lo, hi] numbers, got ${JSON.stringify(iv)}`);
	} else if (iv[0] < 0 || iv[1] > 1 || iv[0] > iv[1]) {
		out.push(`interval_80 must satisfy 0 <= lo <= hi <= 1, got ${JSON.stringify(iv)}`);
	}
	const band = PROBABILITY_BANDS.find(([name]) => name === p.band);
	if (!band) {
		out.push(`band must be one of ${PROBABILITY_BANDS.map((b) => b[0]).join("|")}, got ${JSON.stringify(p.band)}`);
	} else if (isNum(p.p_malicious) && (p.p_malicious < band[1] || p.p_malicious > band[2])) {
		out.push(`band ${p.band} does not contain p_malicious ${p.p_malicious}`);
	}
	if (!isNum(p.relative_risk) || p.relative_risk < 0) {
		out.push(`relative_risk must be a number >= 0, got ${JSON.stringify(p.relative_risk)}`);
	}
	if (!coverage.includes(p.coverage)) {
		out.push(`coverage must be one of ${coverage.join("|")}, got ${JSON.stringify(p.coverage)}`);
	}
	if (!isNum(p.prior) || p.prior <= 0 || p.prior > 0.1) {
		out.push(`prior must be a number in (0, 0.1] (documented ~0.013), got ${JSON.stringify(p.prior)}`);
	}
	if (!Array.isArray(p.evidence)) {
		out.push("evidence must be an array");
	} else {
		p.evidence.forEach((e, i) => {
			if (!e || typeof e !== "object") return out.push(`evidence[${i}] is not an object`);
			if (typeof e.class !== "string" || !e.class) out.push(`evidence[${i}].class must be a non-empty string`);
			if (!("value" in e)) out.push(`evidence[${i}].value is missing`);
			if (!isNum(e.llr)) out.push(`evidence[${i}].llr must be a number, got ${JSON.stringify(e.llr)}`);
			if (!EVIDENCE_DIRECTIONS.includes(e.direction)) {
				out.push(`evidence[${i}].direction must be one of ${EVIDENCE_DIRECTIONS.join("|")}, got ${JSON.stringify(e.direction)}`);
			}
		});
	}
	if (!Array.isArray(p.not_evaluated) || !p.not_evaluated.every((c) => typeof c === "string")) {
		out.push("not_evaluated must be an array of class names");
	}
	if (typeof p.model_version !== "string" || !p.model_version) out.push("model_version must be a non-empty string");
	if (typeof p.note !== "string" || !p.note) out.push("note must be a non-empty string");
	return out;
}
