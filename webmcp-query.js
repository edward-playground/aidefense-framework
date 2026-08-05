import { resolveOwaspLlmReference } from './framework-migrations.js';

/**
 * Build the exact lookup sequence for a WebMCP threat query. Non-OWASP input
 * keeps the original query so generic cross-framework lookup still works.
 * Recognized OWASP LLM input adds its current canonical identifier after a
 * successful resolution, but malformed or ambiguous OWASP input fails closed
 * with no lookup queries so a rank is never guessed.
 */
export function buildThreatQueryPlan(rawThreat) {
    const threat = String(rawThreat || '').trim();
    const resolution = resolveOwaspLlmReference(threat);
    if (resolution?.status === 'invalid' || resolution?.status === 'ambiguous') {
        return {
            threat,
            resolution,
            canonicalThreat: null,
            canonicalThreatId: null,
            queries: []
        };
    }
    const canonicalThreatId = resolution?.canonical?.id || null;
    const canonicalThreat = resolution?.canonical?.label || null;
    const queries = [threat];
    if (canonicalThreatId && canonicalThreatId.toLowerCase() !== threat.toLowerCase()) {
        queries.push(canonicalThreatId);
    }
    return {
        threat,
        resolution,
        canonicalThreat,
        canonicalThreatId,
        queries: [...new Set(queries)]
    };
}

/**
 * Merge query-hit sets without losing a control's framework-specific matches.
 * Exact canonical-ID hits sort ahead of prefix and keyword hits before result
 * limits are applied.
 */
export function mergeThreatHits(...hitSets) {
    const merged = new Map();
    for (const hit of hitSets.flat()) {
        const key = `${hit.id}|${hit.matchedFramework}`;
        const existing = merged.get(key);
        if (!existing) {
            merged.set(key, { ...hit, matchedItems: [...hit.matchedItems] });
            continue;
        }
        existing.matchedItems = [...new Set([...existing.matchedItems, ...hit.matchedItems])];
        existing._tier = Math.min(existing._tier, hit._tier);
    }
    return [...merged.values()].sort((left, right) => left._tier - right._tier);
}
