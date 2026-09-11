import { resolveOwaspLlmReference, resolveCiscoReference } from './framework-migrations.js';

/**
 * Resolve edition-aware Cisco and OWASP LLM references before lookup.
 * Cisco queries use only the resolved current canonical ID; obsolete, conflicting
 * or malformed references cannot fall through to descriptive keyword matches.
 * OWASP retains its existing canonical migration sequence. Other framework input
 * keeps the original query for generic cross-framework lookup.
 */
export function buildThreatQueryPlan(rawThreat) {
    const threat = String(rawThreat || '').trim();
    const ciscoResolution = resolveCiscoReference(threat);
    const resolution = ciscoResolution || resolveOwaspLlmReference(threat);
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
    const queries = ciscoResolution ? [] : [threat];
    if (canonicalThreatId && (ciscoResolution || canonicalThreatId.toLowerCase() !== threat.toLowerCase())) {
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
