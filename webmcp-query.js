import { resolveOwaspLlmReference, resolveCiscoReference, resolveAtlasReference } from './framework-migrations.js';

/**
 * Resolve edition-aware ATLAS, Cisco and OWASP LLM references before lookup.
 * Cisco queries use only the resolved current canonical ID; obsolete, conflicting
 * or malformed references cannot fall through to descriptive keyword matches.
 * OWASP retains its existing canonical migration sequence. Other framework input
 * keeps the original query for generic cross-framework lookup.
 */
export function buildThreatQueryPlan(rawThreat) {
    const threat = String(rawThreat || '').trim();
    const ciscoResolution = resolveCiscoReference(threat);
    const techniqueIntent = /\bAML\.T(?!A)\S*|\bATLAS\s+(?:(?:v|version\s+|edition\s+)?20\d{2}\.\d{2}\s+)?T\d/i.test(threat);
    const atlasResolution = techniqueIntent ? resolveAtlasReference(threat) : null;
    const resolution = atlasResolution || ciscoResolution || resolveOwaspLlmReference(threat);
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
    const strictReference = Boolean(ciscoResolution || atlasResolution);
    const queries = strictReference ? [] : [threat];
    if (canonicalThreatId && (strictReference || canonicalThreatId.toLowerCase() !== threat.toLowerCase())) {
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
