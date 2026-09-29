const TECHNIQUE = /^AID-(?:M|H|D|I|DV|E|R)-\d{3}(?:\.\d{3})?$/;
const GUIDANCE = /^AID-(?:M|H|D|I|DV|E|R)-\d{3}(?:\.\d{3})?-G\d{3}$/;
const ATLAS = /^AML\.T\d{4}(?:\.\d{3})?$/;

export function techniquePath(id, guidanceId = null, base = '/') {
    if (!TECHNIQUE.test(id)) throw new Error('Invalid technique ID');
    if (guidanceId && (!GUIDANCE.test(guidanceId) || !guidanceId.startsWith(id + '-G'))) {
        throw new Error('Guidance does not belong to this technique');
    }
    return base.replace(/\/?$/, '/') + 'techniques/' + id + '/' + (guidanceId ? '#' + guidanceId : '');
}

// Legacy hash links continue to work. A native fragment selects a guidance
// inside the full technique HTML; it never changes the HTTP response body.
export function readSiteRoute(location) {
    const hash = location.hash.slice(1);
    const params = new URLSearchParams(hash);
    const atlasId = params.get('atlas');
    // URLSearchParams already decodes the fragment once. Reject malformed IDs
    // before they can reach the ATLAS modal or be decoded a second time.
    if (atlasId && ATLAS.test(atlasId)) return { atlasId };
    const legacy = params.get('t');
    const pathId = location.pathname.match(/\/techniques\/(AID-[A-Z]+-\d{3}(?:\.\d{3})?)(?:\/|\/index\.html)?$/)?.[1];
    const techniqueId = legacy || pathId;
    if (!TECHNIQUE.test(techniqueId || '')) return {};
    const candidate = legacy ? params.get('g') : hash;
    const guidanceId = GUIDANCE.test(candidate || '') && candidate.startsWith(techniqueId + '-G') ? candidate : null;
    return { techniqueId, guidanceId };
}

// Code blocks are literal examples, even if an authored '<' was not already
// encoded. Keep existing entities intact and let the HTML parser decode once.
export function protectCodeBlocks(html) {
    return String(html ?? '').replace(/(<pre><code(?:\s[^>]*)?>)([\s\S]*?)(<\/code><\/pre>)/gi,
        (_, open, code, close) => open + code.replaceAll('<', '&lt;').replaceAll('>', '&gt;') + close);
}
