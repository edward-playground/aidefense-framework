import assert from 'node:assert/strict';
import test from 'node:test';
import { aidefendData } from '../main.js';
import { techniquePath, readSiteRoute } from '../js/technique-page.js';

test('source-preview links load the application root with the control and guidance', () => {
    const id = 'AID-I-003.002';
    const guidanceId = id + '-G001';
    const options = { staticPages: false };
    assert.equal(techniquePath(id, null, '/', options), '/#t=AID-I-003.002');
    assert.equal(techniquePath(id, guidanceId, '/', options), '/#t=AID-I-003.002&g=AID-I-003.002-G001');
    assert.equal(techniquePath(id, null, '/preview', options), '/preview/#t=AID-I-003.002');
    assert.throws(() => techniquePath('../private', null, '/', options));
    assert.throws(() => techniquePath(id, 'AID-H-001-G001', '/', options));
});

test('every control and guidance round-trips through source and generated-page links', () => {
    const entries = aidefendData.tactics.flatMap(t => t.techniques.flatMap(entry => [entry, ...(entry.subTechniques || [])]));
    for (const entry of entries) {
        for (const staticPages of [false, true]) {
            for (const base of ['/', '/aidefense-framework/']) {
                const options = { staticPages };
                const path = techniquePath(entry.id, null, base, options);
                const url = new URL(path, 'https://aidefend.net');
                assert.equal(url.pathname, staticPages ? base + 'techniques/' + entry.id + '/' : base);
                assert.deepEqual(readSiteRoute(url), { techniqueId: entry.id, guidanceId: null });
                for (const guidance of entry.implementationGuidance || []) {
                    const guidanceUrl = new URL(techniquePath(entry.id, guidance.id, base, options), url);
                    assert.deepEqual(readSiteRoute(guidanceUrl), { techniqueId: entry.id, guidanceId: guidance.id });
                }
            }
        }
    }
});
