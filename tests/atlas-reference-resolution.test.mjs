import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { frameworkMigrations, resolveAtlasReference } from '../framework-migrations.js';
import { buildThreatQueryPlan } from '../webmcp-query.js';
import { aidefendVersion } from '../aidefend-intro.js';

test('every current ATLAS identifier resolves to its own current concept', () => {
    const catalog = frameworkMigrations.frameworks.atlas;
    assert.equal(catalog.activeItems.length, 221);
    for (const item of catalog.activeItems) {
        const result = resolveAtlasReference(`${item.id} ${item.name}`);
        assert.equal(result.status, 'canonical', item.id);
        assert.equal(result.canonical.id, item.id);
        assert.equal(result.canonical.edition, '2026.10');
    }
});

test('retired ATLAS IDs select semantic successors without searching obsolete text', () => {
    for (const [from,to] of [
        ['AML.T0024.001','AML.T0137.002'],
        ['AML.T0024.002','AML.T0005.001'],
        ['AML.T0056','AML.T0085.003']
    ]) {
        const plan = buildThreatQueryPlan(from);
        assert.equal(plan.resolution.status, 'migrated');
        assert.equal(plan.resolution.mappingCarryForward, 'requires-semantic-review');
        assert.deepEqual(plan.queries, [to]);
    }
    for (const id of ['AML.T0024.000','AML.T0057']) {
        const plan = buildThreatQueryPlan(id);
        assert.equal(plan.resolution.status, 'ambiguous');
        assert.equal(plan.resolution.reasonCode, 'split_concept');
        assert.ok(plan.resolution.candidates.length > 1);
        assert.deepEqual(plan.queries, []);
    }
});

test('malformed, conflicting, unknown and mixed ATLAS input never falls back to keywords', () => {
    for (const input of [
        'AML.T9999', 'AML.T0144.99', 'AML.T0144 Wrong name',
        'ATLAS 2026.09 AML.T0144', 'AML.T0144 LLM01:2026',
        'AML.T0144 AITech-1.1', 'AML.T0024.001 AML.T0057'
    ]) {
        assert.deepEqual(buildThreatQueryPlan(input).queries, [], input);
    }
    assert.equal(resolveAtlasReference('generic prompt injection'), null);
});

test('public README badge and current-version text match the authored release', () => {
    const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url)));
    const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
    assert.equal(packageJson.version, aidefendVersion);
    assert.ok(readme.includes(`badge/version-${packageJson.version}-`));
    assert.ok(readme.includes('Version `'+packageJson.version+'` provides:'));
});

test('ATLAS prose and tactic references preserve generic keyword lookup', () => {
    for (const query of ['ATLAS reconnaissance', 'AML.TA0001', 'MITRE ATLAS tactics']) {
        const plan = buildThreatQueryPlan(query);
        assert.deepEqual(plan.queries, [query]);
        assert.equal(plan.canonicalThreatId, null);
    }
});
