import assert from 'node:assert/strict';
import test from 'node:test';
import { frameworkMigrations, resolveCiscoReference } from '../framework-migrations.js';
import { buildThreatQueryPlan } from '../webmcp-query.js';
import { ciscoFramework } from '../cisco-framework.js';

test('Cisco resolver publishes one current taxonomy and conflict-only historical metadata', () => {
    const catalog = frameworkMigrations.frameworks.cisco;
    assert.equal(catalog.activeEdition, '2.0.0');
    assert.equal(catalog.activeLabel, 'Cisco Integrated AI Security and Safety Framework');
    assert.deepEqual(catalog.activeItems, ciscoFramework.activeItems);
    assert.equal(catalog.activeItems.length, 156);
    assert.deepEqual(catalog.migrations, []);
    assert.equal(catalog.historicalItems.filter(x => x.status === 'retired').length, 11);
});

test('every current Cisco ID and complete name resolves with explicit edition metadata', () => {
    for (const item of ciscoFramework.activeItems) {
        for (const query of [item.id, 'Cisco v2 '+item.id, item.id+':2.0.0', item.id+' '+item.name, 'Cisco '+item.name]) {
            const result=resolveCiscoReference(query);
            if (query === 'Cisco '+item.name && ciscoFramework.activeItems.filter(x=>x.name===item.name).length > 1) {
                assert.equal(result.status,'ambiguous',query);
                assert.deepEqual(buildThreatQueryPlan(query).queries,[],query);
                continue;
            }
            assert.ok(result.canonical, query + ': ' + JSON.stringify(result));
            assert.equal(result.canonical.id, item.id, query);
            assert.equal(result.canonical.edition, '2.0.0', query);
            assert.deepEqual(buildThreatQueryPlan(query).queries, [item.id], query);
        }
    }
});

test('Cisco retired, legacy, malformed and conflicting input cannot reach generic lookup', () => {
    const cases = [
        ['Cisco v1 AITech-2.1', 'unsupported_edition'],
        ['AITech-2.1:v1.0.0', 'unsupported_edition'],
        ['Cisco version 1 AITech-2.1', 'unsupported_edition'],
        ['AITech-1.4', 'retired_identifier'],
        ['AISubtech-1.2.1', 'retired_identifier'],
        ['AITech-2.1 Jailbreak', 'id_name_conflict'],
        ['AITech-1.3 Goal Manipulation', 'id_name_conflict'],
        ['AISubtech-15.1.25 Privacy Attacks: PII / PHI / PCI', 'id_name_conflict'],
        ['AITech-2.1 Goal Drift', 'id_name_conflict'],
        ['Cisco Goal Manipulation', 'legacy_name_unsupported'],
        ['AITech-2.1:2.0.0x', 'malformed_or_unsupported_edition'],
        ['Cisco v2.0.0x AITech-2.1', 'malformed_or_unsupported_edition'],
        ['AITech-2.1:', 'malformed_identifier'],
        ['AITech-2.1.9', 'malformed_identifier'],
        ['AISubtech-2.1', 'malformed_identifier'],
        ['AITech-02.1', 'malformed_identifier'],
        ['AITech-2.1foo', 'malformed_identifier'],
        ['AITech2.1', 'malformed_identifier'],
        ['AITech-999.1', 'unknown_identifier'],
        ['Cisco v3 AITech-2.1', 'malformed_or_unsupported_edition'],
        ['AITech-2.1 LLM03:2026', 'mixed_frameworks'],
    ];
    for (const [query,code] of cases) {
        const result=resolveCiscoReference(query);
        assert.equal(result.status,'invalid',query);
        assert.equal(result.reasonCode,code,query);
        assert.equal(result.canonical,undefined,query);
        assert.deepEqual(buildThreatQueryPlan(query).queries,[],query);
    }
    for (const old of frameworkMigrations.frameworks.cisco.historicalItems.filter(x=>x.status==='retired')) {
        assert.equal(resolveCiscoReference(old.id).reasonCode,'retired_identifier');
    }
});

test('multiple Cisco identifiers produce candidates but no lookup', () => {
    for (const query of ['AITech-2.1 AITech-2.2', 'AITech-2.1/AISubtech-2.1.1', 'Cisco AITech-1.4; AITech-2.1']) {
        assert.equal(resolveCiscoReference(query).status,'ambiguous',query);
        assert.deepEqual(buildThreatQueryPlan(query).queries,[],query);
    }
    assert.equal(resolveCiscoReference('AML.T0051'),null);
    assert.equal(resolveCiscoReference('LLM01:2026'),null);
    assert.deepEqual(buildThreatQueryPlan('AML.T0051').queries,['AML.T0051']);
});
