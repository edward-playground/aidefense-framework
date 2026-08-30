import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { aidefendData } from '../main.js';
import {
    frameworkMigrations,
    resolveOwaspLlmReference
} from '../framework-migrations.js';
import { buildThreatQueryPlan, mergeThreatHits } from '../webmcp-query.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = frameworkMigrations.frameworks.owasp_llm;
const activeLabels = new Map(
    catalog.activeItems.map(item => [item.id, `${item.id} ${item.name}`])
);

function allEntities() {
    return aidefendData.tactics.flatMap(tactic =>
        tactic.techniques.flatMap(technique => [
            technique,
            ...(technique.subTechniques || [])
        ])
    );
}

function entityById(id) {
    const entity = allEntities().find(item => item.id === id);
    assert.ok(entity, `missing framework entity ${id}`);
    return entity;
}

test('OWASP LLM registry has one complete current catalog and a one-to-one legacy migration', () => {
    assert.equal(frameworkMigrations.registryVersion, '2026-08-05');
    assert.equal(catalog.activeEdition, '2026');
    assert.equal(catalog.activeLabel, 'OWASP LLM Top 10 2026');
    assert.equal(catalog.sourceArtifact.fileName, 'OWASP-GenAI-LLM-Top-10-2026-v1.0.pdf');
    assert.equal(catalog.sourceArtifact.bytes, 2402520);
    assert.equal(catalog.sourceArtifact.pageCount, 122);
    assert.equal(catalog.sourceArtifact.sha256, 'EF87993A4E50AE9D83B41FF7A3D3E6320A82DFA8D4EC6BF98D0CE264B2E6108E');
    assert.equal(catalog.sourceArtifact.publicationDate, null);
    assert.equal(catalog.sourceLicense.spdxExpression, 'CC-BY-SA-4.0');
    assert.equal(catalog.activeItems.length, 10);
    assert.equal(new Set(catalog.activeItems.map(item => item.id)).size, 10);
    assert.deepEqual(
        catalog.activeItems.map(item => item.id),
        Array.from({ length: 10 }, (_, index) => `LLM${String(index + 1).padStart(2, '0')}:2026`)
    );

    assert.equal(catalog.migrations.length, 10);
    assert.equal(new Set(catalog.migrations.map(item => item.from.id)).size, 10);
    assert.equal(new Set(catalog.migrations.map(item => item.to.id)).size, 10);
    for (const migration of catalog.migrations) {
        assert.equal(migration.mappingCarryForward, 'requires-semantic-review');
        assert.ok(activeLabels.has(migration.to.id));
        assert.equal(activeLabels.get(migration.to.id), `${migration.to.id} ${migration.to.name}`);
    }
});

test('legacy IDs migrate by risk concept rather than by rank', () => {
    const expected = new Map([
        ['LLM01:2025', 'LLM01:2026'],
        ['LLM02:2025', 'LLM02:2026'],
        ['LLM03:2025', 'LLM04:2026'],
        ['LLM04:2025', 'LLM05:2026'],
        ['LLM05:2025', 'LLM10:2026'],
        ['LLM06:2025', 'LLM03:2026'],
        ['LLM07:2025', 'LLM08:2026'],
        ['LLM08:2025', 'LLM09:2026'],
        ['LLM09:2025', 'LLM07:2026'],
        ['LLM10:2025', 'LLM06:2026']
    ]);

    for (const [legacyId, currentId] of expected) {
        const resolution = resolveOwaspLlmReference(legacyId);
        assert.equal(resolution.status, 'migrated');
        assert.equal(resolution.migratedFrom.id, legacyId);
        assert.equal(resolution.canonical.id, currentId);
    }
});

test('every current and superseded risk name resolves to the declared current concept', () => {
    for (const item of catalog.activeItems) {
        const resolution = resolveOwaspLlmReference(item.name);
        assert.equal(resolution.status, 'normalized');
        assert.equal(resolution.canonical.id, item.id);
    }

    for (const migration of catalog.migrations) {
        const resolution = resolveOwaspLlmReference(migration.from.name);
        const nameUnchanged = migration.from.name === migration.to.name;
        assert.equal(resolution.status, nameUnchanged ? 'normalized' : 'migrated');
        assert.equal(resolution.canonical.id, migration.to.id);

        for (const frameworkLabel of [
            'OWASP LLM Top 10 2025',
            'OWASP Top 10 for LLM Applications 2025'
        ]) {
            const historical = resolveOwaspLlmReference(`${frameworkLabel} ${migration.from.name}`);
            assert.equal(historical.status, 'migrated', `${frameworkLabel} ${migration.from.name}`);
            assert.equal(historical.migratedFrom.id, migration.from.id);
            assert.equal(historical.canonical.id, migration.to.id);
        }

        const current = resolveOwaspLlmReference(`OWASP LLM Top 10 2026 ${migration.to.name}`);
        assert.equal(current.status, 'normalized');
        assert.equal(current.canonical.id, migration.to.id);
    }
});

test('current, bare, legacy-name, and rank-name-conflict queries resolve deterministically', () => {
    assert.equal(resolveOwaspLlmReference('LLM03:2026').status, 'canonical');
    assert.equal(resolveOwaspLlmReference('LLM03:2026').canonical.name, 'Excessive Agency');

    const bare = resolveOwaspLlmReference('LLM03');
    assert.equal(bare.status, 'fallback_latest');
    assert.equal(bare.canonical.id, 'LLM03:2026');

    const nonPaddedBare = resolveOwaspLlmReference('LLM3 latest');
    assert.equal(nonPaddedBare.status, 'fallback_latest');
    assert.equal(nonPaddedBare.canonical.id, 'LLM03:2026');

    const explicitLatest = resolveOwaspLlmReference('LLM03:latest');
    assert.equal(explicitLatest.status, 'fallback_latest');
    assert.equal(explicitLatest.canonical.id, 'LLM03:2026');

    for (const contextualLegacy of [
        'OWASP LLM Top 10 2025 LLM03',
        'OWASP Top 10 for LLM Applications 2025 LLM03',
        'LLM03 OWASP 2025',
        'LLM03 2025',
        '2025 / LLM03'
    ]) {
        const resolution = resolveOwaspLlmReference(contextualLegacy);
        assert.equal(resolution.status, 'migrated', contextualLegacy);
        assert.equal(resolution.canonical.id, 'LLM04:2026', contextualLegacy);
    }

    const contextualCurrent = resolveOwaspLlmReference('OWASP LLM Top 10 (2026) LLM03');
    assert.equal(contextualCurrent.status, 'canonical');
    assert.equal(contextualCurrent.canonical.id, 'LLM03:2026');

    const contextualCurrentLatest = resolveOwaspLlmReference('OWASP LLM Top 10 2026 LLM03:latest');
    assert.equal(contextualCurrentLatest.status, 'fallback_latest');
    assert.equal(contextualCurrentLatest.canonical.id, 'LLM03:2026');

    const contextualLegacyLatest = resolveOwaspLlmReference('OWASP LLM Top 10 2025 LLM03:latest');
    assert.equal(contextualLegacyLatest.status, 'invalid');
    assert.equal('canonical' in contextualLegacyLatest, false);

    const legacyName = resolveOwaspLlmReference('System Prompt Leakage');
    assert.equal(legacyName.status, 'migrated');
    assert.equal(legacyName.canonical.id, 'LLM08:2026');

    const conflict = resolveOwaspLlmReference('LLM03 Supply Chain');
    assert.equal(conflict.status, 'normalized');
    assert.equal(conflict.canonical.id, 'LLM04:2026');
    assert.match(conflict.reason, /conflict/i);

    const versionedConflict = resolveOwaspLlmReference('LLM03:2026 Supply Chain');
    assert.equal(versionedConflict.status, 'normalized');
    assert.equal(versionedConflict.canonical.id, 'LLM04:2026');
    assert.equal(versionedConflict.inputNameConflict.resolvedBy, 'recognized-risk-name');

    const legacyVersionedConflict = resolveOwaspLlmReference('LLM03:2025 Excessive Agency');
    assert.equal(legacyVersionedConflict.status, 'normalized');
    assert.equal(legacyVersionedConflict.canonical.id, 'LLM03:2026');
    assert.equal(legacyVersionedConflict.inputNameConflict.resolvedBy, 'recognized-risk-name');

    for (const malformed of [
        'LLM03:',
        'LLM03:foo',
        'LLM03:20X5',
        'LLM03:2025x',
        'LLM03:20250',
        'LLM0003:2026',
        'LLM03:2026.5',
        'LLM03:2026+LLM04:2026',
        'OWASP LLM 20250 LLM03',
        'OWASP LLM 2025x LLM03',
        'OWASP LLM 2025.1 LLM03',
        'OWASP LLM 20X5 LLM03',
        'OWASP LLM 2025 latest LLM03',
        'LLM03 2025 2026',
        'OWASP LLM Top 10 2025 LLM03:2026',
        'OWASP LLM Top 10 2027 LLM03',
        'LLM11:2026'
    ]) {
        const resolution = resolveOwaspLlmReference(malformed);
        assert.equal(resolution.status, 'invalid', malformed);
        assert.equal('canonical' in resolution, false, malformed);
    }

    const multipleIds = resolveOwaspLlmReference('LLM03:2025 / LLM06:2025');
    assert.equal(multipleIds.status, 'ambiguous');
    assert.deepEqual(
        multipleIds.candidates.map(candidate => candidate.id).sort(),
        ['LLM03:2026', 'LLM04:2026']
    );

    for (const separated of [
        'LLM03:2026&LLM04:2026',
        'LLM03:2026? LLM04:2026',
        'LLM03:2026.LLM04:2026',
        'LLM03? / LLM04'
    ]) {
        const resolution = resolveOwaspLlmReference(separated);
        assert.equal(resolution.status, 'ambiguous', separated);
        assert.deepEqual(
            resolution.candidates.map(candidate => candidate.id),
            ['LLM03:2026', 'LLM04:2026'],
            separated
        );
    }

    const multipleNames = resolveOwaspLlmReference('OWASP LLM Excessive Agency and Supply Chain');
    assert.equal(multipleNames.status, 'ambiguous');
    assert.deepEqual(
        multipleNames.candidates.map(candidate => candidate.id).sort(),
        ['LLM03:2026', 'LLM04:2026']
    );

    const sameConceptAliases = resolveOwaspLlmReference('LLM03:2025 / LLM04:2026 Supply Chain');
    assert.equal(sameConceptAliases.canonical.id, 'LLM04:2026');
    assert.deepEqual(sameConceptAliases.coResolvedReferences, ['LLM03:2025', 'LLM04:2026']);

    assert.equal(resolveOwaspLlmReference('AML.T0051'), null);
    assert.equal(resolveOwaspLlmReference('AML.T0051 LLM Prompt Injection'), null);
    assert.equal(resolveOwaspLlmReference('Supply Chain Attacks (Cross-Layer)'), null);

    const contextualFrom = resolveOwaspLlmReference('LLM03 from 2025');
    assert.equal(contextualFrom.status, 'migrated');
    assert.equal(contextualFrom.canonical.id, 'LLM04:2026');

    const crossFrameworkRemainder = resolveOwaspLlmReference(
        'LLM03 MAESTRO Supply Chain Attacks (Cross-Layer)'
    );
    assert.equal(crossFrameworkRemainder.canonical.id, 'LLM03:2026');

    const currentAndLegacyNames = resolveOwaspLlmReference(
        'OWASP LLM Prompt Injection System Prompt Leakage'
    );
    assert.equal(currentAndLegacyNames.status, 'ambiguous');
    assert.deepEqual(
        currentAndLegacyNames.candidates.map(candidate => candidate.id),
        ['LLM01:2026', 'LLM08:2026']
    );

    const wrongEditionName = resolveOwaspLlmReference(
        'OWASP LLM Hidden Context Exposure 2025'
    );
    assert.equal(wrongEditionName.status, 'invalid');

    const malformedPrefixedId = resolveOwaspLlmReference('_LLM03:2026 / LLM04:2026');
    assert.equal(malformedPrefixedId.status, 'invalid');
});

test('WebMCP query planning preserves generic lookup and prioritizes canonical migration hits', () => {
    const migrated = buildThreatQueryPlan('LLM03:2025');
    assert.equal(migrated.resolution.status, 'migrated');
    assert.equal(migrated.canonicalThreat, 'LLM04:2026 Supply Chain');
    assert.equal(migrated.canonicalThreatId, 'LLM04:2026');
    assert.deepEqual(migrated.queries, ['LLM03:2025', 'LLM04:2026']);

    const current = buildThreatQueryPlan('LLM04:2026');
    assert.deepEqual(current.queries, ['LLM04:2026']);

    const invalid = buildThreatQueryPlan('LLM03:2025x');
    assert.equal(invalid.resolution.status, 'invalid');
    assert.deepEqual(invalid.queries, []);
    assert.equal(invalid.canonicalThreat, null);

    const ambiguous = buildThreatQueryPlan('OWASP LLM Excessive Agency and Supply Chain');
    assert.equal(ambiguous.resolution.status, 'ambiguous');
    assert.deepEqual(ambiguous.queries, []);
    assert.equal(ambiguous.canonicalThreat, null);

    const unknownOwasp = buildThreatQueryPlan('OWASP LLM Top 10 2026 Unknown Risk');
    assert.equal(unknownOwasp.resolution.status, 'invalid');
    assert.deepEqual(unknownOwasp.queries, []);
    assert.equal(unknownOwasp.canonicalThreat, null);

    const nonOwasp = buildThreatQueryPlan('AML.T0051');
    assert.equal(nonOwasp.resolution, null);
    assert.deepEqual(nonOwasp.queries, ['AML.T0051']);

    const merged = mergeThreatHits(
        [
            { id: 'AID-X-001', matchedFramework: 'Example', matchedItems: ['keyword'], _tier: 3 },
            { id: 'AID-X-002', matchedFramework: 'Example', matchedItems: ['other'], _tier: 3 }
        ],
        [
            { id: 'AID-X-001', matchedFramework: 'Example', matchedItems: ['canonical'], _tier: 1 }
        ]
    );
    assert.deepEqual(merged.map(hit => [hit.id, hit._tier]), [
        ['AID-X-001', 1],
        ['AID-X-002', 3]
    ]);
    assert.deepEqual(merged[0].matchedItems, ['keyword', 'canonical']);
});

test('every active framework entity uses only canonical OWASP LLM 2026 items', () => {
    const entities = allEntities();
    assert.equal(entities.length, 365);

    for (const entity of entities) {
        const current = entity.defendsAgainst.filter(
            mapping => mapping.framework === catalog.activeLabel
        );
        const legacy = entity.defendsAgainst.filter(
            mapping => mapping.framework === 'OWASP LLM Top 10 2025'
        );
        assert.equal(legacy.length, 0, `${entity.id} still exposes the legacy framework label`);
        assert.equal(current.length, 1, `${entity.id} must contain exactly one current OWASP LLM entry`);
        assert.ok(current[0].items.length > 0, `${entity.id} has an empty OWASP LLM mapping`);

        for (const item of current[0].items) {
            if (item === 'N/A') continue;
            assert.equal(item.startsWith('N/A'), false, `${entity.id} must use exact N/A without annotation`);
            const id = item.split(' ')[0];
            const canonical = activeLabels.get(id);
            assert.ok(canonical, `${entity.id} uses unknown OWASP LLM item ${item}`);
            assert.ok(
                item === canonical || (item.startsWith(`${canonical} (`) && item.endsWith(')')),
                `${entity.id} does not preserve the canonical OWASP LLM label: ${item}`
            );
        }
    }
});

test('2026-08-28 practical-control migration preserves the frozen control boundaries', () => {
    const expectedGuidance = new Map([
        ['AID-H-002.009', 5],
        ['AID-H-018.009', 3],
        ['AID-H-021.005', 3]
    ]);
    const entities = allEntities();

    assert.equal(entities.some(item => item.id === 'AID-H-002.010'), false);
    assert.equal(entities.some(item => item.id === 'AID-H-004.006'), false);

    for (const [id, count] of expectedGuidance) {
        const entity = entityById(id);
        assert.equal(entity.implementationGuidance.length, count, id);
        assert.equal(entity.defendsAgainst.length, 9, `${id} mapping coverage`);
        assert.deepEqual(
            entity.implementationGuidance.map(item => item.id),
            Array.from({ length: count }, (_, index) => `${id}-G${String(index + 1).padStart(3, '0')}`)
        );
    }

    const optionalReviewer = entityById('AID-H-018.003').implementationGuidance;
    assert.equal(optionalReviewer.at(-1).id, 'AID-H-018.003-G002');
    assert.match(optionalReviewer.at(-1).implementation, /non-authoritative|review/i);

    const reciprocalBoundaries = new Map([
        ['AID-H-002.009', [
            'AID-H-002.001', 'AID-H-002.003', 'AID-H-003.009', 'AID-H-006.002'
        ]],
        ['AID-H-018.009', [
            'AID-H-006.002', 'AID-H-018.001', 'AID-H-018.002',
            'AID-H-018.006', 'AID-H-018.007', 'AID-H-025.002',
            'AID-H-030.004', 'AID-H-034.004', 'AID-H-034.005', 'AID-I-001'
        ]],
        ['AID-H-021.005', [
            'AID-H-021.001', 'AID-H-021.002', 'AID-H-021.003',
            'AID-H-030.005', 'AID-H-018.003', 'AID-I-001'
        ]]
    ]);
    for (const [target, neighbors] of reciprocalBoundaries) {
        for (const neighbor of neighbors) {
            const related = entityById(neighbor).scopeBoundary?.relatedTechniques || [];
            assert.ok(
                related.some(item => item.id === target),
                neighbor + ' must contain the reciprocal boundary to ' + target
            );
        }
    }
});

test('MCP examples preserve the 2026-07-28 input_required wire value', () => {
    const hardenSource = fs.readFileSync(path.join(ROOT, 'tactics', 'harden.js'), 'utf8');

    assert.doesNotMatch(
        hardenSource,
        /resultType\s*:\s*\\?["']inputRequired\\?["']/,
        'camelCase helper naming must not leak into the MCP resultType wire value'
    );
    assert.doesNotMatch(
        hardenSource,
        /resultType\s*!==?\s*\\?["']inputRequired\\?["']/,
        'MCP resultType comparisons must use the protocol wire value'
    );
    assert.match(
        hardenSource,
        /resultType\s*:\s*\\?["']input_required\\?["']/,
        'at least one authored MCP example must exercise input_required'
    );
});

test('inter-agent event verification binds the claimed key ID to its producer', () => {
    const guidance = entityById('AID-D-011.002').implementationGuidance
        .find(item => item.id === 'AID-D-011.002-G001');

    assert.ok(guidance, 'missing AID-D-011.002-G001');
    assert.match(guidance.howTo, /active_keys: dict\[tuple\[str, str\]/);
    assert.match(guidance.howTo, /active_keys\.get\(\(producer, key_id\)\)/);
    assert.doesNotMatch(guidance.howTo, /active_keys\[producer\]\.verify/);
});

test('reviewed hardening corrections preserve their enforcement contracts', () => {
    const h032Registry = entityById('AID-H-032.002').implementationGuidance
        .find(item => item.id === 'AID-H-032.002-G001').howTo;
    assert.match(h032Registry, /authoritative registry/i);
    assert.match(h032Registry, /require_atomic_generation_lease: true/);
    assert.match(h032Registry, /ownership_handoff/);
    assert.match(h032Registry, /direct runtime-API bypass/);

    const diagnostics = entityById('AID-H-032.003').implementationGuidance
        .find(item => item.id === 'AID-H-032.003-G006').howTo;
    assert.match(diagnostics, /path: \/internal\/diagnostics/);
    assert.doesNotMatch(diagnostics, /prefix: \/internal\/diagnostics/);
    assert.match(diagnostics, /wrong-identity\.crt/);
    assert.match(diagnostics, /\$\{BASE_URL\}-extra/);
    assert.match(diagnostics, /401\|403\|404/);
    assert.doesNotMatch(diagnostics, /200\|401\|403\|404/);

    const authorization = entityById('AID-H-018.002').implementationGuidance
        .find(item => item.id === 'AID-H-018.002-G001').howTo;
    assert.match(authorization, /input\.resource\.canonical_id in input\.user\.allowed_account_ids/);
    assert.match(authorization, /input\.resource\.tenant_id == input\.user\.tenant_id/);
    assert.doesNotMatch(authorization, /input\.resource\.account_id/);
    assert.doesNotMatch(authorization, /input\.resource\.sensitivity/);

    const breaker = entityById('AID-H-017.001').implementationGuidance
        .find(item => item.id === 'AID-H-017.001-G002').howTo;
    assert.match(breaker, /max_cumulative_tokens/);
    assert.match(breaker, /max_cumulative_cost_microunits/);
    assert.match(breaker, /token_budget_exhausted/);
    assert.match(breaker, /cost_budget_exhausted/);

    const workspaceGate = entityById('AID-H-021.005');
    const atlas = workspaceGate.defendsAgainst.find(
        mapping => mapping.framework === 'MITRE ATLAS'
    );
    assert.ok(atlas.items.some(item => item.startsWith(
        'AML.T0010.005 AI Supply Chain Compromise: AI Agent Tool'
    )));
    const broker = workspaceGate.implementationGuidance
        .find(item => item.id === 'AID-H-021.005-G002').howTo;
    assert.match(broker, /def teardown\(/);
    assert.match(broker, /evidence failed and teardown was not proven/);
});

test('standalone Terraform security-group rules do not mix with inline egress', () => {
    const guidance = entityById('AID-I-002.001').implementationGuidance
        .find(item => item.id === 'AID-I-002.001-G002').howTo;

    assert.doesNotMatch(guidance, /\begress\s*=\s*\[\]/);
    assert.match(guidance, /aws_vpc_security_group_egress_rule/);
    assert.match(guidance, /Keep inline <code>ingress<\/code>\/<code>egress<\/code> arguments absent/);
});

test('inter-agent authorization uses one ordered complete-rule decision chain', () => {
    const guidance = entityById('AID-H-004.003').implementationGuidance
        .find(item => item.id === 'AID-H-004.003-G007').howTo;
    const policy = guidance.slice(
        guidance.indexOf('# File: policy/inter_agent_authorization.rego'),
        guidance.indexOf('</code></pre>', guidance.indexOf('# File: policy/inter_agent_authorization.rego'))
    );

    assert.equal((policy.match(/^decision :=/gm) || []).length, 1);
    assert.equal((policy.match(/^else :=/gm) || []).length, 6);
});

test('generated migration JSON and browser consumers use the authored registry', () => {
    const generatedSource = fs.readFileSync(
        path.join(ROOT, 'data', 'framework-migrations.json'),
        'utf8'
    );
    assert.equal(generatedSource.endsWith('\n'), true);
    assert.match(generatedSource, /^\{\n  "schemaVersion": "1\.0",/);
    const generated = JSON.parse(generatedSource);
    assert.deepEqual(generated, frameworkMigrations);

    const indexHtml = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
    assert.match(indexHtml, /import \{ frameworkMigrations \} from '\.\/framework-migrations\.js'/);
    assert.match(indexHtml, /owaspLlmCatalog\.activeItems\.map/);

    const webMcp = fs.readFileSync(path.join(ROOT, 'webmcp-tools.js'), 'utf8');
    assert.match(webMcp, /buildThreatQueryPlan/);
    assert.match(webMcp, /resolvedQuery/);

    const queryModule = fs.readFileSync(path.join(ROOT, 'webmcp-query.js'), 'utf8');
    assert.match(queryModule, /resolveOwaspLlmReference/);
    assert.match(queryModule, /\.sort\(\(left, right\) => left\._tier - right\._tier\)/);
});
