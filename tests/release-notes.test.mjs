import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MAX_BODY_CHARS, diffDatasets, findPreviousTag, flattenRecords, frameworkEditionChanges,
  hashAssets, renderReleaseNotes, summarizeCounts,
} from '../scripts/release-notes.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const leaf = (id, name, overrides = {}) => ({
  id, name, description: `${name} description`, pillar: ['app'], phase: ['operation'],
  defendsAgainst: [{ framework: 'MITRE ATLAS', items: ['AML.T0051 LLM Prompt Injection'] }],
  implementationGuidance: ['Do the thing'], implementationGuidanceIds: [`${id}-G001`],
  toolsOpenSource: ['Open Policy Agent (OPA)'], contentHash: `${id}-hash`, ...overrides,
});
const family = (id, name, subTechniques) => ({ id, name, description: `${name} family`, defendsAgainst: [], subTechniques, contentHash: `${id}-hash` });
const dataset = (dataVersion, techniques) => ({ version: { schemaVersion: '2.3', dataVersion }, tactics: [{ id: 'harden', name: 'Harden', techniques }] });

const previousDataset = dataset('2026.09.07', [
  family('AID-H-001', 'Family One', [leaf('AID-H-001.001', 'Leaf One'), leaf('AID-H-001.002', 'Leaf Two')]),
  leaf('AID-H-002', 'Standalone Two'),
  leaf('AID-H-003', 'Old Standalone Three'),
  leaf('AID-H-004', 'Unchanged Four'),
]);
const currentDataset = dataset('2026.09.08', [
  family('AID-H-001', 'Family One', [
    leaf('AID-H-001.001', 'Leaf One', { description: 'Leaf One rewritten', contentHash: 'new' }),
    leaf('AID-H-001.002', 'Leaf Two', { defendsAgainst: [{ framework: 'MITRE ATLAS', items: ['AML.T0051 LLM Prompt Injection', 'AML.T0054 LLM Jailbreak'] }], contentHash: 'new' }),
    leaf('AID-H-001.003', 'Leaf Three'),
  ]),
  family('AID-H-002', 'Standalone Two', [leaf('AID-H-002.001', 'Promoted Child')]),
  leaf('AID-H-005', 'Old Standalone Three'),
  leaf('AID-H-004', 'Unchanged Four'),
  leaf('AID-H-006', 'Brand New Six', { toolsOpenSource: [] }),
]);

test('flattening distinguishes families, standalone techniques and sub-techniques', () => {
  const records = flattenRecords(previousDataset);
  assert.deepEqual(summarizeCounts(records), { records: 6, families: 1, standalone: 3, leaves: 2, actionable: 5, guidanceEntries: 5, mappingItems: 5 });
  assert.equal(records.get('AID-H-001').kind, 'family');
  assert.equal(records.get('AID-H-001.002').parent, 'AID-H-001');
  assert.throws(() => flattenRecords({ tactics: [{ id: 'x', techniques: [leaf('AID-X-001', 'a'), leaf('AID-X-001', 'b')] }] }), /Duplicate/);
});

test('diff classifies added, retired, moved and in-place changes with facets', () => {
  const diff = diffDatasets(flattenRecords(previousDataset), flattenRecords(currentDataset));
  assert.deepEqual(diff.added.map(record => record.id), ['AID-H-001.003', 'AID-H-002.001', 'AID-H-006']);
  assert.deepEqual(diff.retired, []);
  assert.deepEqual(diff.moved, [{ from: 'AID-H-003', to: 'AID-H-005', name: 'Old Standalone Three', kind: { from: 'standalone', to: 'standalone' } }]);
  const byId = Object.fromEntries(diff.modified.map(record => [record.id, record]));
  assert.deepEqual(Object.keys(byId), ['AID-H-001', 'AID-H-001.001', 'AID-H-001.002', 'AID-H-002']);
  assert.deepEqual(byId['AID-H-001'].facets, ['children']);
  assert.deepEqual(byId['AID-H-001'].detail.children, { added: ['AID-H-001.003'], removed: [] });
  assert.deepEqual(byId['AID-H-001.001'].facets, ['description']);
  assert.deepEqual(byId['AID-H-001.002'].facets, ['mappings']);
  assert.deepEqual(byId['AID-H-001.002'].detail.mappings, ['MITRE ATLAS']);
  assert.ok(byId['AID-H-002'].facets.includes('kind'));
  assert.deepEqual(byId['AID-H-002'].detail.kind, { from: 'standalone', to: 'family' });
  assert.equal(diff.counts.previous.actionable, 5);
  assert.equal(diff.counts.current.actionable, 7);
});

test('a content hash change with no tracked field difference is still reported', () => {
  const before = flattenRecords(dataset('a', [leaf('AID-H-009', 'Nine')]));
  const after = flattenRecords(dataset('b', [leaf('AID-H-009', 'Nine', { contentHash: 'different' })]));
  assert.deepEqual(diffDatasets(before, after).modified[0].facets, ['other']);
});

test('framework edition changes merge the migration registry with the integration catalogs', () => {
  const before = { frameworks: { atlas: { stableKey: 'atlas', activeLabel: 'MITRE ATLAS', activeEdition: '2026.09' }, owasp_llm: { stableKey: 'owasp_llm', activeLabel: 'OWASP LLM Top 10', activeEdition: '2026' } } };
  const after = { frameworks: { atlas: { stableKey: 'atlas', activeLabel: 'MITRE ATLAS', activeEdition: '2026.10' }, owasp_llm: { stableKey: 'owasp_llm', activeLabel: 'OWASP LLM Top 10', activeEdition: '2026' } } };
  assert.deepEqual(frameworkEditionChanges(before, after), [{ key: 'atlas', label: 'MITRE ATLAS', from: '2026.09', to: '2026.10', source: 'registry' }]);
  assert.deepEqual(frameworkEditionChanges(null, after), []);

  // A framework that enters the registry mid-stream must not look like a
  // "none → X" edition change when the catalogs already knew its prior edition.
  const registryWithoutAtlas = { frameworks: { owasp_llm: before.frameworks.owasp_llm } };
  const catalog = (edition, label = 'MITRE ATLAS', key = 'mitre-atlas') => ({ framework_key: key, display_name: label, upstream_version: edition });
  assert.deepEqual(frameworkEditionChanges(registryWithoutAtlas, after, [catalog('2026.09')], [catalog('2026.10')]),
    [{ key: 'mitre-atlas', label: 'MITRE ATLAS', from: '2026.09', to: '2026.10', source: 'catalog' }]);
  assert.deepEqual(frameworkEditionChanges(registryWithoutAtlas, after, [catalog('2026.10')], [catalog('2026.10')]), []);
  assert.deepEqual(frameworkEditionChanges(registryWithoutAtlas, after),
    [{ key: 'atlas', label: 'MITRE ATLAS', from: null, to: '2026.10', source: 'registry' }]);
  const notes = renderReleaseNotes({ tag: 'v1.20260908', previousTag: 'v1.20260907', dataVersion: 'x', diff: diffDatasets(flattenRecords(previousDataset), flattenRecords(previousDataset)),
    editions: frameworkEditionChanges(registryWithoutAtlas, after), manifest: null, assets: [] });
  assert.ok(notes.includes('MITRE ATLAS: now tracked at edition 2026.10 (no earlier edition recorded)'));
  assert.ok(notes.includes('No technique or sub-technique changed between the two tags.'));
});

test('release notes carry the sections an integrator needs and stay within the GitHub body limit', () => {
  const diff = diffDatasets(flattenRecords(previousDataset), flattenRecords(currentDataset));
  const notes = renderReleaseNotes({
    tag: 'v1.20260908', previousTag: 'v1.20260907', dataVersion: '2026.09.08', schemaVersion: '2.3', diff,
    editions: [{ key: 'atlas', label: 'MITRE ATLAS', from: '2026.09', to: '2026.10', source: 'registry' }],
    manifest: { schema_version: 1, source_data_json_sha256: 'sha256:abc', frameworks_published: [{ source_framework_label: 'MITRE ATLAS', items: 10, referenced_items: 9 }], files: [{ path: 'controls.json', sha256: 'sha256:def', bytes: 12 }] },
    assets: [{ name: 'data.json', bytes: 3, sha256: 'ff' }],
  });
  for (const expected of ['## AIDEFEND v1.20260908', 'relative to the previous release `v1.20260907`', '### How to cite this release',
    'AIDEFEND 2026.09.08', 'does not say the threat is mitigated', '### Summary of changes', '3 added, 0 retired, 1 moved to a new id, 4 changed in place',
    'MITRE ATLAS: edition 2026.09 → 2026.10', '### Added', '`AID-H-006` Brand New Six', '### Moved to a new id', '`AID-H-003` → `AID-H-005`',
    '### Structure changed', 'standalone → family', 'gained `AID-H-001.003`', '### Description, scope or applicability changed', '`AID-H-001.001`',
    '### Threat mappings changed (content unchanged)', '`AID-H-001.002` Leaf Two: MITRE ATLAS', '### Integration export', 'sha256:def',
    '### Attached files', '`data.json` — 3 bytes', 'licensed under CC BY 4.0']) {
    assert.ok(notes.includes(expected), `missing: ${expected}`);
  }
  assert.ok(!notes.includes('### Retired'));
  assert.ok(!notes.includes('<details>'), 'small lists render inline');

  const initial = renderReleaseNotes({ tag: 'v1.20260907', previousTag: null, dataVersion: '2026.09.07', schemaVersion: '2.3', diff: null, editions: [], manifest: null, assets: [] });
  assert.ok(initial.includes('First tagged release in this series'));
  assert.ok(!initial.includes('### Summary of changes'));

  const many = Array.from({ length: 4000 }, (_, index) => leaf(`AID-H-${String(index + 10).padStart(3, '0')}`, `Control ${index} with a reasonably long descriptive name`));
  const bigDiff = diffDatasets(flattenRecords(dataset('a', many)),
    flattenRecords(dataset('b', many.map(record => ({ ...record, description: 'changed', contentHash: 'changed' })))));
  const big = renderReleaseNotes({ tag: 'v1.20260908', previousTag: 'v1.20260907', dataVersion: 'b', diff: bigDiff, editions: [], manifest: null, assets: [] });
  assert.ok(big.length <= MAX_BODY_CHARS, `body too large: ${big.length}`);
  assert.ok(big.includes('<details>'));
  assert.ok(big.includes('more; the complete list is in `release-changes.json`'));
});

function fixture(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aidefend-release-notes-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const repo = path.join(temporary, 'repo');
  fs.mkdirSync(path.join(repo, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(repo, 'data'));
  const git = (...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '-b', 'main');
  git('config', 'user.name', 'Release notes test');
  git('config', 'user.email', 'release-notes-test@example.invalid');
  fs.copyFileSync(path.join(root, 'scripts/release-notes.mjs'), path.join(repo, 'scripts/release-notes.mjs'));
  const release = (tag, data, migrations) => {
    fs.writeFileSync(path.join(repo, 'data/data.json'), JSON.stringify(data));
    if (migrations) fs.writeFileSync(path.join(repo, 'data/framework-migrations.json'), JSON.stringify(migrations));
    git('add', '.'); git('commit', '-m', `release ${tag}`); git('tag', '-a', tag, '-m', tag);
  };
  release('v1.20260907', previousDataset, { frameworks: { atlas: { stableKey: 'atlas', activeLabel: 'MITRE ATLAS', activeEdition: '2026.08' } } });
  release('v1.20260908', currentDataset, { frameworks: { atlas: { stableKey: 'atlas', activeLabel: 'MITRE ATLAS', activeEdition: '2026.09' } } });
  return { repo, git, temporary };
}

test('CLI reads both tags from git, detects the previous release and hashes the staged assets', t => {
  const f = fixture(t);
  assert.equal(findPreviousTag(f.repo, 'v1.20260908'), 'v1.20260907');
  assert.equal(findPreviousTag(f.repo, 'v1.20260907'), null);
  const outDir = path.join(f.temporary, 'assets');
  fs.mkdirSync(outDir);
  fs.writeFileSync(path.join(outDir, 'data.json'), 'asset-bytes');
  const run = args => spawnSync(process.execPath, ['scripts/release-notes.mjs', ...args], { cwd: f.repo, encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: '' } });

  let result = run(['--tag', 'v1.20260908', '--out-dir', outDir]);
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.previousTag, 'v1.20260907');
  assert.deepEqual(summary.assets, ['data.json', 'release-changes.json']);
  assert.deepEqual([summary.added, summary.retired, summary.moved, summary.modified], [3, 0, 1, 4]);
  const notes = fs.readFileSync(path.join(outDir, 'release-notes.md'), 'utf8');
  assert.ok(notes.includes('MITRE ATLAS: edition 2026.08 → 2026.09'));
  assert.ok(notes.includes('`AID-H-003` → `AID-H-005`'));
  const sums = fs.readFileSync(path.join(outDir, 'SHA256SUMS.txt'), 'utf8');
  assert.match(sums, /^[0-9a-f]{64}  data\.json\n[0-9a-f]{64}  release-changes\.json\n$/);
  const changes = JSON.parse(fs.readFileSync(path.join(outDir, 'release-changes.json'), 'utf8'));
  assert.equal(changes.previous_tag, 'v1.20260907');
  assert.equal(changes.data_version, '2026.09.08');

  result = run(['--tag', 'v1.20260907', '--out-dir', path.join(f.temporary, 'first')]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).previousTag, null);
  assert.ok(fs.readFileSync(path.join(f.temporary, 'first', 'release-notes.md'), 'utf8').includes('First tagged release'));

  result = run(['--tag', 'v1.20260908', '--previous', 'none', '--out-dir', path.join(f.temporary, 'none')]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).previousTag, null);

  assert.notEqual(run(['--tag', 'v1.20260909', '--out-dir', path.join(f.temporary, 'missing')]).status, 0, 'unknown tag fails closed');
  assert.notEqual(run(['--tag', 'main', '--out-dir', path.join(f.temporary, 'bad')]).status, 0, 'non-release refs are rejected');
  assert.notEqual(run(['--tag', 'v1.20260907', '--previous', 'v1.20260908', '--out-dir', path.join(f.temporary, 'order')]).status, 0, 'previous must be older');
});

test('hashAssets skips the notes and checksum files and writes a verifiable SHA256SUMS.txt', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aidefend-release-assets-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'b.zip'), 'zip');
  fs.writeFileSync(path.join(directory, 'a.json'), '{}');
  fs.writeFileSync(path.join(directory, 'release-notes.md'), 'notes');
  const assets = hashAssets(directory);
  assert.deepEqual(assets.map(asset => asset.name), ['a.json', 'b.zip']);
  assert.equal(assets[0].sha256, '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
  assert.equal(fs.readFileSync(path.join(directory, 'SHA256SUMS.txt'), 'utf8').split('\n').filter(Boolean).length, 2);
});
