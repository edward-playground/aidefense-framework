import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { integrationCatalogs } from '../integration-catalogs.js';
import { aidefendData } from '../main.js';

const catalog = integrationCatalogs['mitre-atlas'];
const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
function embedded(name) {
  const match = html.match(new RegExp(`const ${name} = (\\{[\\s\\S]*?\\n\\s*\\});`));
  assert.ok(match, `${name} is present`);
  return JSON.parse(match[1]);
}

test('ATLAS 2026.10 retains the pinned official source and active identifiers', () => {
  assert.equal(catalog.upstream_version, '2026.10');
  assert.equal(catalog.source_artifact.git_revision, 'f56c1468731d6428e5bf875263b4643b46d67437');
  assert.equal(catalog.source_artifact.sha256, 'ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d');
  assert.equal(catalog.source_artifact.data_format_version, '6.1.0');
  const ids = new Set(catalog.items.map(x => x.external_id));
  for (const id of ['AML.T0017.003', 'AML.T0085.002', 'AML.T0085.003', 'AML.T0135', 'AML.T0136',
    'AML.T0137', 'AML.T0137.000', 'AML.T0137.001', 'AML.T0137.002', 'AML.T0137.003',
    'AML.T0138', 'AML.T0139', 'AML.T0140', 'AML.T0141', 'AML.T0142', 'AML.T0143', 'AML.T0144', 'AML.T0145']) {
    assert.ok(ids.has(id), id);
  }
  assert.equal(ids.size, 221);
  for (const id of ['AML.T0024.000', 'AML.T0024.001', 'AML.T0024.002', 'AML.T0056', 'AML.T0057']) {
    assert.ok(!ids.has(id), `${id} is not an active catalog item`);
  }
});

test('all five website ATLAS blocks agree with the public identifier catalog', () => {
  const names = embedded('atlasTechNames');
  const descriptions = embedded('atlasTechDescs');
  const hierarchy = embedded('atlasSubTechniques');
  const memberships = embedded('atlasTechToTactics');
  const tactics = embedded('atlasTacticInfo');
  assert.deepEqual(Object.keys(names).sort(), catalog.items.map(x => x.external_id).sort());
  assert.deepEqual(Object.keys(descriptions).sort(), Object.keys(names).sort());
  for (const item of catalog.items) {
    assert.equal(names[item.external_id], item.short_name);
    assert.ok(descriptions[item.external_id].length > 0);
    if (item.parent_id) assert.ok(hierarchy[item.parent_id].includes(item.external_id));
    else assert.deepEqual(memberships[item.external_id].map(name => tactics[name].id).sort(), [...item.tactic_ids].sort());
  }
  assert.equal(Object.keys(tactics).length, catalog.tactics.length);
  for (const tactic of catalog.tactics) assert.equal(tactics[tactic.name].id, tactic.id);
});

test('all ATLAS mappings resolve canonically and renderer claims remain with rendering controls', () => {
  const entries = aidefendData.tactics.flatMap(t => t.techniques.flatMap(c => [c, ...(c.subTechniques || [])]));
  const byId = new Map(catalog.items.map(x => [x.external_id, x]));
  for (const entry of entries) {
    for (const item of entry.defendsAgainst.find(x => x.framework === 'MITRE ATLAS').items) {
      if (item.startsWith('N/A')) continue;
      const target = byId.get(item.split(' ')[0]);
      assert.ok(target, `${entry.id}: ${item}`);
      const canonical = `${target.external_id} ${target.name}`;
      assert.ok(item === canonical || item.startsWith(`${canonical} (`), `${entry.id}: ${item}`);
    }
  }
  for (const id of ['AID-H-006.001', 'AID-D-003.008']) {
    const items = entries.find(c => c.id === id).defendsAgainst.find(x => x.framework === 'MITRE ATLAS').items;
    assert.ok(!items.some(x => x.startsWith('AML.T0077 ')), `${id} must not claim an unimplemented renderer boundary`);
  }
});

test('ATLAS collection mappings preserve data-origin and model-recovery boundaries', () => {
  const entries = aidefendData.tactics.flatMap(t => t.techniques.flatMap(c => [c, ...(c.subTechniques || [])]));
  const idsFor = id => new Set(entries.find(c => c.id === id).defendsAgainst
    .find(f => f.framework === 'MITRE ATLAS').items.map(item => item.split(' ')[0]));
  assert.ok(idsFor('AID-H-013.003').has('AML.T0005.001'), 'behavioral fingerprinting addresses replication');
  assert.ok(!idsFor('AID-H-013.003').has('AML.T0144'), 'a behavioral fingerprint does not recover model internals');
  assert.ok(idsFor('AID-H-005.004').has('AML.T0137.003'), 'deduplication addresses memorized training content');
  assert.ok(idsFor('AID-H-027').has('AML.T0085.002'), 'cache isolation protects retained interactions');
  assert.ok(idsFor('AID-H-005.005').has('AML.T0085.000'), 'vector-store confidentiality protects retrieval sources');
  for (const id of ['AID-H-005.005', 'AID-D-003.007']) {
    assert.ok(!idsFor(id).has('AML.T0137.000'), `${id} does not test training membership`);
    assert.ok(!idsFor(id).has('AML.T0137.002'), `${id} does not reconstruct the training population`);
  }
  const tactics = new Set(catalog.items.find(item => item.external_id === 'AML.T0005').tactic_ids);
  assert.ok(tactics.has('AML.TA0003') && tactics.has('AML.TA0001'), 'replication is present in both official tactics');
});
