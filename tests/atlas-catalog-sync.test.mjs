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

test('ATLAS 2026.09 retains the pinned official source and every new identifier', () => {
  assert.equal(catalog.upstream_version, '2026.09');
  assert.equal(catalog.source_artifact.git_revision, '3259f388d19cbcca11bacf12a0ef97f4198f711b');
  assert.equal(catalog.source_artifact.sha256, '935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688');
  const ids = new Set(catalog.items.map(x => x.external_id));
  for (const id of ['AML.T0000.003', 'AML.T0006.000', 'AML.T0006.001', 'AML.T0006.002', 'AML.T0006.003',
    'AML.T0129', 'AML.T0130', 'AML.T0131', 'AML.T0132', 'AML.T0133', 'AML.T0134']) {
    assert.ok(ids.has(id), id);
  }
  assert.equal(ids.size, 208);
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
