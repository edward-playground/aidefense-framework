import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { aidefendVersion } from '../aidefend-intro.js';
import { frameworkMigrations } from '../framework-migrations.js';
import {
  ATTRIBUTION,
  CLAIM_BOUNDARY,
  DEFERRED_FRAMEWORKS,
  FRAMEWORK_KEY_PATTERN,
  INTEGRATION_SCHEMA_VERSION,
  PUBLISHED_FRAMEWORKS,
  buildIntegrationExport,
  htmlToPlainText,
  loadCatalog,
  splitRationale,
} from '../scripts/integration-export.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INTEGRATION_DIR = path.join(ROOT, 'data', 'integration');
// Raw bytes on purpose: the manifest checksums are a contract with downstream
// consumers, so a CRLF checkout must fail here rather than be normalized away
// (.gitattributes pins data/** to LF).
const readText = file => fs.readFileSync(file, 'utf8');
const readIntegration = relative => JSON.parse(readText(path.join(INTEGRATION_DIR, relative)));
const sha256 = content => `sha256:${createHash('sha256').update(content, 'utf8').digest('hex')}`;

const dataJsonContent = readText(path.join(ROOT, 'data', 'data.json'));
const dataset = JSON.parse(dataJsonContent);
const manifest = readIntegration('manifest.json');
const controlsFile = readIntegration('controls.json');
const joinsFile = readIntegration('threat-control-joins.json');
const catalogFiles = new Map(
  PUBLISHED_FRAMEWORKS.map(framework => [framework.key, readIntegration(`threat-catalogs/${framework.key}.json`)]),
);

const actionableIds = new Set();
const familyIds = new Set();
const frameworkLabels = new Set();
for (const tactic of dataset.tactics) {
  for (const technique of tactic.techniques) {
    for (const block of technique.defendsAgainst) frameworkLabels.add(block.framework);
    if (technique.subTechniques?.length) {
      familyIds.add(technique.id);
      for (const sub of technique.subTechniques) actionableIds.add(sub.id);
    } else {
      actionableIds.add(technique.id);
    }
  }
}

function listFiles(directory, prefix = '') {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    return entry.isDirectory() ? listFiles(path.join(directory, entry.name), relative) : [relative];
  });
}

test('manifest locks the release, the source dataset and every exported file', () => {
  assert.equal(manifest.schema_version, INTEGRATION_SCHEMA_VERSION);
  assert.equal(manifest.aidefend_version, aidefendVersion);
  assert.equal(manifest.git_tag, `v${aidefendVersion}`);
  assert.equal(manifest.data_version, dataset.version.dataVersion);
  assert.equal(manifest.generated_at, dataset.version.generatedAt);
  assert.equal(manifest.source_data_json_sha256, sha256(dataJsonContent));
  assert.equal(manifest.claim_boundary, CLAIM_BOUNDARY);
  assert.equal(manifest.attribution, ATTRIBUTION);
  assert.equal(manifest.license_url, 'https://creativecommons.org/licenses/by/4.0/');
  assert.equal(manifest.first_consumer, 'precogly');

  const onDisk = listFiles(INTEGRATION_DIR).filter(file => file !== 'manifest.json').sort();
  const listed = manifest.files.map(entry => entry.path).sort();
  assert.deepEqual(onDisk, listed, 'every exported file is listed and nothing else is present');
  for (const entry of manifest.files) {
    const body = readText(path.join(INTEGRATION_DIR, entry.path));
    assert.equal(sha256(body), entry.sha256, `checksum for ${entry.path}`);
    assert.equal(Buffer.byteLength(body, 'utf8'), entry.bytes, `size for ${entry.path}`);
  }

  assert.deepEqual(manifest.frameworks_published.map(f => f.framework_key), PUBLISHED_FRAMEWORKS.map(f => f.key));
  assert.deepEqual(manifest.frameworks_deferred.map(f => f.framework_key), DEFERRED_FRAMEWORKS.map(f => f.key));
  assert.deepEqual(manifest.counts, {
    tactics: dataset.tactics.length,
    parent_families: familyIds.size,
    actionable_controls: actionableIds.size,
    standalone_techniques: controlsFile.controls.filter(control => control.kind === 'standalone').length,
    leaf_subtechniques: controlsFile.controls.filter(control => control.kind === 'sub-technique').length,
    threat_join_records: joinsFile.joins.length,
    threat_control_pairs: joinsFile.joins.reduce((sum, join) => sum + join.controls.length, 0),
  });
});

test('controls.json carries every actionable control once, with derived URLs and plain-text descriptions', () => {
  const controlIds = new Set(controlsFile.controls.map(control => control.id));
  assert.equal(controlIds.size, controlsFile.controls.length, 'control IDs are unique');
  assert.deepEqual([...controlIds].sort(), [...actionableIds].sort(), 'exactly the actionable controls of data.json');
  assert.deepEqual(controlsFile.families.map(family => family.id).sort(), [...familyIds].sort());
  assert.equal(controlsFile.counts.actionable_controls, 309);
  assert.equal(controlsFile.counts.families, 58);
  assert.equal(controlsFile.counts.standalone_techniques + controlsFile.counts.leaf_subtechniques, 309);

  const families = new Map(controlsFile.families.map(family => [family.id, family]));
  const knownIds = new Set([...controlIds, ...families.keys()]);
  const tacticIds = new Set(dataset.tactics.map(tactic => tactic.id));
  const tacticNames = new Set(dataset.tactics.map(tactic => tactic.name));
  for (const control of controlsFile.controls) {
    assert.equal(control.actionable, true);
    assert.ok(['standalone', 'sub-technique'].includes(control.kind), `${control.id} kind`);
    if (control.kind === 'standalone') {
      assert.equal(control.family_id, null, `${control.id} standalone has no family`);
    } else {
      assert.ok(families.has(control.family_id), `${control.id} family ${control.family_id} exists`);
      assert.ok(families.get(control.family_id).children.includes(control.id), `${control.id} listed under its family`);
    }
    assert.ok(tacticIds.has(control.tactic_id) && tacticNames.has(control.tactic), `${control.id} tactic`);
    assert.ok(Array.isArray(control.pillar) && control.pillar.length > 0, `${control.id} pillar`);
    assert.ok(Array.isArray(control.phase) && control.phase.length > 0, `${control.id} phase`);
    assert.equal(control.url, `https://aidefend.net/#t=${control.id}`);
    assert.ok(control.description_text.length > 0, `${control.id} description`);
    assert.doesNotMatch(control.description_text, /<[a-z]+[^>]*>/i, `${control.id} description is plain text`);
    assert.doesNotMatch(control.description_text, /&[a-z#0-9]+;/i, `${control.id} entities decoded`);
    if (control.scope_boundary !== null) {
      assert.equal(typeof control.scope_boundary.responsibility, 'string');
      for (const relation of control.scope_boundary.related_techniques) {
        assert.ok(knownIds.has(relation.id), `${control.id} boundary reference ${relation.id} exists`);
        assert.notEqual(relation.id, control.id);
        assert.equal(typeof relation.comparison, 'string');
      }
    }
  }
  for (const family of controlsFile.families) {
    assert.equal(family.actionable, false);
    assert.equal(family.kind, 'family');
    assert.ok(family.children.length >= 2, `${family.id} has at least two children`);
    for (const child of family.children) assert.ok(controlIds.has(child), `${family.id} child ${child}`);
    assert.doesNotMatch(family.description_text, /<[a-z]+[^>]*>/i, `${family.id} description is plain text`);
  }
});

test('threat-control joins resolve by external_id against the published catalogs and control list', () => {
  assert.deepEqual(joinsFile.frameworks, PUBLISHED_FRAMEWORKS.map(framework => framework.key));
  assert.equal(joinsFile.counts.records, joinsFile.joins.length);
  const controlIds = new Set(controlsFile.controls.map(control => control.id));
  const seen = new Set();
  const perCatalog = new Map();
  let pairs = 0;
  for (const join of joinsFile.joins) {
    const catalog = catalogFiles.get(join.framework_key);
    assert.ok(catalog, `${join.framework_key} catalog is published`);
    const item = catalog.items.find(candidate => candidate.external_id === join.external_id);
    assert.ok(item, `${join.framework_key} ${join.external_id} exists in the catalog`);
    assert.equal(join.item_locator, item.item_locator);
    assert.equal(join.name, item.name);
    const key = `${join.framework_key}|${join.external_id}`;
    assert.ok(!seen.has(key), `${key} appears once`);
    seen.add(key);
    assert.ok(join.controls.length > 0, `${key} has controls`);
    const ids = new Set();
    for (const control of join.controls) {
      assert.ok(controlIds.has(control.id), `${key} -> ${control.id} is an actionable control`);
      assert.ok(!ids.has(control.id), `${key} lists ${control.id} once`);
      ids.add(control.id);
      assert.ok(control.item_raw.startsWith(`${join.external_id} `), `${key} item_raw keeps the source string`);
      assert.ok(control.rationale === null || (typeof control.rationale === 'string' && control.rationale.length > 0));
    }
    pairs += join.controls.length;
    if (!perCatalog.has(join.framework_key)) perCatalog.set(join.framework_key, new Map());
    perCatalog.get(join.framework_key).set(join.external_id, join.controls.length);
  }
  assert.equal(joinsFile.counts.control_pairs, pairs);

  for (const [key, catalog] of catalogFiles) {
    const hits = perCatalog.get(key) || new Map();
    let referenced = 0;
    for (const item of catalog.items) {
      const count = hits.get(item.external_id) || 0;
      assert.equal(item.referenced, count > 0, `${key} ${item.external_id} referenced flag`);
      assert.equal(item.control_count, count, `${key} ${item.external_id} control_count`);
      if (count > 0) referenced += 1;
    }
    assert.equal(catalog.counts.items, catalog.items.length);
    assert.equal(catalog.counts.referenced_items, referenced);
  }
});

test('threat catalogs are slug-keyed, structurally complete and carry no upstream descriptions', () => {
  const published = new Set(PUBLISHED_FRAMEWORKS.map(framework => framework.key));
  for (const framework of [...PUBLISHED_FRAMEWORKS, ...DEFERRED_FRAMEWORKS]) {
    assert.match(framework.key, FRAMEWORK_KEY_PATTERN, `${framework.key} is slug-safe`);
  }
  for (const framework of DEFERRED_FRAMEWORKS) assert.ok(!published.has(framework.key));
  const coveredLabels = new Set([...PUBLISHED_FRAMEWORKS, ...DEFERRED_FRAMEWORKS].map(framework => framework.label));
  assert.deepEqual([...frameworkLabels].sort(), [...coveredLabels].sort(), 'every mapped framework is published or deferred');

  for (const [key, catalog] of catalogFiles) {
    assert.equal(catalog.schema_version, INTEGRATION_SCHEMA_VERSION);
    assert.equal(catalog.aidefend_version, aidefendVersion);
    assert.equal(catalog.framework_key, key);
    assert.ok(frameworkLabels.has(catalog.source_framework_label), `${key} label matches data.json`);
    assert.ok(catalog.license_notice.length > 0 && catalog.upstream_version.length > 0 && catalog.upstream_url.length > 0);
    const ids = new Set();
    for (const item of catalog.items) {
      assert.ok(!ids.has(item.external_id), `${key} ${item.external_id} unique`);
      ids.add(item.external_id);
      assert.equal(item.item_locator, `${item.external_id} ${item.name}`);
      assert.equal(item.description, undefined, `${key} ${item.external_id} carries no upstream description`);
    }
  }

  const atlas = catalogFiles.get('mitre-atlas');
  assert.equal(atlas.items.length, 208);
  assert.equal(atlas.upstream_version, '2026.09');
  assert.equal(atlas.tactics.length, 16);
  const atlasIds = new Set(atlas.items.map(item => item.external_id));
  const atlasTactics = new Set(atlas.tactics.map(tactic => tactic.id));
  for (const item of atlas.items) {
    if (item.parent_id !== null) {
      assert.ok(atlasIds.has(item.parent_id), `${item.external_id} parent exists`);
      assert.ok(item.name.startsWith(`${atlas.items.find(p => p.external_id === item.parent_id).name}: `));
    }
    assert.ok(item.tactic_ids.length > 0 && item.tactic_ids.every(id => atlasTactics.has(id)), `${item.external_id} tactics`);
  }

  for (const key of ['owasp-llm-top-10-2026', 'owasp-ml-top-10-2023', 'owasp-agentic-top-10-2026']) {
    const catalog = catalogFiles.get(key);
    assert.deepEqual(catalog.items.map(item => item.rank), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], `${key} ranks`);
  }
  assert.deepEqual(
    catalogFiles.get('owasp-llm-top-10-2026').items.map(item => [item.external_id, item.name]),
    frameworkMigrations.frameworks.owasp_llm.activeItems.map(item => [item.id, item.name]),
    'OWASP LLM 2026 catalog mirrors the active edition registry',
  );
});

test('the export is reproducible from data.json byte for byte', () => {
  const rebuilt = buildIntegrationExport({
    tactics: dataset.tactics,
    aidefendVersion,
    dataVersion: dataset.version.dataVersion,
    generatedAt: dataset.version.generatedAt,
    dataJsonContent,
  });
  const expected = new Set(rebuilt.files.keys());
  assert.deepEqual(listFiles(INTEGRATION_DIR).sort(), [...expected].sort());
  for (const [relative, body] of rebuilt.files) {
    assert.equal(readText(path.join(INTEGRATION_DIR, relative)), body, `${relative} matches the generator output`);
  }
  assert.equal(rebuilt.summary.duplicatePairs, 0);
});

test('htmlToPlainText converts the bounded description markup and rejects anything else', () => {
  assert.equal(htmlToPlainText('<strong>Bold</strong> text<br>next &amp; more'), 'Bold text\nnext & more');
  assert.equal(
    htmlToPlainText('Steps:<ul><li> first </li><li>second <code>x</code></li></ul>Done'),
    'Steps:\n\n- first\n- second x\n\nDone',
  );
  assert.equal(htmlToPlainText('<ol><li>one</li><li>two</li></ol>'), '1. one\n2. two');
  assert.throws(() => htmlToPlainText('<p>para</p>', 'X'), /Unsupported HTML tag <p>/);
  assert.throws(() => htmlToPlainText('a &bogus; b', 'X'), /Unknown HTML entity/);
  assert.throws(() => htmlToPlainText('<ul><li>open', 'X'), /Unclosed list/);
});

test('splitRationale keeps catalog identity and only strips an AIDEFEND parenthetical rationale', () => {
  const framework = PUBLISHED_FRAMEWORKS[0];
  const items = new Map(loadCatalog(framework.key).items.map(item => [item.external_id, item]));
  assert.deepEqual(splitRationale('AML.T0020 Training Data Poisoning', framework, items), {
    external_id: 'AML.T0020',
    name: 'Training Data Poisoning',
    rationale: null,
  });
  assert.deepEqual(
    splitRationale('AML.T0115.000 Publish Poisoned AI Artifacts: Datasets (sanitization runs before admission)', framework, items),
    { external_id: 'AML.T0115.000', name: 'Publish Poisoned AI Artifacts: Datasets', rationale: 'sanitization runs before admission' },
  );
  assert.throws(() => splitRationale('AML.T0020 Data Poisoning', framework, items), /does not match catalog name/);
  assert.throws(() => splitRationale('AML.T9999 Nothing', framework, items), /not in the catalog/);
});
