#!/usr/bin/env node
// Build the GitHub Release page for a published v1.YYYYMMDD tag.
//
// The release-tag workflow creates an immutable annotated tag for every
// validated Framework release. This script turns that tag into release notes
// that an integrator can act on: which controls were added, retired, moved,
// renamed or changed since the previous tag, which external framework editions
// moved, the current counts, the integration-export checksums, and the files
// attached to the release. It reads every dataset from the tagged commits with
// `git show`, never from the working tree, so the notes describe exactly what
// the tag contains.
//
//   node scripts/release-notes.mjs --tag v1.20261101 [--previous v1.20261008 | --previous none]
//                                  [--out-dir release-assets] [--repo-root <path>]
//
// Outputs inside --out-dir: release-notes.md (the Release body),
// release-changes.json (the complete machine-readable diff) and SHA256SUMS.txt
// (one line per file already present in the directory, so the workflow copies
// the data assets in first). Zero dependencies; Node >= 22.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const TAG_PATTERN = /^v1\.\d{8}$/;
export const CLAIM_BOUNDARY = 'A threat-to-control mapping says a control is relevant to a threat. ' +
  'It does not say the threat is mitigated, that a system is secure, or that any standard is satisfied.';
export const ATTRIBUTION = 'AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.';
// GitHub rejects release bodies above 125,000 characters; stay well below.
export const MAX_BODY_CHARS = 110_000;
const DETAILS_THRESHOLD = 15;

const FACET_LABELS = {
  name: 'renamed',
  kind: 'structure changed (standalone, family or sub-technique role)',
  children: 'sub-technique set changed',
  description: 'description changed',
  scopeBoundary: 'scope boundary changed',
  applicability: 'pillar or phase changed',
  guidance: 'implementation guidance changed',
  tools: 'tool lists changed',
  mappings: 'threat mappings changed',
  other: 'content hash changed without a tracked field difference',
};
const FACET_ORDER = Object.keys(FACET_LABELS);

const stable = value => JSON.stringify(value ?? null);
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const normalizeName = name => String(name ?? '').trim().toLowerCase().replace(/\s+/g, ' ');

export function flattenRecords(dataset) {
  assert.ok(dataset && Array.isArray(dataset.tactics), 'data.json must contain a tactics array.');
  const records = new Map();
  const put = record => {
    assert.ok(!records.has(record.id), `Duplicate technique id ${record.id}.`);
    records.set(record.id, record);
  };
  const pick = (source, { kind, tactic, parent }) => ({
    id: source.id,
    name: source.name ?? '',
    kind,
    tactic,
    parent,
    contentHash: source.contentHash ?? null,
    description: source.description ?? '',
    scopeBoundary: source.scopeBoundary ?? null,
    pillar: [...(source.pillar ?? [])].sort(),
    phase: [...(source.phase ?? [])].sort(),
    defendsAgainst: source.defendsAgainst ?? [],
    guidance: source.implementationGuidance ?? [],
    guidanceIds: source.implementationGuidanceIds ?? [],
    tools: {
      openSource: source.toolsOpenSource ?? [],
      sourceAvailable: source.toolsSourceAvailable ?? [],
      commercial: source.toolsCommercial ?? [],
    },
    children: (source.subTechniques ?? []).map(sub => sub.id).sort(),
  });
  for (const tactic of dataset.tactics) {
    const tacticKey = tactic.id ?? tactic.name ?? '';
    for (const technique of tactic.techniques ?? []) {
      const subTechniques = technique.subTechniques ?? [];
      put(pick(technique, { kind: subTechniques.length ? 'family' : 'standalone', tactic: tacticKey, parent: null }));
      for (const sub of subTechniques) put(pick(sub, { kind: 'leaf', tactic: tacticKey, parent: technique.id }));
    }
  }
  return records;
}

export function summarizeCounts(records) {
  const counts = { records: records.size, families: 0, standalone: 0, leaves: 0, actionable: 0, guidanceEntries: 0, mappingItems: 0 };
  for (const record of records.values()) {
    if (record.kind === 'family') counts.families += 1;
    else if (record.kind === 'standalone') counts.standalone += 1;
    else counts.leaves += 1;
    if (record.kind !== 'family') {
      counts.actionable += 1;
      counts.guidanceEntries += record.guidance.length;
      for (const entry of record.defendsAgainst) counts.mappingItems += (entry.items ?? []).length;
    }
  }
  return counts;
}

function facetsFor(previous, current) {
  const facets = [];
  const detail = {};
  if (previous.name !== current.name) { facets.push('name'); detail.name = { from: previous.name, to: current.name }; }
  if (previous.kind !== current.kind) { facets.push('kind'); detail.kind = { from: previous.kind, to: current.kind }; }
  if (stable(previous.children) !== stable(current.children)) {
    facets.push('children');
    detail.children = {
      added: current.children.filter(id => !previous.children.includes(id)),
      removed: previous.children.filter(id => !current.children.includes(id)),
    };
  }
  if (previous.description !== current.description) facets.push('description');
  if (stable(previous.scopeBoundary) !== stable(current.scopeBoundary)) facets.push('scopeBoundary');
  if (stable(previous.pillar) !== stable(current.pillar) || stable(previous.phase) !== stable(current.phase)) {
    facets.push('applicability');
    detail.applicability = { pillar: { from: previous.pillar, to: current.pillar }, phase: { from: previous.phase, to: current.phase } };
  }
  if (stable(previous.guidance) !== stable(current.guidance) || stable(previous.guidanceIds) !== stable(current.guidanceIds)) {
    facets.push('guidance');
    detail.guidance = { from: previous.guidance.length, to: current.guidance.length };
  }
  if (stable(previous.tools) !== stable(current.tools)) facets.push('tools');
  if (stable(previous.defendsAgainst) !== stable(current.defendsAgainst)) {
    facets.push('mappings');
    const before = new Map(previous.defendsAgainst.map(entry => [entry.framework, stable(entry.items)]));
    const after = new Map(current.defendsAgainst.map(entry => [entry.framework, stable(entry.items)]));
    const frameworks = new Set([...before.keys(), ...after.keys()]);
    detail.mappings = [...frameworks].filter(framework => before.get(framework) !== after.get(framework)).sort();
  }
  if (!facets.length && previous.contentHash !== current.contentHash) facets.push('other');
  return { facets, detail };
}

// Compare two flattened datasets. Records are matched by id; a retired id whose
// exact name reappears under a new id is reported as a move so integrators can
// re-point instead of dropping the reference. Everything else that differs is
// listed per record with the facets that changed.
export function diffDatasets(previousRecords, currentRecords) {
  const added = [];
  const retired = [];
  const modified = [];
  for (const [id, current] of currentRecords) {
    const previous = previousRecords.get(id);
    if (!previous) { added.push(current); continue; }
    const { facets, detail } = facetsFor(previous, current);
    if (facets.length) modified.push({ id, name: current.name, kind: current.kind, tactic: current.tactic, facets, detail });
  }
  for (const [id, previous] of previousRecords) if (!currentRecords.has(id)) retired.push(previous);
  const moved = [];
  for (const old of [...retired]) {
    const candidates = added.filter(record => normalizeName(record.name) === normalizeName(old.name) && normalizeName(old.name));
    const match = candidates.find(record => record.tactic === old.tactic) ?? candidates[0];
    if (!match) continue;
    moved.push({ from: old.id, to: match.id, name: match.name, kind: { from: old.kind, to: match.kind } });
    retired.splice(retired.indexOf(old), 1);
    added.splice(added.indexOf(match), 1);
  }
  const strip = record => ({ id: record.id, name: record.name, kind: record.kind, tactic: record.tactic, parent: record.parent });
  return {
    added: added.map(strip).sort(byId),
    retired: retired.map(strip).sort(byId),
    moved: moved.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : 0)),
    modified: modified.sort(byId),
    counts: { previous: summarizeCounts(previousRecords), current: summarizeCounts(currentRecords) },
  };
}

// External framework editions come from two tagged sources: the migration
// registry (data/framework-migrations.json, activeEdition per stable key) and
// the integration threat catalogs (upstream_version per published framework).
// The catalog edition wins when both exist, because the registry only started
// tracking a framework once it needed successor metadata, so a framework may be
// new in the registry while its catalog already recorded the earlier edition.
export function frameworkEditionChanges(previousMigrations, currentMigrations, previousCatalogs = [], currentCatalogs = []) {
  const readRegistry = migrations => Object.values(migrations?.frameworks ?? {})
    .map(entry => [entry.stableKey ?? entry.activeLabel, { label: entry.activeLabel ?? entry.stableKey, edition: entry.activeEdition ?? null }]);
  const readCatalogs = catalogs => (catalogs ?? []).map(catalog => [catalog.framework_key ?? catalog.display_name,
    { label: catalog.display_name ?? catalog.framework_key, edition: catalog.upstream_version ?? null }]);
  const changes = new Map();
  const compare = (beforeEntries, afterEntries, source, previousKnown) => {
    const before = new Map(beforeEntries);
    for (const [key, current] of afterEntries) {
      const previous = before.get(key);
      const label = current.label;
      if (previous && previous.edition !== current.edition) changes.set(label, { key, label, from: previous.edition, to: current.edition, source });
      else if (!previous && previousKnown && !changes.has(label)) changes.set(label, { key, label, from: null, to: current.edition, source });
      else if (previous && changes.get(label)?.from === null) changes.delete(label);
    }
  };
  compare(readRegistry(previousMigrations), readRegistry(currentMigrations), 'registry', Boolean(previousMigrations));
  compare(readCatalogs(previousCatalogs), readCatalogs(currentCatalogs), 'catalog', previousCatalogs.length > 0);
  return [...changes.values()].sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
}

export function readCatalogsAtRef(repoRoot, ref) {
  const manifest = readJsonAtRef(repoRoot, ref, 'data/integration/manifest.json');
  return (manifest?.frameworks_published ?? [])
    .map(entry => readJsonAtRef(repoRoot, ref, `data/integration/${entry.catalog_path}`))
    .filter(Boolean);
}

const describe = record => `\`${record.id}\` ${record.name}${record.kind === 'family' ? ' (family, navigation only)' : ''}`;

function renderList(items, format, cap) {
  if (!items.length) return '';
  const shown = items.slice(0, cap).map(item => `- ${format(item)}`);
  const hidden = items.length - shown.length;
  if (hidden > 0) shown.push(`- … ${hidden} more; the complete list is in \`release-changes.json\`.`);
  const body = shown.join('\n');
  if (items.length <= DETAILS_THRESHOLD) return `${body}\n`;
  return `<details><summary>${items.length} records</summary>\n\n${body}\n\n</details>\n`;
}

function renderBody({ tag, previousTag, dataVersion, schemaVersion, diff, editions, manifest, assets }, cap) {
  const lines = [];
  const counts = diff?.counts.current ?? null;
  lines.push(`## AIDEFEND ${tag}`, '');
  lines.push(`- Data version: \`${dataVersion ?? 'unknown'}\`${schemaVersion ? ` (public schema ${schemaVersion})` : ''}`);
  lines.push(previousTag
    ? `- Changes below are relative to the previous release \`${previousTag}\`.`
    : '- First tagged release in this series; no previous tag to compare against.');
  if (counts) {
    lines.push(`- Records: ${counts.records} (${counts.families} navigation-only families, ${counts.actionable} actionable controls = ` +
      `${counts.standalone} standalone techniques + ${counts.leaves} sub-techniques), ${counts.guidanceEntries} implementation-guidance entries, ` +
      `${counts.mappingItems} threat-mapping items.`);
  }
  lines.push('');
  lines.push('### How to cite this release', '');
  lines.push(`Cite controls as \`AID-X-NNN[.MMM]\` together with the data version, for example \`AID-H-018.002 (AIDEFEND ${dataVersion ?? tag})\`. ` +
    'Pin integrations to this tag, not to `main`. Families (`actionable: false`) are navigation only and are never a countermeasure. ' +
    `${CLAIM_BOUNDARY}`, '');

  if (diff && previousTag) {
    const { added, retired, moved, modified } = diff;
    const structural = modified.filter(record => record.facets.some(facet => ['kind', 'children'].includes(facet)));
    const renamed = modified.filter(record => record.facets.includes('name'));
    const content = modified.filter(record => record.facets.some(facet => ['description', 'scopeBoundary', 'applicability'].includes(facet)));
    const guidanceOrTools = modified.filter(record => record.facets.some(facet => ['guidance', 'tools'].includes(facet)) &&
      !record.facets.some(facet => ['description', 'scopeBoundary', 'applicability', 'kind', 'children', 'name'].includes(facet)));
    const mappingOnly = modified.filter(record => record.facets.every(facet => facet === 'mappings'));
    const other = modified.filter(record => record.facets.every(facet => facet === 'other'));
    const previousCounts = diff.counts.previous;
    const delta = diff.counts.current.actionable - previousCounts.actionable;

    lines.push('### Summary of changes', '');
    lines.push(`- ${added.length} added, ${retired.length} retired, ${moved.length} moved to a new id, ${modified.length} changed in place ` +
      `(${mappingOnly.length} of them threat-mapping only). Actionable controls ${previousCounts.actionable} → ${diff.counts.current.actionable} (${delta >= 0 ? '+' : ''}${delta}).`);
    for (const change of editions) {
      lines.push(change.from === null
        ? `- ${change.label}: now tracked at edition ${change.to ?? 'unknown'} (no earlier edition recorded).`
        : `- ${change.label}: edition ${change.from} → ${change.to ?? 'none'}.`);
    }
    lines.push('');
    if (added.length) { lines.push('### Added', ''); lines.push(renderList(added, describe, cap)); }
    if (moved.length) {
      lines.push('### Moved to a new id', '', 'Update references from the old id to the new one; the name is unchanged.', '');
      lines.push(renderList(moved, item => `\`${item.from}\` → \`${item.to}\` ${item.name}${item.kind.from !== item.kind.to ? ` (${item.kind.from} → ${item.kind.to})` : ''}`, cap));
    }
    if (retired.length) {
      lines.push('### Retired', '', 'These ids no longer exist. No automatic successor is recorded; check the scope boundaries of related controls before re-pointing a reference.', '');
      lines.push(renderList(retired, describe, cap));
    }
    if (structural.length) {
      lines.push('### Structure changed', '');
      lines.push(renderList(structural, record => {
        const parts = [];
        if (record.detail.kind) parts.push(`${record.detail.kind.from} → ${record.detail.kind.to}`);
        if (record.detail.children) {
          if (record.detail.children.added.length) parts.push(`gained ${record.detail.children.added.map(id => `\`${id}\``).join(', ')}`);
          if (record.detail.children.removed.length) parts.push(`lost ${record.detail.children.removed.map(id => `\`${id}\``).join(', ')}`);
        }
        return `${describe(record)}: ${parts.join('; ')}`;
      }, cap));
    }
    if (renamed.length) {
      lines.push('### Renamed', '');
      lines.push(renderList(renamed, record => `\`${record.id}\` ${record.detail.name.from} → ${record.detail.name.to}`, cap));
    }
    if (content.length) {
      lines.push('### Description, scope or applicability changed', '', 'Re-read these controls before relying on an earlier citation.', '');
      lines.push(renderList(content, record => `${describe(record)}: ${record.facets.filter(facet => facet !== 'mappings').map(facet => FACET_LABELS[facet]).join(', ')}`, cap));
    }
    if (guidanceOrTools.length) {
      lines.push('### Implementation guidance or tools changed', '');
      lines.push(renderList(guidanceOrTools, record => {
        const parts = record.facets.filter(facet => facet !== 'mappings').map(facet => facet === 'guidance' && record.detail.guidance
          ? `guidance ${record.detail.guidance.from} → ${record.detail.guidance.to} entries` : FACET_LABELS[facet]);
        return `${describe(record)}: ${parts.join(', ')}`;
      }, cap));
    }
    if (mappingOnly.length) {
      lines.push('### Threat mappings changed (content unchanged)', '',
        'Usually caused by an upstream framework edition update listed above; the control text did not change.', '');
      lines.push(renderList(mappingOnly, record => `${describe(record)}: ${record.detail.mappings.join(', ')}`, cap));
    }
    if (other.length) {
      lines.push('### Content hash changed without a tracked field difference', '');
      lines.push(renderList(other, describe, cap));
    }
    if (!added.length && !retired.length && !moved.length && !modified.length) {
      lines.push('No technique or sub-technique changed between the two tags.', '');
    }
  }

  if (manifest) {
    lines.push('### Integration export', '');
    lines.push(`\`data/integration/\` schema ${manifest.schema_version ?? '?'}; \`data.json\` ${manifest.source_data_json_sha256 ?? ''}`.trim() + '.');
    const published = (manifest.frameworks_published ?? []).map(entry => `${entry.source_framework_label} (${entry.referenced_items}/${entry.items} items referenced)`);
    if (published.length) lines.push(`Published threat catalogs: ${published.join('; ')}.`);
    const deferred = (manifest.frameworks_deferred ?? []).map(entry => entry.source_framework_label);
    if (deferred.length) lines.push(`Deferred catalogs: ${deferred.join(', ')}.`);
    for (const file of manifest.files ?? []) lines.push(`- \`${file.path}\` ${file.sha256} (${file.bytes} bytes)`);
    lines.push('');
  }

  if (assets?.length) {
    lines.push('### Attached files', '');
    for (const asset of assets) lines.push(`- \`${asset.name}\` — ${asset.bytes} bytes, sha256 \`${asset.sha256}\``);
    lines.push('', 'Verify downloads against `SHA256SUMS.txt` before importing.', '');
  }

  lines.push('---', '', `${ATTRIBUTION} External framework identifiers, names and structure remain their owners' material; see THIRD_PARTY_NOTICES.md.`, '');
  return lines.join('\n');
}

export function renderReleaseNotes(input) {
  let body = '';
  for (const cap of [Infinity, 60, 15, 5]) {
    body = renderBody(input, cap);
    if (body.length <= MAX_BODY_CHARS) return body;
  }
  return `${body.slice(0, MAX_BODY_CHARS - 200)}\n\n… truncated; the complete change list is in \`release-changes.json\`.\n`;
}

export function hashAssets(directory, { exclude = ['release-notes.md', 'SHA256SUMS.txt'] } = {}) {
  const assets = [];
  for (const name of fs.readdirSync(directory).sort()) {
    if (exclude.includes(name)) continue;
    const file = path.join(directory, name);
    if (!fs.statSync(file).isFile()) continue;
    const bytes = fs.readFileSync(file);
    assets.push({ name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  fs.writeFileSync(path.join(directory, 'SHA256SUMS.txt'), assets.map(asset => `${asset.sha256}  ${asset.name}\n`).join(''));
  return assets;
}

function gitAt(repoRoot) {
  return (...args) => execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

export function readJsonAtRef(repoRoot, ref, file) {
  const git = gitAt(repoRoot);
  try { git('cat-file', '-e', `${ref}:${file}`); } catch { return null; }
  return JSON.parse(git('show', `${ref}:${file}`));
}

// The previous release is the newest v1.YYYYMMDD tag that is an ancestor of the
// given tag and sorts before it, which is the same ordering the tag workflow
// enforces when it refuses version rollbacks.
export function findPreviousTag(repoRoot, tag) {
  const git = gitAt(repoRoot);
  const candidates = git('tag', '--merged', `refs/tags/${tag}`, '--list', 'v1.*').split('\n')
    .filter(candidate => TAG_PATTERN.test(candidate) && candidate < tag).sort();
  return candidates.at(-1) ?? null;
}

export function buildRelease({ repoRoot, tag, previous, outDir }) {
  assert.ok(TAG_PATTERN.test(tag), 'Tag must look like v1.YYYYMMDD.');
  const git = gitAt(repoRoot);
  git('rev-parse', '--verify', `refs/tags/${tag}^{commit}`);
  const previousTag = previous === 'none' ? null : (previous ?? findPreviousTag(repoRoot, tag));
  if (previousTag) {
    assert.ok(TAG_PATTERN.test(previousTag) && previousTag < tag, 'Previous tag must be an older v1.YYYYMMDD tag.');
    git('rev-parse', '--verify', `refs/tags/${previousTag}^{commit}`);
  }
  const current = readJsonAtRef(repoRoot, `refs/tags/${tag}`, 'data/data.json');
  assert.ok(current, `${tag} does not contain data/data.json.`);
  const previousData = previousTag ? readJsonAtRef(repoRoot, `refs/tags/${previousTag}`, 'data/data.json') : null;
  const currentRecords = flattenRecords(current);
  const diff = previousData ? diffDatasets(flattenRecords(previousData), currentRecords) : { counts: { previous: null, current: summarizeCounts(currentRecords) } };
  const editions = frameworkEditionChanges(
    previousTag ? readJsonAtRef(repoRoot, `refs/tags/${previousTag}`, 'data/framework-migrations.json') : null,
    readJsonAtRef(repoRoot, `refs/tags/${tag}`, 'data/framework-migrations.json'),
    previousTag ? readCatalogsAtRef(repoRoot, `refs/tags/${previousTag}`) : [],
    readCatalogsAtRef(repoRoot, `refs/tags/${tag}`));
  const manifest = readJsonAtRef(repoRoot, `refs/tags/${tag}`, 'data/integration/manifest.json');
  fs.mkdirSync(outDir, { recursive: true });
  const changes = {
    tag, previous_tag: previousTag, data_version: current.version?.dataVersion ?? null, schema_version: current.version?.schemaVersion ?? null,
    generated_from: 'data/data.json at both tags', framework_edition_changes: editions, ...diff,
  };
  fs.writeFileSync(path.join(outDir, 'release-changes.json'), `${JSON.stringify(changes, null, 2)}\n`);
  const assets = hashAssets(outDir);
  const notes = renderReleaseNotes({
    tag, previousTag, dataVersion: changes.data_version, schemaVersion: changes.schema_version,
    diff: previousData ? diff : null, editions, manifest, assets,
  });
  fs.writeFileSync(path.join(outDir, 'release-notes.md'), notes);
  return { tag, previousTag, outDir, notesPath: path.join(outDir, 'release-notes.md'), assets: assets.map(asset => asset.name),
    added: diff.added?.length ?? 0, retired: diff.retired?.length ?? 0, moved: diff.moved?.length ?? 0, modified: diff.modified?.length ?? 0 };
}

function parseArgs(argv) {
  const options = { previous: undefined, outDir: 'release-assets', repoRoot: undefined, tag: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const [flag, inline] = argv[index].split('=', 2);
    const value = inline ?? argv[++index];
    assert.ok(value !== undefined, `Missing value for ${flag}.`);
    if (flag === '--tag') options.tag = value;
    else if (flag === '--previous') options.previous = value;
    else if (flag === '--out-dir') options.outDir = value;
    else if (flag === '--repo-root') options.repoRoot = value;
    else assert.fail(`Unknown argument ${flag}. Use --tag, --previous, --out-dir, --repo-root.`);
  }
  assert.ok(options.tag, 'Use --tag v1.YYYYMMDD.');
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const repoRoot = path.resolve(options.repoRoot ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
  const result = buildRelease({ repoRoot, tag: options.tag, previous: options.previous, outDir: path.resolve(options.outDir) });
  console.log(JSON.stringify(result));
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `notes=${result.notesPath}\nprevious_tag=${result.previousTag ?? ''}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
