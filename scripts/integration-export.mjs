/**
 * Tool-neutral integration export: data/integration/
 *
 * Produces versioned JSON that downstream tools (first consumer: Precogly,
 * https://github.com/precogly/precogly/issues/552) can convert into their own
 * formats without parsing AIDEFEND's authoring conventions:
 *
 *   manifest.json                     version lock, checksums, counts, attribution
 *   controls.json                     309 actionable controls + 58 navigation-only families
 *   threat-control-joins.json         defendsAgainst inverted: one record per (framework, item)
 *   threat-catalogs/<framework>.json  upstream identifiers/names/structure, no descriptions
 *
 * This module is pure: it builds file contents from the generated dataset and
 * returns them. scripts/generate-dataset.js writes or verifies the files, so
 * `node scripts/generate-dataset.js --check` (run in CI) fails whenever the
 * export drifts from the framework source. Every mapping string must resolve
 * against its framework catalog; anything unresolved aborts generation instead
 * of being guessed.
 */
import { createHash } from 'node:crypto';
import { frameworkMigrations } from '../framework-migrations.js';
import { integrationCatalogs } from '../integration-catalogs.js';

export const INTEGRATION_SCHEMA_VERSION = 1;
export const SITE_URL = 'https://aidefend.net';
export const FRAMEWORK_KEY_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;
export const ATTRIBUTION =
  'AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.';
export const LICENSE_URL = 'https://creativecommons.org/licenses/by/4.0/';
export const CLAIM_BOUNDARY =
  'A threat-to-control mapping says a control is relevant to a threat. It does not say the threat is mitigated, ' +
  'that a system is secure, or that any standard is satisfied.';
export const LICENSE_SUMMARY =
  'CC BY 4.0 for AIDEFEND-authored content: control names, descriptions, scope boundaries, threat-to-control ' +
  "relationships and rationales. External framework identifiers, names and structure remain their owners' " +
  'material under the license recorded in each threat catalog.';

/** Frameworks exported in this release, in output order. `label` is the exact defendsAgainst framework string. */
export const PUBLISHED_FRAMEWORKS = Object.freeze([
  { key: 'mitre-atlas', label: 'MITRE ATLAS', idPattern: /^(AML\.T\d{4}(?:\.\d{3})?)\s+(.*)$/s },
  { key: 'owasp-llm-top-10-2026', label: 'OWASP LLM Top 10 2026', idPattern: /^(LLM\d{2}:2026)\s+(.*)$/s },
  { key: 'owasp-ml-top-10-2023', label: 'OWASP ML Top 10 2023', idPattern: /^(ML\d{2}:2023)\s+(.*)$/s },
  { key: 'owasp-agentic-top-10-2026', label: 'OWASP Top 10 for Agentic Applications 2026', idPattern: /^(ASI\d{2}:2026)\s+(.*)$/s },
]);

/** Frameworks mapped in data.json whose catalogs and joins are not exported yet. */
export const DEFERRED_FRAMEWORKS = Object.freeze([
  { key: 'maestro-1-0', label: 'MAESTRO' },
  { key: 'nist-aml-2025', label: 'NIST Adversarial Machine Learning 2025' },
  { key: 'cisco-ai-security-safety-2-0', label: 'Cisco Integrated AI Security and Safety Framework' },
  { key: 'google-saif-2-0-risks', label: 'Google Secure AI Framework 2.0 - Risks' },
  { key: 'databricks-dasf-3-0', label: 'Databricks AI Security Framework 3.0' },
]);

const DEFERRAL_REASON =
  'Mapped in data.json; catalog and joins export deferred until the upstream license notice for redistributing ' +
  'the full identifier list is recorded in THIRD_PARTY_NOTICES.md.';

const HTML_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function sha256(content) {
  return `sha256:${createHash('sha256').update(content, 'utf8').digest('hex')}`;
}

function toJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/**
 * Convert the bounded HTML subset used in technique descriptions to plain text.
 * Supported: <br>, <strong>, <em>, <code>, <b>, <i>, <ul>/<ol>/<li>. Any other tag
 * or unknown entity aborts generation so new markup is handled deliberately.
 */
export function htmlToPlainText(html, ownerId = '<unknown>') {
  const source = String(html ?? '').replace(/\r\n?/g, '\n');
  const tagPattern = /<\/?([a-zA-Z0-9]+)\b[^>]*>/g;
  const listStack = [];
  let out = '';
  let last = 0;
  let match;
  while ((match = tagPattern.exec(source)) !== null) {
    out += source.slice(last, match.index);
    last = tagPattern.lastIndex;
    const closing = match[0].startsWith('</');
    const tag = match[1].toLowerCase();
    switch (tag) {
      case 'br':
        out += '\n';
        break;
      case 'strong':
      case 'em':
      case 'code':
      case 'b':
      case 'i':
        break;
      case 'ul':
      case 'ol':
        if (closing) {
          if (listStack.length === 0 || listStack[listStack.length - 1].type !== tag) {
            throw new Error(`Unbalanced </${tag}> in description of ${ownerId}`);
          }
          listStack.pop();
          out += '\n\n';
        } else {
          listStack.push({ type: tag, count: 0 });
          out += '\n';
        }
        break;
      case 'li': {
        if (closing) break;
        const list = listStack[listStack.length - 1];
        if (!list) throw new Error(`<li> outside a list in description of ${ownerId}`);
        list.count += 1;
        const indent = '  '.repeat(listStack.length - 1);
        out += `\n${indent}${list.type === 'ol' ? `${list.count}. ` : '- '}`;
        break;
      }
      default:
        throw new Error(`Unsupported HTML tag <${tag}> in description of ${ownerId}`);
    }
  }
  out += source.slice(last);
  if (listStack.length > 0) throw new Error(`Unclosed list in description of ${ownerId}`);
  out = out.replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (entity, name) => {
    if (name[0] === '#') {
      const code = name[1].toLowerCase() === 'x' ? Number.parseInt(name.slice(2), 16) : Number.parseInt(name.slice(1), 10);
      return String.fromCodePoint(code);
    }
    const decoded = HTML_ENTITIES[name.toLowerCase()];
    if (decoded === undefined) throw new Error(`Unknown HTML entity ${entity} in description of ${ownerId}`);
    return decoded;
  });
  return out
    .split('\n')
    .map(line => line.replace(/^(\s*(?:-|\d+\.) )[ \t]+/, '$1').replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function scopeBoundary(value, ownerId) {
  if (!value) return null;
  const allowed = new Set(['responsibility', 'relatedTechniques']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`Unexpected scopeBoundary field "${key}" on ${ownerId}`);
  }
  return {
    responsibility: value.responsibility,
    related_techniques: (value.relatedTechniques || []).map(relation => ({
      id: relation.id,
      comparison: relation.comparison,
    })),
  };
}

function controlUrl(id) {
  return `${SITE_URL}/#t=${encodeURIComponent(id)}`;
}

function controlRecord(entity, tactic, familyId, kind) {
  return {
    id: entity.id,
    name: entity.name,
    actionable: true,
    kind,
    tactic: tactic.name,
    tactic_id: tactic.id,
    family_id: familyId,
    pillar: [...(entity.pillar || [])],
    phase: [...(entity.phase || [])],
    description_text: htmlToPlainText(entity.description, entity.id),
    scope_boundary: scopeBoundary(entity.scopeBoundary, entity.id),
    url: controlUrl(entity.id),
  };
}

function familyRecord(entity, tactic, children) {
  return {
    id: entity.id,
    name: entity.name,
    actionable: false,
    kind: 'family',
    tactic: tactic.name,
    tactic_id: tactic.id,
    description_text: htmlToPlainText(entity.description, entity.id),
    scope_boundary: scopeBoundary(entity.scopeBoundary, entity.id),
    children: children.map(child => child.id),
    url: controlUrl(entity.id),
  };
}

/** Load the upstream catalog for a published framework key. */
export function loadCatalog(key) {
  if (key === 'owasp-llm-top-10-2026') {
    const registry = frameworkMigrations.frameworks.owasp_llm;
    if (registry.activeEdition !== '2026') {
      throw new Error(`framework-migrations.js active OWASP LLM edition is ${registry.activeEdition}, expected 2026`);
    }
    const artifact = registry.sourceArtifact;
    const license = registry.sourceLicense;
    return {
      framework_key: key,
      source_framework_label: registry.activeLabel,
      display_name: registry.activeLabel,
      upstream: 'OWASP Foundation / OWASP GenAI Security Project',
      upstream_version: `${registry.activeEdition} ${artifact.release}`,
      upstream_url: registry.sourceUrl,
      source_artifact: {
        url: artifact.downloadUrl,
        release: artifact.release,
        file_name: artifact.fileName,
        sha256: artifact.sha256,
      },
      license_notice:
        `${license.attribution}, licensed under ${license.spdxExpression} (${license.licenseUrl}). ` +
        'Identifiers, ranks and names only; no source prose is reproduced. See THIRD_PARTY_NOTICES.md.',
      items: registry.activeItems.map(item => ({ external_id: item.id, rank: item.rank, name: item.name })),
    };
  }
  const catalog = integrationCatalogs[key];
  if (!catalog) throw new Error(`No integration catalog for framework key ${key}`);
  return catalog;
}

/**
 * Resolve one AIDEFEND mapping string against the framework catalog.
 * Returns the catalog identity and AIDEFEND's parenthetical rationale, if any.
 */
export function splitRationale(raw, framework, itemsById) {
  const match = framework.idPattern.exec(raw);
  if (!match) throw new Error(`${framework.key}: cannot parse mapping item "${raw}"`);
  const [, externalId, rest] = match;
  const item = itemsById.get(externalId);
  if (!item) throw new Error(`${framework.key}: ${externalId} is not in the catalog ("${raw}")`);
  if (rest === item.name) return { external_id: externalId, name: item.name, rationale: null };
  if (rest.startsWith(`${item.name} (`) && rest.endsWith(')')) {
    return { external_id: externalId, name: item.name, rationale: rest.slice(item.name.length + 2, -1).trim() };
  }
  throw new Error(`${framework.key}: item text does not match catalog name "${item.name}": "${raw}"`);
}

/**
 * Build every data/integration file from the generated dataset.
 * @returns {{ files: Map<string, string>, summary: object }}
 */
export function buildIntegrationExport({ tactics, aidefendVersion, dataVersion, generatedAt, dataJsonContent }) {
  if (!/^1\.\d{8}$/.test(aidefendVersion)) throw new Error(`Invalid AIDEFEND version ${aidefendVersion}`);
  if (!Number.isFinite(Date.parse(generatedAt))) throw new Error(`Invalid generatedAt ${generatedAt}`);
  const header = { schema_version: INTEGRATION_SCHEMA_VERSION, aidefend_version: aidefendVersion };

  const actionable = [];
  const families = [];
  for (const tactic of tactics) {
    for (const technique of tactic.techniques) {
      const subs = technique.subTechniques || [];
      if (subs.length > 0) {
        families.push(familyRecord(technique, tactic, subs));
        for (const sub of subs) {
          actionable.push({ source: sub, record: controlRecord(sub, tactic, technique.id, 'sub-technique') });
        }
      } else {
        actionable.push({ source: technique, record: controlRecord(technique, tactic, null, 'standalone') });
      }
    }
  }
  const controls = actionable.map(entry => entry.record);
  const controlIds = new Set(controls.map(control => control.id));
  if (controlIds.size !== controls.length) throw new Error('Duplicate control IDs in integration export');
  for (const family of families) {
    if (controlIds.has(family.id)) throw new Error(`${family.id} is both a family and a control`);
  }

  const catalogFiles = [];
  const joins = [];
  const publishedSummary = [];
  let duplicatePairs = 0;
  let controlPairs = 0;
  for (const framework of PUBLISHED_FRAMEWORKS) {
    if (!FRAMEWORK_KEY_PATTERN.test(framework.key)) throw new Error(`Framework key ${framework.key} is not slug-safe`);
    const catalog = loadCatalog(framework.key);
    if (catalog.framework_key !== framework.key || catalog.source_framework_label !== framework.label) {
      throw new Error(`Catalog metadata mismatch for ${framework.key}`);
    }
    const itemsById = new Map(catalog.items.map(item => [item.external_id, item]));
    if (itemsById.size !== catalog.items.length) throw new Error(`Duplicate identifiers in ${framework.key} catalog`);

    const hits = new Map();
    for (const { source, record } of actionable) {
      const block = (source.defendsAgainst || []).find(entry => entry.framework === framework.label);
      if (!block) throw new Error(`${record.id} has no "${framework.label}" mapping block`);
      for (const raw of block.items) {
        if (/^N\/A\b/.test(raw.trim())) continue;
        const parsed = splitRationale(raw, framework, itemsById);
        let list = hits.get(parsed.external_id);
        if (!list) hits.set(parsed.external_id, (list = []));
        if (list.some(entry => entry.id === record.id)) {
          duplicatePairs += 1;
          continue;
        }
        list.push({ id: record.id, rationale: parsed.rationale, item_raw: raw });
      }
    }

    const items = catalog.items.map(item => {
      const list = hits.get(item.external_id) || [];
      return {
        item_locator: `${item.external_id} ${item.name}`,
        ...item,
        referenced: list.length > 0,
        control_count: list.length,
      };
    });
    const referencedItems = items.filter(item => item.referenced).length;
    for (const item of items) {
      const list = hits.get(item.external_id);
      if (!list) continue;
      controlPairs += list.length;
      joins.push({
        framework_key: framework.key,
        external_id: item.external_id,
        item_locator: item.item_locator,
        name: item.name,
        controls: list,
      });
    }

    const { items: _omit, tactics: catalogTactics, ...metadata } = catalog;
    const catalogPath = `threat-catalogs/${framework.key}.json`;
    catalogFiles.push([catalogPath, {
      ...header,
      ...metadata,
      item_locator_rule: 'item_locator is "<external_id> <name>". Match identity on external_id; never on the raw AIDEFEND string.',
      counts: { items: items.length, referenced_items: referencedItems },
      ...(catalogTactics ? { tactics: catalogTactics } : {}),
      items,
    }]);
    publishedSummary.push({
      framework_key: framework.key,
      source_framework_label: framework.label,
      catalog_path: catalogPath,
      items: items.length,
      referenced_items: referencedItems,
    });
  }

  const standalone = controls.filter(control => control.kind === 'standalone').length;
  const files = new Map();
  files.set('controls.json', toJson({
    ...header,
    data_version: dataVersion,
    unit_rule: 'Every entry in controls is an independently selectable control unit. Entries in families are navigation only and must not be treated as countermeasures.',
    counts: {
      actionable_controls: controls.length,
      standalone_techniques: standalone,
      leaf_subtechniques: controls.length - standalone,
      families: families.length,
    },
    controls,
    families,
  }));
  files.set('threat-control-joins.json', toJson({
    ...header,
    data_version: dataVersion,
    identity_rule: 'Resolve each record against threat-catalogs/<framework_key>.json by external_id. item_raw is the exact AIDEFEND source string, kept for traceability only. rationale is AIDEFEND-authored context for that pair, or null.',
    frameworks: PUBLISHED_FRAMEWORKS.map(framework => framework.key),
    counts: { records: joins.length, control_pairs: controlPairs },
    joins,
  }));
  for (const [catalogPath, body] of catalogFiles) files.set(catalogPath, toJson(body));

  const fileEntries = [...files.entries()].map(([filePath, body]) => ({
    path: filePath,
    sha256: sha256(body),
    bytes: Buffer.byteLength(body, 'utf8'),
  }));
  files.set('manifest.json', toJson({
    ...header,
    data_version: dataVersion,
    git_tag: `v${aidefendVersion}`,
    generated_at: generatedAt,
    source_data_json_sha256: sha256(dataJsonContent),
    first_consumer: 'precogly',
    layout: {
      controls: 'controls.json',
      threat_control_joins: 'threat-control-joins.json',
      threat_catalogs: 'threat-catalogs/<framework_key>.json',
    },
    counts: {
      tactics: tactics.length,
      parent_families: families.length,
      actionable_controls: controls.length,
      standalone_techniques: standalone,
      leaf_subtechniques: controls.length - standalone,
      threat_join_records: joins.length,
      threat_control_pairs: controlPairs,
    },
    frameworks_published: publishedSummary,
    frameworks_deferred: DEFERRED_FRAMEWORKS.map(framework => ({
      framework_key: framework.key,
      source_framework_label: framework.label,
      reason: DEFERRAL_REASON,
    })),
    files: fileEntries,
    license: LICENSE_SUMMARY,
    license_url: LICENSE_URL,
    attribution: ATTRIBUTION,
    claim_boundary: CLAIM_BOUNDARY,
    notes: [
      'Generated by scripts/generate-dataset.js from tactics/*.js; do not hand-edit. Regenerated with every AIDEFEND release and verified by CI.',
      'Control IDs are stable across releases; retirements or splits are called out in release notes.',
      "Threat catalogs carry upstream identifiers, names and structure only. Item descriptions are the upstream owners' material and are not reproduced.",
      'Within one schema_version the layout only gains fields; consumers should ignore unknown fields.',
    ],
  }));

  return {
    files,
    summary: {
      controls: controls.length,
      families: families.length,
      joinRecords: joins.length,
      controlPairs,
      duplicatePairs,
      catalogs: publishedSummary,
    },
  };
}
