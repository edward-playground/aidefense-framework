#!/usr/bin/env node
/**
 * Count techniques and sub-techniques from the exported tactic objects.
 *
 * Do not count source text with regular expressions: implementation examples
 * legitimately contain fields such as `id` and `control_id`, which are not
 * framework controls.
 */

import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const TACTICS_DIR = path.join(__dirname, '..', 'tactics');

const tacticModules = [
  ['detect.js', 'detectTactic', 18, 53],
  ['harden.js', 'hardenTactic', 37, 139],
  ['isolate.js', 'isolateTactic', 8, 25],
  ['model.js', 'modelTactic', 10, 35],
  ['deceive.js', 'deceiveTactic', 7, 0],
  ['evict.js', 'evictTactic', 5, 8],
  ['restore.js', 'restoreTactic', 7, 5],
];

console.log('Exported Tactic Object Analysis');
console.log('===============================\n');

let totalTechniques = 0;
let totalSubTechniques = 0;
let totalParentFamilies = 0;
let totalStandaloneTechniques = 0;
const seenIds = new Set();

for (const [file, exportName, expectedTechniques, expectedSubTechniques] of tacticModules) {
  const moduleUrl = pathToFileURL(path.join(TACTICS_DIR, file)).href;
  const module = await import(moduleUrl);
  const tactic = module[exportName];

  if (!tactic || !Array.isArray(tactic.techniques)) {
    throw new TypeError(`${file} does not export ${exportName}.techniques as an array`);
  }

  const techniqueCount = tactic.techniques.length;
  const parentFamilyCount = tactic.techniques.filter(
    technique => Array.isArray(technique.subTechniques) && technique.subTechniques.length > 0,
  ).length;
  const standaloneTechniqueCount = techniqueCount - parentFamilyCount;
  const subTechniqueCount = tactic.techniques.reduce((count, technique) => {
    if (!technique || typeof technique.id !== 'string') {
      throw new TypeError(`${file} contains a technique without a string id`);
    }
    if (seenIds.has(technique.id)) {
      throw new Error(`Duplicate control id: ${technique.id}`);
    }
    seenIds.add(technique.id);

    if (technique.subTechniques === undefined) return count;
    if (!Array.isArray(technique.subTechniques)) {
      throw new TypeError(`${technique.id}.subTechniques must be an array`);
    }

    for (const subTechnique of technique.subTechniques) {
      if (!subTechnique || typeof subTechnique.id !== 'string') {
        throw new TypeError(`${technique.id} contains a sub-technique without a string id`);
      }
      if (seenIds.has(subTechnique.id)) {
        throw new Error(`Duplicate control id: ${subTechnique.id}`);
      }
      seenIds.add(subTechnique.id);
    }
    return count + technique.subTechniques.length;
  }, 0);

  console.log(`${file}: ${techniqueCount} techniques, ${subTechniqueCount} sub-techniques`);
  if (techniqueCount !== expectedTechniques || subTechniqueCount !== expectedSubTechniques) {
    throw new Error(
      `${file} live export count drifted: expected ${expectedTechniques} techniques and ` +
      `${expectedSubTechniques} sub-techniques, found ${techniqueCount} and ${subTechniqueCount}`,
    );
  }
  totalTechniques += techniqueCount;
  totalSubTechniques += subTechniqueCount;
  totalParentFamilies += parentFamilyCount;
  totalStandaloneTechniques += standaloneTechniqueCount;
}

console.log('\n------------------------');
console.log(`TOTAL: ${totalTechniques} techniques, ${totalSubTechniques} sub-techniques`);
console.log(`TOTAL TAXONOMY ENTRIES: ${totalTechniques + totalSubTechniques}`);
console.log(`PARENT FAMILIES (navigation only): ${totalParentFamilies}`);
console.log(`ACTIONABLE CONTROLS: ${totalStandaloneTechniques + totalSubTechniques}`);
if (totalTechniques !== 92 || totalSubTechniques !== 265 || seenIds.size !== 357 ||
    totalParentFamilies !== 57 || totalStandaloneTechniques !== 35) {
  throw new Error(
    `Live corpus count drifted: expected 92 techniques, 265 sub-techniques, 357 unique IDs, ` +
    `57 parent families, and 35 standalone controls; found ${totalTechniques}, ` +
    `${totalSubTechniques}, ${seenIds.size}, ${totalParentFamilies}, and ` +
    `${totalStandaloneTechniques}`,
  );
}
