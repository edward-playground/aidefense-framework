#!/usr/bin/env node
/**
 * Count techniques and sub-techniques in source JS files
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TACTICS_DIR = path.join(__dirname, '..', 'tactics');
const files = ['detect.js', 'harden.js', 'isolate.js', 'model.js', 'deceive.js', 'evict.js', 'restore.js'];

console.log('Source JS Files Analysis');
console.log('========================\n');

let totalTech = 0;
let totalSub = 0;

files.forEach(file => {
  try {
    const content = fs.readFileSync(path.join(TACTICS_DIR, file), 'utf-8');

    // Count parent techniques (AID-X-NNN without decimal)
    // Handle both quoted ("id":) and unquoted (id:) key formats
    const allIds = content.match(/["']?id["']?:\s*["']AID-[A-Z]+-\d+(\.\d+)?["']/g) || [];
    const parentIds = allIds.filter(m => !m.match(/\.\d+["']/));
    const subIds = allIds.filter(m => m.match(/\.\d+["']/));

    console.log(`${file}: ${parentIds.length} techniques, ${subIds.length} sub-techniques`);
    totalTech += parentIds.length;
    totalSub += subIds.length;
  } catch(e) {
    console.log(`${file}: ERROR - ${e.message}`);
  }
});

console.log('\n------------------------');
console.log(`TOTAL: ${totalTech} techniques, ${totalSub} sub-techniques`);
