#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deceiveTactic } from '../tactics/deceive.js';
import { detectTactic } from '../tactics/detect.js';
import { evictTactic } from '../tactics/evict.js';
import { hardenTactic } from '../tactics/harden.js';
import { isolateTactic } from '../tactics/isolate.js';
import { modelTactic } from '../tactics/model.js';
import { restoreTactic } from '../tactics/restore.js';

const tactics = [
    ['model', modelTactic],
    ['harden', hardenTactic],
    ['detect', detectTactic],
    ['isolate', isolateTactic],
    ['deceive', deceiveTactic],
    ['evict', evictTactic],
    ['restore', restoreTactic]
];

const CONTROL_ID_PATTERN = /^AID-(?:DV|M|H|D|I|E|R)-[0-9]{3}(?:\.[0-9]{3})?$/;

const rules = [
    ['keyword_argument', /\b(?:timeout|connect_timeout|read_timeout|write_timeout|total_timeout|max_age|ttl|retention|freshness|expires_in)\s*=\s*\d+(?:\.\d+)?\b/gi],
    ['retry_argument', /\b(?:max_attempts|max_retries|total_max_attempts)\s*["']?\s*[:=]\s*\d+(?:\.\d+)?\b/gi],
    ['retry_count', /\bretries\s*=\s*\d+\b/gi],
    ['constant_assignment', /\b[A-Z][A-Z0-9_]*(?:TIMEOUT|TTL|RETENTION|FRESHNESS|MAX_AGE|EXPIRY)[A-Z0-9_]*\s*=\s*\d+(?:\.\d+)?\b/g],
    ['typed_default', /\b(?:timeout|connect_timeout|read_timeout|write_timeout|total_timeout|max_age|ttl|retention|freshness|expires_in)[a-zA-Z0-9_]*\s*:\s*[^=,\n]+\s*=\s*\d+(?:\.\d+)?\b/g],
    ['curl_max_time', /--max-time\s+\d+(?:\.\d+)?\b/g],
    ['timeout_constructor', /\b(?:Timeout|ClientTimeout)\(\s*\d+(?:\.\d+)?\b/g],
    ['fixed_duration', /\btimedelta\(\s*(?:days|hours|minutes|seconds)\s*=\s*\d+(?:\.\d+)?\b/g]
];

function decodeHtml(source) {
    return source
        .replaceAll('&gt;', '>')
        .replaceAll('&lt;', '<')
        .replaceAll('&amp;', '&')
        .replaceAll('&quot;', '"')
        .replaceAll('&#39;', "'");
}

function displayValue(value) {
    if (value === undefined) return 'missing';
    if (value === null) return 'null';
    return JSON.stringify(value);
}

export function assertGuidanceId(guidance, ownerControlId, guidanceIndex) {
    const context = `${ownerControlId} guidance ${guidanceIndex + 1}`;
    if (!CONTROL_ID_PATTERN.test(String(ownerControlId || ''))) {
        throw new Error(`${context}: invalid owning control ID ${displayValue(ownerControlId)}`);
    }
    if (!Number.isInteger(guidanceIndex) || guidanceIndex < 0) {
        throw new Error(`${context}: guidance index must be a non-negative integer`);
    }
    if (!guidance || typeof guidance !== 'object' || Array.isArray(guidance)) {
        throw new Error(`${context}: guidance entry must be an object with an explicit id`);
    }

    const expectedId = `${ownerControlId}-G${String(guidanceIndex + 1).padStart(3, '0')}`;
    if (guidance.id !== expectedId) {
        throw new Error(
            `${context}: expected canonical guidance ID ${expectedId}; found ${displayValue(guidance.id)}`
        );
    }
    return guidance.id;
}

export function findPolicyLiteralsInCode(code) {
    const findings = [];
    for (const [rule, pattern] of rules) {
        pattern.lastIndex = 0;
        for (const match of code.matchAll(pattern)) {
            findings.push({
                rule,
                match: match[0],
                line: code.slice(0, match.index).split(/\r?\n/).length
            });
        }
    }
    return findings;
}

export function findGuidancePolicyLiterals() {
    const findings = [];
    for (const [tacticName, tactic] of tactics) {
        const units = tactic.techniques.flatMap(item => item.subTechniques || [item]);
        for (const unit of units) {
            for (const [guidanceIndex, guidance] of (unit.implementationGuidance || []).entries()) {
                const guidanceRef = assertGuidanceId(guidance, unit.id, guidanceIndex);
                const blocks = [
                    ...String(guidance.howTo || '').matchAll(
                        /<pre><code(?:\s[^>]*)?>([\s\S]*?)<\/code><\/pre>/gi
                    )
                ];
                for (const [blockIndex, block] of blocks.entries()) {
                    const code = decodeHtml(block[1]);
                    for (const finding of findPolicyLiteralsInCode(code)) {
                        findings.push({
                            ref: `${guidanceRef}/code-${blockIndex + 1}:${finding.line}`,
                            tactic: tacticName,
                            rule: finding.rule,
                            match: finding.match
                        });
                    }
                }
            }
        }
    }
    return findings;
}

export function policyLiteralAuditReport() {
    const findings = findGuidancePolicyLiterals();
    const byTactic = {};
    const byRule = {};
    for (const finding of findings) {
        byTactic[finding.tactic] = (byTactic[finding.tactic] || 0) + 1;
        byRule[finding.rule] = (byRule[finding.rule] || 0) + 1;
    }
    return {
        summary: { findings: findings.length, byTactic, byRule },
        findings
    };
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath && fileURLToPath(import.meta.url) === invokedPath) {
    const report = policyLiteralAuditReport();
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.findings.length ? 1 : 0;
}
