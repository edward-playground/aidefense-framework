import assert from 'node:assert/strict';
import test from 'node:test';

import { deceiveTactic } from '../tactics/deceive.js';
import { detectTactic } from '../tactics/detect.js';
import { evictTactic } from '../tactics/evict.js';
import { hardenTactic } from '../tactics/harden.js';
import { isolateTactic } from '../tactics/isolate.js';
import { modelTactic } from '../tactics/model.js';
import { restoreTactic } from '../tactics/restore.js';

const tactics = [
    modelTactic,
    hardenTactic,
    detectTactic,
    isolateTactic,
    deceiveTactic,
    evictTactic,
    restoreTactic
];

function units() {
    return tactics.flatMap(tactic =>
        tactic.techniques.flatMap(technique => [
            technique,
            ...(technique.subTechniques || [])
        ])
    );
}

function guidanceById(id) {
    for (const unit of units()) {
        const guidance = (unit.implementationGuidance || []).find(item => item.id === id);
        if (guidance) return guidance;
    }
    throw new Error(`Unknown guidance ID: ${id}`);
}

function codeBlocks(howTo) {
    return [...howTo.matchAll(/<pre><code(?:\s[^>]*)?>([\s\S]*?)<\/code><\/pre>/gi)]
        .map(match => match[1]);
}

test('every tactics howTo has balanced, extractable code-block markup', () => {
    for (const unit of units()) {
        for (const guidance of unit.implementationGuidance || []) {
            const howTo = String(guidance.howTo || '');
            const openings = [...howTo.matchAll(/<pre><code(?:\s[^>]*)?>/gi)].length;
            const closings = [...howTo.matchAll(/<\/code><\/pre>/gi)].length;
            const extracted = codeBlocks(howTo);

            assert.equal(openings, closings, `${guidance.id} has unbalanced code markup`);
            assert.equal(extracted.length, openings, `${guidance.id} has an unextractable code block`);
            for (const [index, block] of extracted.entries()) {
                assert.ok(block.length > 0, `${guidance.id} code block ${index + 1} is empty`);
                assert.doesNotMatch(
                    block,
                    /<pre><code|<\/code><\/pre>/i,
                    `${guidance.id} code block ${index + 1} contains nested or premature markup`
                );
            }
        }
    }
});

test('timeout comparisons survive authoritative HTML extraction without truncation', () => {
    const affected = [
        'AID-E-002-G001',
        'AID-E-003.002-G001',
        'AID-E-003.005-G001',
        'AID-E-003.005-G002',
        'AID-E-003.005-G003',
        'AID-H-031.003-G001',
        'AID-R-001.002-G003',
        'AID-R-001.002-G004'
    ];

    for (const unit of units()) {
        for (const guidance of unit.implementationGuidance || []) {
            assert.doesNotMatch(
                String(guidance.howTo || ''),
                /COMMAND_TIMEOUT_SECONDS\s*</,
                `${guidance.id} contains an unsafe raw HTML comparison`
            );
        }
    }

    for (const id of affected) {
        const guidance = guidanceById(id);
        assert.doesNotMatch(
            guidance.howTo,
            /COMMAND_TIMEOUT_SECONDS\s*<[^&]/,
            `${id} contains an unsafe raw HTML comparison`
        );
        assert.match(
            guidance.howTo,
            /COMMAND_TIMEOUT_SECONDS[^\n]*&lt;/,
            `${id} lost the escaped timeout comparison`
        );

        const matchingBlock = codeBlocks(guidance.howTo).find(block =>
            /COMMAND_TIMEOUT_SECONDS[^\n]*&lt;/.test(block)
        );
        assert.ok(matchingBlock, `${id} timeout code block was truncated during extraction`);
        const decoded = matchingBlock.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');
        assert.match(decoded, /COMMAND_TIMEOUT_SECONDS[^\n]*</);
        assert.match(decoded, /raise (?:RuntimeError|SystemExit)/, `${id} lost code after the comparison`);
    }
});

test('signed incident identifiers cannot escape the evidence directory', () => {
    const guidance = guidanceById('AID-E-001.001-G003');

    assert.match(
        guidance.howTo,
        /incident_id.*test\(\\?"\^\[A-Za-z0-9\]\[A-Za-z0-9\._-\]\{0,127\}\$\\?"\)/s
    );
    assert.doesNotMatch(
        guidance.howTo,
        /incident_id.*type == \\"string\\" and length &gt; 0/s
    );
});
