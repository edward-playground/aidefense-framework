import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { aidefendData } from '../main.js';
import { ciscoFramework } from '../cisco-framework.js';

const names = new Map(ciscoFramework.activeItems.map(item => [item.id, `${item.id} ${item.name}`]));
const entities = aidefendData.tactics.flatMap(t => t.techniques.flatMap(e => [e, ...(e.subTechniques || [])]));
const itemsFor = entity => entity.defendsAgainst.find(m => m.framework === ciscoFramework.frameworkKey).items;
function canonical(item) {
    if (item === 'N/A') return item;
    const id = item.split(' ')[0];
    const name = names.get(id);
    assert.ok(name, `Unknown or retired Cisco v2 ID: ${item}`);
    assert.ok(item === name || item.startsWith(`${name} (`), `Cisco v2 name/meaning mismatch: ${item}`);
    return name;
}

test('Cisco current catalog has unique v2 IDs and complete parent relationships', () => {
    assert.equal(ciscoFramework.version, '2.0.0');
    assert.deepEqual(ciscoFramework.counts, { objectives: 19, techniques: 41, subtechniques: 115 });
    assert.equal(names.size, 156);
    const objectives = new Set(ciscoFramework.groups.map(group => group.id));
    assert.equal(objectives.size, 19);
    for (const item of ciscoFramework.activeItems) {
        if (item.id.startsWith('AITech-')) {
            assert.ok(objectives.has(item.parentObjective), item.id);
        } else {
            assert.match(item.id, /^AISubtech-\d+\.\d+\.\d+$/);
            assert.ok(names.has(item.parentTechnique), item.id);
        }
    }
});

test('Cisco reused IDs resolve only to their v2 concepts', () => {
    assert.equal(names.get('AITech-1.3'), 'AITech-1.3 Multimodal Injection and Manipulation');
    assert.equal(names.get('AITech-2.1'), 'AITech-2.1 Excessive Agency');
    assert.equal(names.get('AISubtech-2.1.1'), 'AISubtech-2.1.1 Execution Approval Bypass');
    assert.equal(names.get('AISubtech-15.1.25'), 'AISubtech-15.1.25 General Harms');
    for (const retired of ['AITech-1.4', 'AISubtech-1.2.1', 'AISubtech-2.1.3']) {
        assert.ok(!names.has(retired), retired);
    }
});

test('every authored Cisco mapping uses a current canonical ID and name', () => {
    for (const entity of entities) {
        const items = itemsFor(entity);
        assert.ok(items.length > 0, entity.id);
        assert.equal(new Set(items.map(canonical)).size, items.length, entity.id);
        if (items.includes('N/A')) assert.deepEqual(items, ['N/A'], entity.id);
    }
});

test('Cisco parent families contain exactly the canonical child union', () => {
    for (const entity of entities.filter(e => e.subTechniques?.length)) {
        const union = [...new Set(entity.subTechniques.flatMap(itemsFor).filter(i => i !== 'N/A').map(canonical))];
        assert.deepEqual(itemsFor(entity).map(canonical).sort(), (union.length ? union : ['N/A']).sort(), entity.id);
    }
});

test('Cisco mapping boundaries reject reused meanings and unsupported attack inferences', () => {
    const idsFor = id => itemsFor(entities.find(e => e.id === id)).map(item => item.split(' ')[0]);
    for (const [control, rejected] of [
        ['AID-D-001.002', ['AISubtech-1.3.1', 'AISubtech-1.3.3']],
        ['AID-D-012.001', ['AITech-9.2']],
        ['AID-H-014', ['AITech-11.2', 'AISubtech-11.2.2']],
        ['AID-DV-004', ['AITech-10.2']],
        ['AID-H-018.009', ['AISubtech-9.1.1']]
    ]) {
        for (const id of rejected) assert.ok(!idsFor(control).includes(id), `${control} must not infer ${id}`);
    }
    assert.ok(idsFor('AID-D-009.001').includes('AISubtech-15.1.5'), 'Fact verification follows the official disinformation definition');
    assert.ok(idsFor('AID-D-012.001').includes('AISubtech-9.2.2'), 'Backdoor testing maps independently of the misleading numeric parent');
    for (const control of ['AID-D-001.003', 'AID-D-011.001']) {
        assert.deepEqual(idsFor(control), ['N/A'], `${control}: generic anomaly scores do not establish a Cisco attack`);
    }
    for (const [control, admitted] of [
        ['AID-D-009.001', 'AISubtech-15.1.19'],
        ['AID-D-009.002', 'AISubtech-15.1.19'],
        ['AID-D-014.002', 'AISubtech-6.1.1'],
        ['AID-M-002.004', 'AISubtech-6.1.1'],
        ['AID-E-003.001', 'AISubtech-9.2.2'],
        ['AID-E-003.002', 'AITech-6.1'],
        ['AID-DV-003', 'AISubtech-10.1.1'],
        ['AID-H-018.009', 'AISubtech-11.1.2'],
        ['AID-H-033.006', 'AISubtech-10.1.2']
    ]) assert.ok(idsFor(control).includes(admitted), `${control}: bounded direct mechanism supports ${admitted}`);
    for (const control of ['AID-H-018.008', 'AID-H-018.003', 'AID-H-018.006', 'AID-H-017.001', 'AID-H-017.006', 'AID-M-009.003']) {
        assert.ok(!idsFor(control).includes('AITech-4.3'), `${control}: replay or delegation does not inherit protocol-manipulation parent`);
    }
    assert.ok(!idsFor('AID-H-004.004').includes('AISubtech-4.3.3'), 'source binding alone does not prevent DNS rebinding');
});

test('website and distributed Cisco catalog use the same v2 source', () => {
    const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    assert.match(html, /import \{ ciscoFramework \} from '\.\/cisco-framework\.js'/);
    assert.match(html, /'cisco':\s*\{\s*\.\.\.ciscoFramework,/);
    assert.match(html, /Cisco Integrated AI Security &amp; Safety Framework v2\.0/);
    assert.deepEqual(JSON.parse(fs.readFileSync(new URL('../data/cisco-framework.json', import.meta.url), 'utf8')), ciscoFramework);
});
