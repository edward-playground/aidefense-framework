import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {modelTactic} from '../tactics/model.js';
import {detectTactic} from '../tactics/detect.js';

function guidance(tactic, controlId, guidanceId) {
  const control = tactic.techniques.flatMap(x => [x, ...(x.subTechniques || [])])
    .find(x => x.id === controlId);
  return control.implementationGuidance.find(x => x.id === guidanceId);
}
function pythonBlocks(howTo) {
  return [...howTo.matchAll(/<pre><code class="language-python">([\s\S]*?)<\/code><\/pre>/g)]
    .map(x => x[1].replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&'));
}
const builder = guidance(modelTactic, 'AID-M-003.005', 'AID-M-003.005-G001');
const lifecycle = guidance(modelTactic, 'AID-M-003.005', 'AID-M-003.005-G002');
const detector = guidance(detectTactic, 'AID-D-001.002', 'AID-D-001.002-G005');
const [runtimeSource, builderSource] = pythonBlocks(builder.howTo);
const [detectorSource] = pythonBlocks(detector.howTo);
const python = process.env.AIDEFEND_GUIDANCE_PYTHON || 'python';
const fixture = fileURLToPath(new URL('./fixtures/reconstruction-reference.py', import.meta.url));

function run(mode) {
  const result = spawnSync(python, [fixture, mode], {
    input: JSON.stringify({runtimeSource, builderSource, detectorSource}),
    encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  return result.stdout;
}

test('published reconstruction examples parse and reject incompatible, expired and incomplete references', () => {
  assert.ok(runtimeSource && builderSource && detectorSource);
  assert.match(run('contract'), /CONTRACT_OK/);
});

test('reconstruction verification binds captured bytes and cannot silently accept failed signatures', () => {
  assert.match(run('verification'), /VERIFICATION_OK/);
});

const dependencies = spawnSync(python, ['-c', 'import torch, numpy, PIL'], {windowsHide: true}).status === 0;
test('actual CPU builder output is consumed by the actual detector with the same reconstruction and preprocessing', {
  skip: dependencies ? false : 'Install the example dependencies (torch, numpy, Pillow) in AIDEFEND_GUIDANCE_PYTHON',
}, () => {
  assert.match(run('numerical'), /NUMERICAL_HANDOFF_OK/);
});

test('reconstruction lifecycle includes preprocessing rollback and separates renewal from recalibration', () => {
  assert.match(lifecycle.howTo, /Expiry is not itself a reason to retrain, recalibrate or move a threshold/);
  assert.match(lifecycle.howTo, /rollback must restore preprocessing as well as model and reference/);
  assert.match(lifecycle.howTo, /must not revive an expired reference/);
  assert.match(builder.howTo, /legacy v1 artifacts require a measured rebuild/);
  assert.doesNotMatch(detectorSource, /generator\(inverter\.project/);
});
