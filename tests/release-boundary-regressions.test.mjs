import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { detectTactic } from '../tactics/detect.js';
import { evictTactic } from '../tactics/evict.js';
import { hardenTactic } from '../tactics/harden.js';
import { isolateTactic } from '../tactics/isolate.js';
import { modelTactic } from '../tactics/model.js';
import { restoreTactic } from '../tactics/restore.js';

function flatten(items) {
  return items.flatMap(item => [item, ...flatten(item.subTechniques || [])]);
}

const controls = new Map(
  [modelTactic, hardenTactic, detectTactic, isolateTactic, evictTactic, restoreTactic]
    .flatMap(tactic => flatten(tactic.techniques))
    .map(item => [item.id, item]),
);

function control(id) {
  const value = controls.get(id);
  assert.ok(value, `missing control ${id}`);
  return value;
}

function guidance(id, guidanceId) {
  const value = control(id).implementationGuidance?.find(item => item.id === guidanceId);
  assert.ok(value, `missing guidance ${guidanceId}`);
  return value;
}

function relatedIds(id) {
  return new Set(control(id).scopeBoundary?.relatedTechniques?.map(item => item.id) || []);
}

function codeBlocks(howTo, language) {
  const pattern = new RegExp(
    `<pre><code class="language-${language}">([\\s\\S]*?)</code></pre>`,
    'g',
  );
  return [...howTo.matchAll(pattern)].map(match => match[1]
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&amp;', '&'));
}

function assertPythonParses(source, label) {
  const result = spawnSync(
    'python',
    ['-c', 'import ast, sys; ast.parse(sys.stdin.read())'],
    { input: source, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, `${label}: ${result.stderr || result.stdout}`);
}

function assertPythonDriver(source, driver, label) {
  const result = spawnSync('python', ['-c', driver], {
    input: source,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `${label}: ${result.stderr || result.stdout}`);
}

function assertJavaScriptParses(source, label) {
  const directory = mkdtempSync(join(tmpdir(), 'aidefend-guidance-'));
  const file = join(directory, 'example.mjs');
  try {
    writeFileSync(file, source, 'utf8');
    const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${label}: ${result.stderr || result.stdout}`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('supply-chain examples use installable delivery claims and current schemas', () => {
  const workspace = control('AID-H-021.005').toolsOpenSource.find(
    item => item.includes('Workspace Guard'),
  );
  assert.match(workspace, /^ToppyMicroServices Workspace Guard \/ workspace-guard-scan/);
  assert.match(workspace, /not distributed through the npm registry/);
  assert.doesNotMatch(workspace, /^Workspace Guard workspace-guard-scan CLI/);

  const howTo = guidance('AID-H-003.001', 'AID-H-003.001-G003').howTo;
  assert.match(
    howTo,
    /sigstore\/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4\.1\.2/,
  );
  assert.doesNotMatch(howTo, /f713795cb21599bc4e5c4b58cbad1da852d7eeb9/);
  assert.match(howTo, /verifyImages:\n\s+- imageReferences:\n\s+- "my-registry\/my-ml-app:\*"/);
  assert.match(howTo, /attestors:\n\s+- entries:\n\s+- keyless:/);
  assert.doesNotMatch(howTo, /verifyImages:\n\s+- image:/);
});

test('working-state architecture and runtime context-store enforcement have one TTL owner', () => {
  const architecture = control('AID-H-017.004');
  const runtime = control('AID-I-004.001');
  const howTo = guidance('AID-H-017.004', 'AID-H-017.004-G001').howTo;

  assert.match(architecture.scopeBoundary.responsibility, /application-level statelessness/i);
  assert.match(architecture.scopeBoundary.responsibility, /does not own runtime context-store/i);
  assert.doesNotMatch(howTo, /create an isolated memory object with a strict TTL/i);
  assert.match(howTo, /TTL.*AID-I-004\.001/s);
  assert.match(runtime.scopeBoundary.responsibility, /TTL/);
  assert.ok(relatedIds('AID-H-017.004').has('AID-I-004.001'));
  assert.ok(relatedIds('AID-I-004.001').has('AID-H-017.004'));
});

test('MCP command handlers consume filesystem-broker receipts and never accept cwd', () => {
  const howTo = guidance('AID-H-034.003', 'AID-H-034.003-G005').howTo;
  assert.match(howTo, /AID-H-018\.009/);
  assert.match(howTo, /workspaceHandle/);
  assert.match(howTo, /receipt_signature_b64/);
  assert.match(howTo, /receipt\.exit_code !== 0/);
  assert.doesNotMatch(howTo, /runAllowedCommand\(commandId, cwd\)/);
  assert.doesNotMatch(howTo, /\bspawn\(/);
  assert.ok(relatedIds('AID-H-034.003').has('AID-H-018.009'));

  const blocks = codeBlocks(howTo, 'javascript');
  assert.ok(blocks.length > 0, 'H-034.003-G005 is missing its JavaScript example');
  blocks.forEach((source, index) => assertJavaScriptParses(
    source,
    `H-034.003-G005 JavaScript block ${index + 1}`,
  ));
});

test('artifact admission and independent drift detection cannot double-score one verification', () => {
  const integrity = control('AID-M-002.002');
  const detector = control('AID-D-004.001');
  const howTo = guidance('AID-D-004.001', 'AID-D-004.001-G001').howTo;

  assert.match(integrity.scopeBoundary.responsibility, /does not decide release promotion/i);
  assert.match(detector.name, /Re-verification & Drift Monitoring/);
  assert.match(detector.scopeBoundary.responsibility, /independently scheduled or event-triggered/i);
  assert.match(detector.scopeBoundary.responsibility, /does not create the authoritative digest/i);
  assert.ok(detector.phase.includes('operation'));
  assert.ok(relatedIds('AID-M-002.002').has('AID-D-004.001'));
  assert.ok(relatedIds('AID-D-004.001').has('AID-M-002.002'));
  assert.match(howTo, /Consume, do not recreate/);
  assert.match(howTo, /detector_status/);
  assert.doesNotMatch(howTo, /def build_manifest/);
});

test('RAG semantic concept monitoring is bound to the exact post-retrieval population', () => {
  const rag = control('AID-D-014.001');
  const method = guidance('AID-D-014.001', 'AID-D-014.001-G002');

  assert.match(rag.description, /exact post-retrieval population/i);
  assert.doesNotMatch(rag.description, /vector-store contents/i);
  assert.match(method.implementation, /exact ordered retrieval population/i);
  assert.doesNotMatch(method.implementation, /scheduled semantic similarity scans/i);
  assert.doesNotMatch(method.implementation, /before they are ever retrieved/i);
  assert.match(method.howTo, /Do not enumerate the vector store/i);
  assert.match(method.howTo, /expected_chunk_count/);
  assert.match(method.howTo, /seen_ranks != set\(range\(expected_count\)\)/);
  assert.match(method.howTo, /method_status/);
  assert.match(method.howTo, /"CLEAR".*"FINDING".*"INCOMPLETE".*"ERROR"/s);
  assert.doesNotMatch(method.howTo, /aidefend\.d014001-vector-hunt/);
});

test('new Python detector examples are syntactically executable', () => {
  for (const [controlId, guidanceId] of [
    ['AID-D-004.001', 'AID-D-004.001-G001'],
    ['AID-D-014.001', 'AID-D-014.001-G002'],
  ]) {
    const blocks = codeBlocks(guidance(controlId, guidanceId).howTo, 'python');
    assert.ok(blocks.length > 0, `${guidanceId} is missing its Python example`);
    blocks.forEach((source, index) => assertPythonParses(
      source,
      `${guidanceId} Python block ${index + 1}`,
    ));
  }
});

test('new detector cores pass positive, negative, and incomplete fixtures', () => {
  const driftSource = codeBlocks(
    guidance('AID-D-004.001', 'AID-D-004.001-G001').howTo,
    'python',
  )[0];
  assertPythonDriver(driftSource, `
import os, sys
os.environ.update({
    "D004001_MAX_FILES": "10",
    "D004001_MAX_FILE_BYTES": "1048576",
    "D004001_MAX_TOTAL_BYTES": "2097152",
    "D004001_MAX_MANIFEST_BYTES": "1048576",
})
namespace = {"__name__": "guidance_test"}
exec(compile(sys.stdin.read(), "d004001.py", "exec"), namespace)
assert namespace["safe_relative"]("models/adapter.bin") == "models/adapter.bin"
for unsafe in ("../adapter.bin", "models\\\\adapter.bin", "models/\\x00adapter.bin"):
    try:
        namespace["safe_relative"](unsafe)
    except namespace["DetectorError"]:
        pass
    else:
        raise AssertionError("unsafe manifest path was accepted: " + repr(unsafe))
`, 'AID-D-004.001 core fixtures');

  const retrievalSource = codeBlocks(
    guidance('AID-D-014.001', 'AID-D-014.001-G002').howTo,
    'python',
  )[0];
  assertPythonDriver(retrievalSource, `
import copy, json, sys
from datetime import datetime, timezone
namespace = {"__name__": "guidance_test"}
exec(compile(sys.stdin.read(), "d014001.py", "exec"), namespace)
encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
policy = {
    "schema_version": "aidefend.d014001-retrieved-concept-policy.v1",
    "policy_version": "policy-7",
    "embedding_model_id": "embedder",
    "embedding_model_revision": "sha256:revision",
    "maximum_chunks": 2,
    "maximum_concepts": 2,
    "vector_dimension": 2,
    "maximum_snapshot_age_seconds": 300,
    "maximum_future_skew_seconds": 5,
    "concept_thresholds": {"prompt-injection": 0.8},
}
retrieval = {
    "schema_version": "aidefend.d014001-retrieval-snapshot.v1",
    "request_id": "request-1",
    "retrieval_id": "retrieval-1",
    "asset_id": "kb-1",
    "asset_version": "version-9",
    "route_id": "support-rag",
    "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "collection_complete": True,
    "expected_chunk_count": 1,
    "embedding_model_id": "embedder",
    "embedding_model_revision": "sha256:revision",
    "chunks": [{
        "chunk_id": "chunk-1",
        "rank": 0,
        "content_sha256": "a" * 64,
        "vector": [1.0, 0.0],
    }],
}
concepts = {
    "schema_version": "aidefend.d014001-concept-set.v1",
    "embedding_model_id": "embedder",
    "embedding_model_revision": "sha256:revision",
    "concepts": [{"concept_id": "prompt-injection", "vector": [1.0, 0.0]}],
}
evaluate = namespace["evaluate"]
assert evaluate(encode(policy), encode(retrieval), encode(concepts))["method_status"] == "FINDING"
clear = copy.deepcopy(retrieval)
clear["chunks"][0]["vector"] = [0.0, 1.0]
assert evaluate(encode(policy), encode(clear), encode(concepts))["method_status"] == "CLEAR"
incomplete = copy.deepcopy(retrieval)
incomplete["collection_complete"] = False
assert evaluate(encode(policy), encode(incomplete), encode(concepts))["method_status"] == "INCOMPLETE"
bad_time = copy.deepcopy(retrieval)
bad_time["captured_at"] = "not-a-time"
try:
    evaluate(encode(policy), encode(bad_time), encode(concepts))
except namespace["InputError"]:
    pass
else:
    raise AssertionError("malformed timestamp was accepted")
`, 'AID-D-014.001 core fixtures');
});

test('inventory, agent admission, reasoning findings, and containment preserve handoffs', () => {
  const composition = control('AID-M-001.002');
  const compositionHowTo = guidance('AID-M-001.002', 'AID-M-001.002-G004').howTo;
  const reasoning = control('AID-D-002.005');
  const memoryFingerprint = guidance('AID-D-001.005', 'AID-D-001.005-G002');
  const quarantine = guidance('AID-I-003.001', 'AID-I-003.001-G001');

  assert.match(composition.scopeBoundary.responsibility, /agent and non-agent services/i);
  assert.ok(relatedIds('AID-M-001.002').has('AID-H-021.002'));
  assert.ok(relatedIds('AID-H-021.002').has('AID-M-001.002'));
  assert.doesNotMatch(compositionHowTo, /Action:<\/strong> Block promotion/);
  assert.match(compositionHowTo, /AID-H-003\.002.*promotion block/s);
  assert.match(reasoning.description, /untrusted input/i);
  assert.ok(relatedIds('AID-D-002.005').has('AID-I-003'));
  assert.doesNotMatch(memoryFingerprint.implementation, /blocked on future recall/i);
  assert.doesNotMatch(quarantine.implementation, /disable key\/account/i);
  assert.match(quarantine.implementation, /AID-E-001/);
});

test('registry telemetry and adjacent control seams have explicit primary owners', () => {
  const registry = control('AID-D-005.006');
  assert.equal(registry.name, 'Agent Registry & Resolution Telemetry Monitoring');
  assert.match(registry.description, /ANS.*named implementation driver/i);
  assert.ok(relatedIds('AID-D-005.006').has('AID-D-011.002'));
  assert.ok(relatedIds('AID-D-011.002').has('AID-D-005.006'));

  for (const [left, right] of [
    ['AID-H-004.005', 'AID-H-012.004'],
    ['AID-H-011.003', 'AID-H-015'],
    ['AID-H-021.005', 'AID-H-018.007'],
    ['AID-I-001.004', 'AID-I-002.002'],
    ['AID-I-003', 'AID-E-001'],
    ['AID-I-006', 'AID-R-001.002'],
    ['AID-I-007', 'AID-H-003.011'],
  ]) {
    assert.ok(relatedIds(left).has(right), `${left} is missing ${right}`);
    assert.ok(relatedIds(right).has(left), `${right} is missing ${left}`);
  }

  for (const expected of [
    'AID-H-034.001', 'AID-H-033.005', 'AID-D-004.008', 'AID-M-001.006',
  ]) {
    assert.ok(relatedIds('AID-H-038.001').has(expected), `H-038.001 is missing ${expected}`);
  }
  assert.equal(relatedIds('AID-H-038.001').has('AID-H-004.003'), false);
  assert.ok(relatedIds('AID-H-003.011').has('AID-H-013'));
  assert.ok(relatedIds('AID-H-003.011').has('AID-I-007'));
});
