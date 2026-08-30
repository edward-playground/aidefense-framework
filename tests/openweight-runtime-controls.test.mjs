import assert from 'node:assert/strict';
import test from 'node:test';

import { detectTactic } from '../tactics/detect.js';
import { hardenTactic } from '../tactics/harden.js';
import { modelTactic } from '../tactics/model.js';

function flatten(tactic) {
  return tactic.techniques.flatMap(technique => [
    technique,
    ...(technique.subTechniques || []),
  ]);
}

const harden = new Map(flatten(hardenTactic).map(item => [item.id, item]));
const detect = new Map(flatten(detectTactic).map(item => [item.id, item]));
const model = new Map(flatten(modelTactic).map(item => [item.id, item]));

test('inference serving governance preserves two independently scoreable boundaries', () => {
  const parent = harden.get('AID-H-038');
  assert.deepEqual(parent.subTechniques.map(item => item.id), [
    'AID-H-038.001',
    'AID-H-038.002',
  ]);
  for (const forbidden of [
    'pillar', 'phase', 'toolsOpenSource', 'toolsSourceAvailable',
    'toolsCommercial', 'implementationGuidance',
  ]) {
    assert.equal(forbidden in parent, false, `parent unexpectedly owns ${forbidden}`);
  }

  const surface = harden.get('AID-H-038.001');
  const privilege = harden.get('AID-H-038.002');
  assert.match(surface.scopeBoundary.responsibility, /process-level enumeration/i);
  assert.match(surface.scopeBoundary.responsibility, /does not own TLS\/mTLS/i);
  assert.match(surface.description, /KV-transfer listeners/);
  assert.doesNotMatch(surface.description, /HTTP\/gRPC/);
  assert.match(privilege.scopeBoundary.responsibility, /operation-level authorization/i);
  assert.match(privilege.description, /authoritative state readback/i);
  assert.match(privilege.implementationGuidance[0].howTo, /duplicate or shadowed runtime route/);

  const surfaceOwasp = surface.defendsAgainst.find(
    mapping => mapping.framework === 'OWASP LLM Top 10 2026',
  );
  assert.deepEqual(surfaceOwasp.items, ['N/A']);
  const privilegeOwasp = privilege.defendsAgainst.find(
    mapping => mapping.framework === 'OWASP LLM Top 10 2026',
  );
  assert.deepEqual(privilegeOwasp.items, [
    'LLM05:2026 Data and Model Poisoning',
    'LLM06:2026 Unbounded Consumption (operation authorization prevents untrusted callers from changing serving capacity or execution state, while request budgets and rate limits remain separate)',
  ]);
});

test('reasoning semantic monitoring remains distinct from metadata and visible output', () => {
  const semantic = detect.get('AID-D-002.005');
  const metadata = detect.get('AID-D-002.004');
  const visibleOutput = detect.get('AID-D-003.001');

  assert.match(semantic.description, /complete emitted trace/i);
  assert.match(semantic.description, /not proof of the model's hidden intent/i);
  assert.match(semantic.warning.description, /not a faithful transcript/i);
  assert.match(semantic.warning.description, /not automatically feed/i);
  assert.match(metadata.scopeBoundary.responsibility, /does not semantically judge/i);
  assert.match(visibleOutput.scopeBoundary.responsibility, /intended for display or downstream/i);
  assert.match(visibleOutput.scopeBoundary.responsibility, /does not inspect a non-user-facing emitted reasoning channel/i);

  const howTo = semantic.implementationGuidance[0].howTo;
  assert.match(howTo, /complete_input/);
  assert.match(howTo, /label.*severity.*digest.*reference/s);
  assert.match(howTo, /load_cert_chain/);
  assert.match(howTo, /maximum_response_bytes/);

  const owaspLlm = semantic.defendsAgainst.find(
    mapping => mapping.framework === 'OWASP LLM Top 10 2026',
  );
  assert.equal(owaspLlm.items.length, 1);
  assert.match(owaspLlm.items[0], /^LLM01:2026 Prompt Injection/);
  assert.doesNotMatch(owaspLlm.items[0], /Sensitive Information Disclosure/);
});

test('white-box probes and provider log probabilities stay with existing owners', () => {
  const distribution = detect.get('AID-D-002.001');
  const internals = detect.get('AID-D-002.003');

  assert.match(distribution.scopeBoundary.responsibility, /token-probability distributions/i);
  assert.match(distribution.scopeBoundary.responsibility, /does not claim access to hidden logits/i);
  assert.match(internals.scopeBoundary.responsibility, /Provider-returned top-k log probabilities remain/i);
  assert.match(internals.implementationGuidance.at(-1).howTo, /quantization configuration digest/i);
  assert.match(internals.implementationGuidance.at(-1).howTo, /AWQ, GPTQ, GGUF, FP8/);
});

test('edge model key release is attestation, entitlement, release, and recipient bound', () => {
  const edge = harden.get('AID-H-003.011');
  const howTo = edge.implementationGuidance[0].howTo;

  assert.match(edge.scopeBoundary.responsibility, /fresh platform-attestation enforcement/i);
  assert.match(edge.warning.description, /cannot guarantee that plaintext weights remain secret/i);
  for (const binding of [
    'challenge_id', 'subject', 'release_sha256', 'recipient_key',
    'expires_at', 'policy_sha256',
  ]) {
    assert.match(howTo, new RegExp(binding));
  }
  assert.match(howTo, /allowed_app_versions/);
  assert.match(howTo, /allowed_attestation_platforms/);
  assert.match(howTo, /NOT_APPLICABLE/);
  assert.match(howTo, /INSUFFICIENT_DATA/);

  const nist = edge.defendsAgainst.find(
    mapping => mapping.framework === 'NIST Adversarial Machine Learning 2025',
  );
  assert.deepEqual(nist.items, ['N/A']);
});

test('model-interface composition has one release owner and separate parser and drift checks', () => {
  const composition = model.get('AID-M-001.002');
  const releaseGate = harden.get('AID-H-003.002');
  const parser = harden.get('AID-H-006.001');
  const regression = harden.get('AID-H-007.006');
  const drift = detect.get('AID-D-004.003');

  assert.match(composition.scopeBoundary.responsibility, /release-bound model-interface tuple/i);
  assert.match(composition.implementationGuidance.at(-1).howTo, /explicit_container_command/);
  assert.match(releaseGate.description, /tokenizer, chat template, generation configuration, or parser/i);
  assert.match(parser.scopeBoundary.responsibility, /deterministic conformance/i);
  assert.match(parser.implementationGuidance.at(-1).howTo, /parse\(chunks: list\[str\]\)/);
  assert.match(regression.description, /serving-time model\/interface pairing/i);
  assert.match(drift.scopeBoundary.responsibility, /model-interface composition/i);
});
