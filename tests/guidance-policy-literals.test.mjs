import assert from 'node:assert/strict';
import test from 'node:test';

import {
    assertGuidanceId,
    findGuidancePolicyLiterals,
    findPolicyLiteralsInCode
} from '../scripts/audit-guidance-policy-literals.mjs';
import { modelTactic } from '../tactics/model.js';
import { restoreTactic } from '../tactics/restore.js';

function guidanceById(tactic, guidanceId) {
    const unit = tactic.techniques
        .flatMap(item => item.subTechniques || [item])
        .find(item => (item.implementationGuidance || [])
            .some(guidance => guidance.id === guidanceId));
    assert.ok(unit, `Unknown guidance ID: ${guidanceId}`);
    return unit.implementationGuidance.find(guidance => guidance.id === guidanceId);
}

test('implementation guidance contains no hard-coded policy deadlines or retry budgets', () => {
    const findings = findGuidancePolicyLiterals();
    assert.deepEqual(
        findings,
        [],
        `Policy literals must come from verified, versioned profiles:\n${JSON.stringify(findings, null, 2)}`
    );
});

test('policy-literal audit detects deadline and retry regressions', () => {
    const fixture = [
        'client(timeout=30)',
        'Config(connect_timeout=5, read_timeout=60)',
        'retries={"max_attempts": 3}',
        'MAXIMUM_TIMEOUT_SECONDS = 10',
        'timedelta(minutes=15)'
    ].join('\n');
    const rules = new Set(findPolicyLiteralsInCode(fixture).map(item => item.rule));

    assert.deepEqual(
        rules,
        new Set([
            'keyword_argument',
            'retry_argument',
            'constant_assignment',
            'fixed_duration'
        ])
    );
});

test('policy-literal audit fails closed on missing or misplaced guidance IDs', () => {
    assert.equal(
        assertGuidanceId({ id: 'AID-H-021.005-G001' }, 'AID-H-021.005', 0),
        'AID-H-021.005-G001'
    );
    assert.throws(
        () => assertGuidanceId({}, 'AID-H-021.005', 0),
        /expected canonical guidance ID AID-H-021\.005-G001; found missing/
    );
    assert.throws(
        () => assertGuidanceId({ id: 'AID-H-021.005-G002' }, 'AID-H-021.005', 0),
        /expected canonical guidance ID AID-H-021\.005-G001/
    );
    assert.throws(
        () => assertGuidanceId({ id: 'AID-H-018.009-G001' }, 'AID-H-021.005', 0),
        /expected canonical guidance ID AID-H-021\.005-G001/
    );
});

test('reviewed deadline and retry fixes remain bound to verified profiles', () => {
    const skillDecision = guidanceById(modelTactic, 'AID-M-001.003-G002').howTo;
    assert.match(skillDecision, /SKILL_DECISION_VERIFY_TIMEOUT_SECONDS/);
    assert.match(skillDecision, /timeout=COMMAND_TIMEOUT_SECONDS/);
    assert.match(skillDecision, /runtime_profile_sha256/);

    const missionBoot = guidanceById(modelTactic, 'AID-M-003.004-G004').howTo;
    assert.match(missionBoot, /sqlite_busy_timeout_seconds: float/);
    assert.match(missionBoot, /timeout=profile\.sqlite_busy_timeout_seconds/);

    const providerRecovery = guidanceById(restoreTactic, 'AID-R-001.001-G002').howTo;
    assert.match(providerRecovery, /"maximum_retry_attempts": 3/);
    assert.match(providerRecovery, /runtime\["maximum_retry_attempts"\]/);
    assert.match(providerRecovery, /"max_attempts": maximum_retry_attempts/);

    const recoveryTraining = guidanceById(restoreTactic, 'AID-R-001.002-G001').howTo;
    assert.match(recoveryTraining, /R001_INPUT_MAXIMUM_RETRY_ATTEMPTS/);
    assert.match(recoveryTraining, /connect_timeout=CONNECT_TIMEOUT/);
    assert.match(recoveryTraining, /read_timeout=READ_TIMEOUT/);
    assert.match(recoveryTraining, /"max_attempts": MAXIMUM_RETRY_ATTEMPTS/);
});
