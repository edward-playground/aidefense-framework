import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { hardenTactic } from '../tactics/harden.js';

test('canonicalization examples preserve real Unicode fixtures and execute their declared expectations', () => {
  const flatten = rows => rows.flatMap(row => [row, ...flatten(row.subTechniques || [])]);
  const control = flatten(hardenTactic.techniques).find(row => row.id === 'AID-H-002.002');
  const guidance = control.implementationGuidance.find(row => row.id === 'AID-H-002.002-G002');
  const blocks = [...guidance.howTo.matchAll(/<pre><code[^>]*>([\s\S]*?)<\/code><\/pre>/g)]
    .map(match => match[1].replaceAll('&lt;', '<').replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"').replaceAll('&#39;', "'").replaceAll('&amp;', '&'));
  assert.equal(blocks.length, 3);
  const python = String.raw`
import ast, json, os, sys
blocks = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="strict"))
tree = ast.parse(blocks[2])
fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
               and n.name == "test_declared_canonical_forms")
pairs = ast.literal_eval(fixture.decorator_list[0].args[1])
assert len(pairs) == 4, "complete published fixture population required"
assert pairs[0] == ("\uff21\u200bB", "AB"), "fullwidth fixture was corrupted"
assert pairs[2] == ("cafe\u0301", "caf\u00e9"), "combining-mark expectation was corrupted"
os.environ["VERIFIED_H002_CANONICAL_INPUT_MAX_CHARS"] = "64"
namespace = {"__name__": "reference_canonicalizer"}
exec(compile(blocks[0], "canonicalize.py", "exec"), namespace)
canonicalize = namespace["canonicalize"]
for raw, expected in pairs:
    observed = canonicalize(raw)
    assert observed == expected, (ascii(raw), ascii(expected), ascii(observed))
    assert canonicalize(observed) == observed
for value, error in [("\u200b\u202e", ValueError), ("x" * 65, ValueError), (b"not-text", TypeError)]:
    try:
        canonicalize(value)
    except error:
        pass
    else:
        raise AssertionError("invalid input was admitted")
assert canonicalize("x" * 64) == "x" * 64
print(json.dumps({"published_fixtures": len(pairs), "invalid_inputs_rejected": 3, "idempotence_cases": len(pairs)}))
`;
  const result = spawnSync('python', ['-I', '-S', '-c', python], {
    input: JSON.stringify(blocks), encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.deepEqual(JSON.parse(result.stdout), {
    published_fixtures: 4, invalid_inputs_rejected: 3, idempotence_cases: 4,
  });
});
