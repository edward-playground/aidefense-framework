import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { detectTactic } from '../tactics/detect.js';

test('agent trace example disables automatic exception capture on both spans and retains private error telemetry', () => {
  const flatten = rows => rows.flatMap(row => [row, ...flatten(row.subTechniques || [])]);
  const control = flatten(detectTactic.techniques).find(row => row.id === 'AID-D-005.004');
  const guidance = control.implementationGuidance.find(row => row.id === 'AID-D-005.004-G002');
  const blocks = [...guidance.howTo.matchAll(/<pre><code[^>]*>([\s\S]*?)<\/code><\/pre>/g)];
  assert.equal(blocks.length, 1);
  const python = String.raw`
import contextlib, hashlib, hmac, html, json, sys, types
code = html.unescape(json.loads(sys.stdin.buffer.read().decode('utf-8', errors='strict')))
spans = []
class StatusCode:
    ERROR = 'ERROR'
class Status:
    def __init__(self, status_code, description=None):
        self.status_code, self.description = status_code, description
class Span:
    def __init__(self, name):
        self.name, self.attributes, self.events, self.status = name, {}, [], None
    def set_attribute(self, key, value): self.attributes[key] = value
    def record_exception(self, exc): self.events.append(str(exc))
    def set_status(self, status): self.status = status
class Tracer:
    @contextlib.contextmanager
    def start_as_current_span(self, name, **kwargs):
        assert kwargs.get('record_exception') is False, 'automatic exception events must be disabled'
        assert kwargs.get('set_status_on_exception') is False, 'automatic exception status text must be disabled'
        span = Span(name)
        spans.append(span)
        yield span
trace = types.ModuleType('opentelemetry.trace')
trace.get_tracer = lambda name: Tracer()
trace.Status, trace.StatusCode = Status, StatusCode
otel = types.ModuleType('opentelemetry')
otel.trace = trace
sys.modules.update({'opentelemetry': otel, 'opentelemetry.trace': trace})
ns = {'__name__': 'exact_framework_example'}
exec(compile(code, 'exact_framework_example.py', 'exec'), ns)
secret = 'SYNTHETIC_SENSITIVE_PAYLOAD'
key = b'test-only-correlation-key-at-least-32-bytes'
params = {'private': secret}
result = {'result': secret}
def tool(fn, candidate_key=key):
    return ns['run_tool_with_trace'](session_id='s1', agent_id='a1', tool_name='tool1',
        tool_call_id='c1', tool_params=params, policy_id='p1', evidence_ref='e1',
        correlation_key=candidate_key, correlation_key_id='test-v1', tool_callable=fn)
def agent(fn):
    return ns['run_agent_with_trace'](session_id='s1', agent_id='a1', provider_name='p1',
        model_id='m1', goal_id='g1', planner_callable=fn)
assert agent(lambda: tool(lambda: result)) is result
assert len(spans) == 2
expected = hmac.new(key, b'tool_params\x00' + json.dumps(params, sort_keys=True, default=str).encode('utf-8'), hashlib.sha256).hexdigest()
assert spans[1].attributes['aidefend.tool.params_hmac_sha256'] == expected
assert all(secret not in json.dumps(s.attributes) and not s.events for s in spans)
for planner_failure in [False, True]:
    spans.clear()
    error = type(secret, (Exception,), {})(secret)
    def fail(): raise error
    try:
        agent(fail if planner_failure else lambda: tool(fail))
    except Exception as actual:
        assert actual is error
    else: raise AssertionError('failure was swallowed')
    assert len(spans) == (1 if planner_failure else 2)
    for s in spans:
        assert not s.events
        assert s.status.status_code == StatusCode.ERROR and s.status.description is None
        assert secret not in json.dumps(s.attributes)
calls = []
try:
    tool(lambda: calls.append(True), b'short')
except ValueError: pass
else: raise AssertionError('invalid key accepted')
assert not calls
print('source-example-contract-pass; stdlib tracing test double; real SDK proof is separate')
`;
  const result = spawnSync('python', ['-I', '-S', '-c', python], {
    input: JSON.stringify(blocks[0][1]), encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.match(result.stdout, /source-example-contract-pass/);
});
