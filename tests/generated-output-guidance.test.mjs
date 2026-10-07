import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { detectTactic } from '../tactics/detect.js';

function find(items, id) {
  for (const item of items) {
    if (item.id === id) return item;
    const nested = find(item.subTechniques || [], id);
    if (nested) return nested;
  }
}

const control = find(detectTactic.techniques, 'AID-D-003.008');
const sources = control.implementationGuidance.map(guidance => {
  const blocks = [...guidance.howTo.matchAll(/<pre><code class="language-python">([\s\S]*?)<\/code><\/pre>/g)];
  assert.equal(blocks.length, 1, `${guidance.id} must contain one executable Python example`);
  return blocks[0][1].replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');
});

// Execute the actual rendered examples. ZIP handling and snapshot I/O are real;
// external parser/scanner responses are controlled fixtures, not deployment proof.
const setup = String.raw`
import copy, hashlib, io, json, os, struct, subprocess, sys, tempfile, types, zipfile
from dataclasses import replace
from pathlib import Path

modules = []
for name, source in zip(('generated_artifact_probe', 'generated_artifact_scanners', 'generated_artifact_rollup'), json.load(sys.stdin)):
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, name, 'exec'), module.__dict__)
    modules.append(module)
probe, scanner, rollup = modules

policy = dict(policy_version='policy-1', probe_revision='probe-1', tika_app_jar='tika.jar',
    allowed_media_types=['application/zip', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'image/png', 'application/pdf'],
    allowed_codecs=['png', 'pcm_s16le'], maximum_artifact_bytes=100000,
    maximum_member_bytes=50000, maximum_expanded_bytes=100000, maximum_members=20,
    maximum_depth=4, maximum_expansion_ratio=1000, maximum_width=100,
    maximum_height=100, maximum_pixels=10000, maximum_media_streams=3,
    maximum_duration_seconds=10, maximum_decoded_bytes=10000,
    maximum_decoded_packets=100, maximum_tool_output_bytes=10000,
    population_timeout_seconds=10, probe_timeout_seconds=3)

def result(code=0, out='', err=''):
    return subprocess.CompletedProcess([], code, out, err)

def parser(command, timeout, output_limit):
    assert timeout > 0 and output_limit > 0
    if command[0] == 'java':
        data = Path(command[-1]).read_bytes()
        kind = 'application/zip' if data.startswith(b'PK') else 'image/png' if data.startswith(b'PNG') else 'application/pdf' if data.startswith(b'%PDF') else 'text/plain'
        return result(out=kind + '\n')
    if command[0] == 'ffprobe':
        return result(out=json.dumps({'streams': [{'codec_type':'video','codec_name':'png','width':2,'height':2}], 'format':{}}))
    if command[0] == 'ffmpeg':
        assert '-xerror' in command and command[command.index('-map')+1] == '0'
        assert '-t' not in command and '-frames:v' not in command
        return result(out='#tb 0: 1/25\n0, 0, 0, 1, 12, 0x00000000\n')
    raise AssertionError(command)

real_probe_run = probe.run
probe.run = parser

def archive(entries, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as handle:
        for name, value in entries:
            handle.writestr(name, value)
    return output.getvalue()

def manifest(root):
    files = sorted(path for path in root.rglob('*') if path.is_file())
    return dict(schema_version='aidefend.generated-output-manifest.v1', manifest_id='manifest-1', expected_count=len(files),
        artifacts=[dict(artifact_id='artifact-'+str(i), relative_path=p.relative_to(root).as_posix(), sha256=hashlib.sha256(p.read_bytes()).hexdigest(), declared_media_type='application/zip') for i,p in enumerate(files)])

def inspect(data, selected_policy=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root/'output.bin').write_bytes(data)
        with probe.probe_population(root, manifest(root), selected_policy or policy) as population:
            saved = copy.deepcopy(population)
            for unit in saved['units']:
                if 'snapshot_path' in unit:
                    unit['snapshot_bytes'] = Path(unit['snapshot_path']).read_bytes()
            return saved

def gap(call):
    try:
        call()
    except (ValueError, OSError, RuntimeError):
        return
    raise AssertionError('expected visible error or coverage gap')

def binding(artifact='root', detector='probe', digest=None):
    return dict(manifest_id='manifest-1', artifact_id=artifact, artifact_sha256=digest or 'a'*64,
        probe_revision='probe-1', policy_version='policy-1', detector=detector,
        detector_version='detector-1', rule_version='rules-1')

def receipt(bound, control='PASS', finding='NO_FINDING', **extra):
    return dict(bound, control_status=control, finding_status=finding, **extra)
`;

function execute(driver) {
  const outcome = spawnSync('python', ['-c', setup + '\n' + driver], {
    input: JSON.stringify(sources), encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
  });
  assert.equal(outcome.status, 0, outcome.error?.message || outcome.stderr || outcome.stdout);
}

test('generated-output probe enumerates immutable ZIP, Office ZIP and nested members', () => execute(String.raw`
nested = archive([('inner.txt', b'inner text')])
data = archive([('[Content_Types].xml', b'<Types/>'), ('word/document.xml', b'<document/>'), ('nested.zip', nested)])
population = inspect(data)
assert population['status'] == 'PASS'
assert len(population['units']) == 5
assert {u.get('member_name') for u in population['units']} >= {'word/document.xml', 'nested.zip', 'inner.txt'}
assert len({u['artifact_id'] for u in population['units']}) == 5
for unit in population['units']:
    assert hashlib.sha256(unit['snapshot_bytes']).hexdigest() == unit['sha256']
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    target = root/'result.txt'
    target.write_bytes(b'original bytes')
    declared = manifest(root)
    with probe.probe_population(root, declared, policy) as population:
        target.write_bytes(b'replaced after probing')
        assert Path(population['units'][0]['snapshot_path']).read_bytes() == b'original bytes'
    (root/'extra.txt').write_text('extra')
    gap(lambda: probe.probe_population(root, declared, policy).__enter__())
    duplicate = manifest(root)
    duplicate['artifacts'][1]['artifact_id'] = duplicate['artifacts'][0]['artifact_id']
    gap(lambda: probe.probe_population(root, duplicate, policy).__enter__())
    wrong_digest = manifest(root)
    wrong_digest['artifacts'][0]['sha256'] = '0'*64
    with probe.probe_population(root, wrong_digest, policy) as population:
        assert population['status'] == 'INSUFFICIENT_DATA'
`));

test('generated-output probe never clears encrypted, unsafe, truncated or over-limit members', () => execute(String.raw`
data = bytearray(archive([('secret.txt', b'private')]))
local = data.index(b'PK\x03\x04')
central = data.index(b'PK\x01\x02')
for offset in (local+6, central+8):
    struct.pack_into('<H', data, offset, struct.unpack_from('<H', data, offset)[0] | 1)
encrypted = inspect(bytes(data))
assert encrypted['status'] == 'INSUFFICIENT_DATA'
assert any(u.get('reason') == 'encrypted_member' for u in encrypted['units'])
fixtures = [
    (archive([('../escape.txt', b'no')]), policy),
    (archive([('same.txt', b'a'), ('same.txt', b'b')]), policy),
    (archive([('big.txt', b'x'*100)]), dict(policy, maximum_member_bytes=20)),
    (archive([('huge.txt', b'x'*10000)], zipfile.ZIP_DEFLATED), dict(policy, maximum_expansion_ratio=2)),
    (archive([('nested.zip', archive([('inside.txt', b'a')]))]), dict(policy, maximum_depth=1)),
    (archive([('a.txt', b'a'), ('b.txt', b'b')]), dict(policy, maximum_members=1)),
    (archive([('a.txt', b'abcdef')])[:-30], policy),
    (b'%PDF unsupported document', policy),
]
for data, selected in fixtures:
    assert inspect(data, selected)['status'] == 'INSUFFICIENT_DATA'
corrupt = bytearray(archive([('member.txt', b'CRC-CHECK')]))
corrupt[corrupt.index(b'CRC-CHECK')] ^= 1
assert inspect(bytes(corrupt))['status'] == 'INSUFFICIENT_DATA'
assert inspect(archive([('a.txt', b'abc'), ('b.txt', b'def')]), dict(policy, maximum_expanded_bytes=4))['status'] == 'INSUFFICIENT_DATA'
`));

test('generated-output media probe requires bounded full decoding of every stream', () => execute(String.raw`
assert inspect(b'PNG valid')['status'] == 'PASS'
original = parser
def failed_decode(command, timeout, output_limit):
    return result(1, err='truncated frame') if command[0] == 'ffmpeg' else original(command, timeout, output_limit)
probe.run = failed_decode
assert inspect(b'PNG truncated')['status'] == 'INSUFFICIENT_DATA'
def missing_stream(command, timeout, output_limit):
    if command[0] == 'ffprobe':
        return result(out=json.dumps({'streams':[{'codec_type':'video','codec_name':'png','width':2,'height':2}, {'codec_type':'audio','codec_name':'pcm_s16le'}]}))
    return original(command, timeout, output_limit)
probe.run = missing_stream
assert inspect(b'PNG missing stream')['status'] == 'INSUFFICIENT_DATA'
probe.run = original
assert inspect(b'PNG oversize', dict(policy, maximum_pixels=3))['status'] == 'INSUFFICIENT_DATA'
assert inspect(b'PNG decoded bytes', dict(policy, maximum_decoded_bytes=11))['status'] == 'INSUFFICIENT_DATA'
def excessive_duration(command, timeout, output_limit):
    if command[0] == 'ffprobe':
        return result(out=json.dumps({'streams':[{'codec_type':'video','codec_name':'png','width':2,'height':2,'duration':'11'}]}))
    return original(command, timeout, output_limit)
probe.run = excessive_duration
assert inspect(b'PNG duration')['status'] == 'INSUFFICIENT_DATA'
def timed_out(*args):
    raise probe.CoverageGap('parser_timeout')
probe.run = timed_out
assert inspect(b'PNG timeout')['status'] == 'INSUFFICIENT_DATA'
# Exercise the real subprocess output/timeout bounds separately from tool stubs.
gap(lambda: real_probe_run([sys.executable, '-c', 'print("x"*1000)'], 3, 10))
gap(lambda: real_probe_run([sys.executable, '-c', 'import time; time.sleep(2)'], 0.2, 1000))
`));

test('generated-output scanners preserve ClamAV coverage gaps and positive findings independently', () => execute(String.raw`
clean = scanner.clamav_result(result(out='file: OK\n'), True)
assert clean == {'control_status':'PASS','finding_status':'NO_FINDING'}
assert scanner.clamav_result(result(out='file: OK\n'), False)['control_status'] == 'INSUFFICIENT_DATA'
for signature in ('Heuristics.Encrypted.Zip', 'Heuristics.Limits.Exceeded.MaxFileSize'):
    limited = scanner.clamav_result(result(1, 'file: '+signature+' FOUND\n'), True)
    assert limited['control_status'] == 'INSUFFICIENT_DATA' and limited['finding_status'] == 'UNKNOWN'
both = scanner.clamav_result(result(1, 'file: Heuristics.Encrypted.Zip FOUND\nfile: Test.Signature FOUND\n'), True)
assert both['control_status'] == 'INSUFFICIENT_DATA' and both['finding_status'] == 'FINDING'
assert scanner.clamav_result(result(2, err='scanner unavailable'), True)['control_status'] == 'ERROR'
assert scanner.clamav_result(result(0, 'file: Test.Signature FOUND\nfile: OK\n'), True)['control_status'] == 'ERROR'
`));

test('generated-output scanners scan extracted member bytes and reject stale provider bindings', () => execute(String.raw`
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    rules = root/'rules.yar'
    rules.write_bytes(b'rule sample { condition: true }')
    selected = scanner.ScannerPolicy('policy-1', str(rules), hashlib.sha256(rules.read_bytes()).hexdigest(), 100000, 10000, 10000, 2, 'clamav-1', 'database-1', 'yara-1', 'moderation-1', 'classifier-1', True)
    output = root/'outputs'
    output.mkdir()
    (output/'document.zip').write_bytes(archive([('payload.txt', b'TEST-PAYLOAD'), ('clean.txt', b'benign')], zipfile.ZIP_DEFLATED))
    scans = []
    def tools(command, timeout, output_limit):
        data = Path(command[-1]).read_bytes()
        scans.append((command[0], data))
        return result(out='file: OK\n') if command[0] == 'clamdscan' else result(out='sample file\n' if data == b'TEST-PAYLOAD' else '')
    scanner.run = tools
    with probe.probe_population(output, manifest(output), policy) as population:
        receipts = []
        for unit in population['units']:
            verified = scanner.VerifiedProbe(population['manifest_id'], unit['artifact_id'], unit['sha256'], unit['detected_media_type'], 'probe-1', unit['status'])
            receipts.extend(scanner.scan_artifact(ingress_path=Path(unit['snapshot_path']), probe=verified, policy=selected, moderate_media=None, verify_moderation_receipt=None))
        assert len(receipts) == 6
        assert ('yara', b'TEST-PAYLOAD') in scans and ('yara', b'benign') in scans
        assert any(r['detector']=='yara' and r['finding_status']=='FINDING' for r in receipts)
    media = root/'media.png'
    media.write_bytes(b'PNG content')
    verified = scanner.VerifiedProbe('manifest-1', 'media', hashlib.sha256(media.read_bytes()).hexdigest(), 'image/png', 'probe-1', 'PASS')
    def provider(path, digest, media_type, version):
        return dict(detector='media_moderation', detector_version='classifier-1', policy_version=version, artifact_sha256=digest, control_status='PASS', finding_status='NO_FINDING')
    def scan(probe_value=verified, adapter=provider):
        return scanner.scan_artifact(ingress_path=media, probe=probe_value, policy=selected, moderate_media=adapter, verify_moderation_receipt=lambda value:value)
    assert scan()[-1]['control_status'] == 'PASS'
    def stale(*args):
        return dict(provider(*args), artifact_sha256='0'*64)
    assert scan(adapter=stale)[-1]['control_status'] == 'ERROR'
    def old_version(*args):
        return dict(provider(*args), detector_version='old')
    assert scan(adapter=old_version)[-1]['control_status'] == 'ERROR'
    assert all(r['control_status']=='INSUFFICIENT_DATA' for r in scan(replace(verified, coverage_status='INSUFFICIENT_DATA')))
    gap(lambda: scan(replace(verified, artifact_sha256='0'*64)))
    def unavailable(*args):
        raise probe.CoverageGap('scanner_timeout')
    scanner.run = unavailable
    assert all(r['control_status']=='INSUFFICIENT_DATA' for r in scan()[:2])
`));

test('generated-output roll-up rejects receipt mixing and retains findings alongside missing coverage', () => execute(String.raw`
first, second = binding(), binding('member', 'yara', 'b'*64)
expected = {(b['artifact_id'],b['detector']):b for b in (first,second)}
good = [receipt(first), receipt(second)]
assert rollup.roll_up('manifest-1', expected, good)['outcome'] == 'PASS'
replayed = rollup.roll_up('manifest-1', expected, good+[dict(good[0])])
assert replayed['outcome']=='PASS' and replayed['identical_replays']==1
conflict = rollup.roll_up('manifest-1', expected, good+[receipt(first, finding='FINDING')])
assert conflict['outcome']=='FAIL' and conflict['coverage_status']=='INCOMPLETE' and conflict['conflicting_receipts']
for key, value in (('artifact_sha256','c'*64),('detector_version','old'),('policy_version','wrong'),('manifest_id','other')):
    bad = rollup.roll_up('manifest-1', expected, [dict(good[0], **{key:value}),good[1]])
    assert bad['outcome']=='ERROR' and bad['invalid_receipts']
extra = rollup.roll_up('manifest-1', expected, good+[receipt(binding('extra'))])
assert extra['outcome']=='ERROR' and extra['unexpected_receipts']
missing = rollup.roll_up('manifest-1', expected, [good[0]])
assert missing['outcome']=='INSUFFICIENT_DATA' and missing['missing_detector_population']
finding_with_gap = rollup.roll_up('manifest-1', expected, [receipt(first, finding='FINDING')])
assert finding_with_gap['outcome']=='FAIL' and finding_with_gap['coverage_status']=='INCOMPLETE'
gap_with_finding = rollup.roll_up('manifest-1', expected, [receipt(first, 'INSUFFICIENT_DATA', 'UNKNOWN'), receipt(second, finding='FINDING')])
assert gap_with_finding['finding_status']=='FINDING' and gap_with_finding['insufficient_receipts']
malformed = rollup.roll_up('manifest-1', expected, [receipt(first, 'INSUFFICIENT_DATA', 'NO_FINDING'),good[1]])
assert malformed['outcome']=='ERROR'
gap(lambda: rollup.roll_up('manifest-1', {('root','probe'):dict(first, rule_version='')}, []))
# The root probe gap remains expected even when an unreadable member has no digest.
root_gap = rollup.roll_up('manifest-1', expected, [receipt(first, 'INSUFFICIENT_DATA', 'UNKNOWN', unreadable_members=['encrypted.txt']), good[1]])
assert root_gap['outcome']=='INSUFFICIENT_DATA' and root_gap['coverage_status']=='INCOMPLETE'
`));
