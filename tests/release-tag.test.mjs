import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateReleaseVersion, assertPublicationContext, planReleaseTag } from '../scripts/release-tag.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const intro = version => `export const aidefendVersion = "${version}";\n`;

function fixture(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aidefend-release-tag-'));
  // Only the exact newly created temporary tree is removed, never a checkout
  // supplied by the user or an inferred repository parent.
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const remote = path.join(temporary, 'remote.git');
  const repo = path.join(temporary, 'repo');
  fs.mkdirSync(repo);
  const git = (...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '--bare', remote);
  git('init', '-b', 'main');
  git('config', 'user.name', 'Release test');
  git('config', 'user.email', 'release-test@example.invalid');
  git('remote', 'add', 'origin', remote);
  fs.mkdirSync(path.join(repo, 'scripts'));
  fs.copyFileSync(path.join(root, 'scripts/release-tag.mjs'), path.join(repo, 'scripts/release-tag.mjs'));
  let sequence = 0;
  const commit = (version = '1.20260907') => {
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ version, type: 'module' }));
    fs.writeFileSync(path.join(repo, 'aidefend-intro.js'), intro(version));
    fs.writeFileSync(path.join(repo, 'note.txt'), String(++sequence));
    git('add', '.'); git('commit', '-m', `fixture ${sequence}`);
    return git('rev-parse', 'HEAD');
  };
  const head = commit();
  git('push', '-u', 'origin', 'main');
  return { repo, git, head, commit };
}

test('release version is a real calendar date and agrees across authored sources', () => {
  assert.equal(validateReleaseVersion('1.20260907', intro('1.20260907')), 'v1.20260907');
  for (const version of ['1.20260230', '1.20260907.1', '1.20260907\ninjected', '1.20261301']) {
    assert.throws(() => validateReleaseVersion(version, intro(version)));
  }
  assert.throws(() => validateReleaseVersion('1.20260907', intro('1.20260908')));
  assert.throws(() => validateReleaseVersion('1.20260907', intro('1.20260907').repeat(2)));
});

test('only a main push or main manual retry of the exact tested commit can publish', () => {
  const env = { GITHUB_ACTIONS: 'true', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: 'a'.repeat(40), GITHUB_EVENT_NAME: 'push' };
  assert.doesNotThrow(() => assertPublicationContext(env, env.GITHUB_SHA));
  for (const change of [{ GITHUB_ACTIONS: '' }, { GITHUB_REF: 'refs/pull/1/merge' },
    { GITHUB_EVENT_NAME: 'pull_request_target' }, { GITHUB_SHA: 'b'.repeat(40) }]) {
    assert.throws(() => assertPublicationContext({ ...env, ...change }, env.GITHUB_SHA));
  }
});

test('new release selects exact HEAD; later same-version commits preserve the original tag', t => {
  const f = fixture(t);
  assert.deepEqual(planReleaseTag(f.repo), { status: 'create_tag', tag: 'v1.20260907', commit: f.head, checked_commit: f.head });
  f.git('tag', '-a', 'v1.20260907', '-m', 'fixture release');
  f.git('push', 'origin', 'refs/tags/v1.20260907');
  const later = f.commit();
  assert.deepEqual(planReleaseTag(f.repo), { status: 'already_tagged', tag: 'v1.20260907', commit: f.head, checked_commit: later });
  const next = f.commit('1.20260908');
  assert.equal(planReleaseTag(f.repo).commit, next);
  assert.equal(planReleaseTag(f.repo).tag, 'v1.20260908');
});

test('version rollback and conflicting tag target fail closed', t => {
  const f = fixture(t);
  f.commit('1.20260908');
  f.git('tag', 'v1.20260907');
  f.git('push', 'origin', 'refs/tags/v1.20260907');
  f.commit('1.20260907');
  assert.throws(() => planReleaseTag(f.repo), /cannot decrease/);
  f.commit('1.20260907');
  assert.throws(() => planReleaseTag(f.repo), /declared release version/);
});

test('publication creates an annotated remote tag, is idempotent, and never changes main', t => {
  const f = fixture(t);
  const run = overrides => spawnSync(process.execPath, ['scripts/release-tag.mjs', '--publish'], {
    cwd: f.repo, encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: '',
      GITHUB_ACTIONS: 'true', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: f.head,
      GITHUB_EVENT_NAME: 'push', ...overrides },
  });
  assert.notEqual(run({ GITHUB_REF: 'refs/heads/develop' }).status, 0);
  assert.equal(f.git('ls-remote', '--tags', 'origin'), '');
  let result = run({});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, 'tag_published');
  const before = f.git('ls-remote', 'origin');
  assert.match(before, /refs\/tags\/v1\.20260907\^\{\}/);
  result = run({});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, 'already_tagged');
  assert.equal(f.git('ls-remote', 'origin'), before);
  assert.equal(f.git('rev-parse', 'HEAD'), f.head);
});
