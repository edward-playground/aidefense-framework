#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function validateReleaseVersion(packageVersion, introSource) {
  const match = /^1\.(\d{4})(\d{2})(\d{2})$/.exec(packageVersion ?? '');
  assert.ok(match, 'Release version must use 1.YYYYMMDD.');
  const [, year, month, day] = match;
  const date = new Date(`${year}-${month}-${day}T00:00:00Z`);
  assert.ok(Number.isFinite(date.valueOf()) &&
    date.toISOString().slice(0, 10) === `${year}-${month}-${day}`, 'Release date is invalid.');
  const declarations = [...introSource.matchAll(/^export const aidefendVersion = ["']([^"']+)["'];\s*$/gm)];
  assert.equal(declarations.length, 1, 'Expected exactly one aidefendVersion declaration.');
  assert.equal(declarations[0][1], packageVersion, 'package.json and aidefend-intro.js versions differ.');
  return `v${packageVersion}`;
}

export function assertPublicationContext(environment, head) {
  assert.equal(environment.GITHUB_ACTIONS, 'true', 'Automatic publication requires GitHub Actions.');
  assert.equal(environment.GITHUB_REF, 'refs/heads/main', 'Only main may publish release tags.');
  assert.ok(['push', 'workflow_dispatch'].includes(environment.GITHUB_EVENT_NAME), 'This event cannot publish tags.');
  assert.equal(environment.GITHUB_SHA, head, 'Checkout differs from the tested event commit.');
}

export function planReleaseTag(repoRoot) {
  const git = (...args) => execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  const head = git('rev-parse', 'HEAD');
  const version = JSON.parse(git('show', `${head}:package.json`)).version;
  const tag = validateReleaseVersion(version, git('show', `${head}:aidefend-intro.js`));
  // The workflow fetches complete history and tags. This also rejects a
  // rollback to an older version even if that version had no earlier tag.
  const parents = git('rev-list', '--parents', '-n', '1', head).split(' ').slice(1);
  if (parents.length) {
    const previous = JSON.parse(git('show', `${parents[0]}:package.json`)).version;
    validateReleaseVersion(previous, git('show', `${parents[0]}:aidefend-intro.js`));
    assert.ok(version >= previous, 'Release version cannot decrease.');
  }
  for (const released of git('tag', '--merged', head, '--list', 'v1.*').split('\n')) {
    if (/^v1\.\d{8}$/.test(released)) {
      assert.ok(`v${version}` >= released, 'Release version is older than an ancestor release.');
    }
  }
  const refs = git('ls-remote', '--tags', 'origin', `refs/tags/${tag}`, `refs/tags/${tag}^{}`)
    .split('\n').filter(Boolean).map(line => line.split(/\s+/));
  const target = refs.find(([, ref]) => ref === `refs/tags/${tag}^{}`)?.[0]
    ?? refs.find(([, ref]) => ref === `refs/tags/${tag}`)?.[0];
  if (target) {
    // Existing tags are immutable. Later same-version documentation or tooling
    // commits do not move the original release boundary.
    git('merge-base', '--is-ancestor', target, head);
    const taggedVersion = JSON.parse(git('show', `${target}:package.json`)).version;
    assert.equal(taggedVersion, version, 'Existing tag does not contain its declared release version.');
    return { status: 'already_tagged', tag, commit: target, checked_commit: head };
  }
  return { status: 'create_tag', tag, commit: head, checked_commit: head };
}

async function main() {
  assert.ok(process.argv.length <= 3 && (!process.argv[2] || process.argv[2] === '--publish'), 'Use no arguments or --publish.');
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const git = (...args) => execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  const plan = planReleaseTag(repoRoot);
  if (process.argv[2] === '--publish') {
    assertPublicationContext(process.env, plan.checked_commit);
    assert.equal(git('status', '--porcelain', '--untracked-files=no'), '', 'Publication requires unchanged tracked files.');
    if (plan.status === 'create_tag') {
      git('-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
        'tag', '--annotate', plan.tag, plan.commit, '--message', `AIDEFEND ${plan.tag}\n\nValidated Framework source release.`);
      try {
        git('push', 'origin', `refs/tags/${plan.tag}:refs/tags/${plan.tag}`);
      } catch {
        // A concurrent run may have won the create-only push. Only the exact
        // same target is an idempotent success; never force or relocate a tag.
        const winner = planReleaseTag(repoRoot);
        assert.equal(winner.status, 'already_tagged', 'Release tag push failed.');
        assert.equal(winner.commit, plan.commit, 'Concurrent tag publication selected another commit.');
      }
      const readback = planReleaseTag(repoRoot);
      assert.equal(readback.commit, plan.commit, 'Published release tag readback differs.');
      assert.equal(readback.status, 'already_tagged');
      plan.status = 'tag_published';
    }
  }
  console.log(JSON.stringify(plan));
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `status=${plan.status}\ntag=${plan.tag}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
