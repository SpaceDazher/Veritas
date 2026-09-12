import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REQUIRED_TICKETS = Object.freeze(['S2-001', 'S1-007', 'S1-008', 'S1-010']);
const STAGE_ONE_TICKETS = new Set(['S1-007', 'S1-008', 'S1-010']);
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;

function isPortableRelative(value) {
  return typeof value === 'string'
    && value.length > 0
    && !path.isAbsolute(value)
    && !/^[A-Za-z]:[\\/]/.test(value)
    && !value.includes('\\')
    && !value.split('/').includes('..');
}

export function verifyDependencyBinding(record, root) {
  const issues = [];
  if (!record || typeof record !== 'object') return { ok: false, verified: 0, issues: ['record:not-object'] };
  const dependencies = Array.isArray(record.dependencies) ? record.dependencies : [];
  const byTicket = new Map();
  for (const dependency of dependencies) {
    if (!dependency || typeof dependency.ticket !== 'string' || byTicket.has(dependency.ticket)) {
      issues.push('dependencies:duplicate-or-invalid-ticket');
      continue;
    }
    byTicket.set(dependency.ticket, dependency);
  }
  for (const ticket of REQUIRED_TICKETS) {
    if (!byTicket.has(ticket)) issues.push(`${ticket}:missing`);
  }
  for (const ticket of byTicket.keys()) {
    if (!REQUIRED_TICKETS.includes(ticket)) issues.push(`${ticket}:unexpected`);
  }

  const s2 = byTicket.get('S2-001');
  if (s2) {
    if (!isPortableRelative(s2.evidence)) issues.push('S2-001:absolute-path');
    const evidencePath = isPortableRelative(s2.evidence) ? path.join(root, s2.evidence) : '';
    if (!evidencePath || !fs.existsSync(evidencePath)) issues.push('S2-001:evidence-missing');
    if (s2.result !== 'PASS_WITH_LIMITS' || s2.productionDeploymentAuthorized !== false) {
      issues.push('S2-001:unsafe-status');
    }
    if (!GIT_COMMIT.test(s2.upstreamMainCommit ?? '')) issues.push('S2-001:unpinned-commit');
  }

  const source = record.sourceRepository ?? {};
  const sourceCommit = source.headCommitAtBindingTime;
  if (source.remote !== 'https://github.com/SpaceDazher/AgentOS.git') issues.push('agentos:unexpected-remote');
  if (!GIT_COMMIT.test(sourceCommit ?? '')) issues.push('agentos:unpinned-commit');
  if (!GIT_COMMIT.test(source.headTreeAtBindingTime ?? '')) issues.push('agentos:unpinned-tree');

  for (const ticket of STAGE_ONE_TICKETS) {
    const dependency = byTicket.get(ticket);
    if (!dependency) continue;
    if (!isPortableRelative(dependency.evaluationRecordPath)) issues.push(`${ticket}:absolute-path`);
    if (dependency.sourceCommit !== sourceCommit || !GIT_COMMIT.test(dependency.sourceCommit ?? '')) {
      issues.push(`${ticket}:unpinned-source`);
    }
    const expectedPath = `research/tickets/stage-1/${ticket}/evaluation-record.json`;
    if (dependency.evaluationRecordPath !== expectedPath) issues.push(`${ticket}:wrong-record-path`);
    const expectedUrl = `https://raw.githubusercontent.com/SpaceDazher/AgentOS/${sourceCommit}/${expectedPath}`;
    if (dependency.evaluationRecordUrl !== expectedUrl) issues.push(`${ticket}:wrong-record-url`);
    if (!SHA256.test(dependency.evaluationRecordSha256 ?? '')) issues.push(`${ticket}:invalid-record-digest`);
    if (!SHA256.test(dependency.artifactChainHash ?? '')) issues.push(`${ticket}:invalid-chain`);
    if (!/^reval_[A-Z0-9]+$/.test(dependency.evaluationId ?? '')) issues.push(`${ticket}:invalid-evaluation-id`);
    if (dependency.status !== 'BOUND_PASS_WITH_LIMITS') issues.push(`${ticket}:unsafe-status`);
  }

  return { ok: issues.length === 0, verified: REQUIRED_TICKETS.filter((ticket) => byTicket.has(ticket)).length, issues };
}

function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const record = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-002-dependency-binding.json'), 'utf8'));
  const result = verifyDependencyBinding(record, root);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
