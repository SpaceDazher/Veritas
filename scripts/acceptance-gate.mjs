import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = process.cwd();
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));

export function readAcceptanceState() {
  const profile = readJson('pilots/pilot-profile.json');
  const briefs = ['pilots/scenario-a/task-brief.json', 'pilots/scenario-b/task-brief.json'].map(readJson);
  const outputs = [
    'pilots/scenario-a/solution-pack.example.json',
    'pilots/scenario-b/research-dossier.example.json',
  ].map(readJson);
  const pilotExecutions = outputs.flatMap((output) => Object.values(output.artifacts)
    .filter((artifact) => artifact.status === 'PRESENT' || output.execution_status === 'MEASURED')).length;
  const needsInput = [profile, ...briefs].some((record) => record.status === 'NEEDS_INPUT')
    || briefs.some((brief) => brief.execution_authorized !== false || brief.unknowns.length > 0);
  const executionAuthorized = briefs.every((brief) => brief.execution_authorized === true);
  const blockers = [];
  if (pilotExecutions === 0) blockers.push('pilotExecutions=0');
  if (needsInput) blockers.push('Scenario A/B remain NEEDS_INPUT');
  if (!executionAuthorized) blockers.push('execution_authorized=false');
  return {
    verdict: pilotExecutions > 0 && !needsInput && executionAuthorized ? 'ELIGIBLE_FOR_ACCEPTANCE_REVIEW' : 'BLOCKED',
    pilotExecutions,
    needsInput,
    executionAuthorized,
    blockers,
  };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const state = readAcceptanceState();
  console.log(JSON.stringify(state, null, 2));
  if (process.argv.includes('--test')) {
    assert.equal(state.verdict, 'BLOCKED');
    assert.equal(state.pilotExecutions, 0);
    assert.equal(state.executionAuthorized, false);
    process.exit(0);
  }
  process.exit(state.verdict === 'BLOCKED' ? 1 : 0);
}
