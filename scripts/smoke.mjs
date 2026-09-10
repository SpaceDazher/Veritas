import fs from 'node:fs';

const report = {
  schemaVersion: 1,
  exitCode: 0,
  status: 'NOT_RUN',
  scope: 'Optional database/browser smoke is never run implicitly',
  reason: process.env.DATABASE_URL
    ? 'VERITAS_SMOKE_ENABLED is not set; a dedicated local server and database grant are required'
    : 'DATABASE_URL is absent; no database or browser smoke was run',
  screenshots: [],
  createdTaskIds: [],
};
fs.writeFileSync('evidence/workspace-smoke.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
