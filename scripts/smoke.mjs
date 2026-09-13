import { runPostgresSmoke } from './verify-postgres-smoke.mjs';

runPostgresSmoke({ writeEvidence: true })
  .then((report) => console.log(JSON.stringify(report, null, 2)))
  .catch((error) => { console.error(error.message); process.exit(1); });
