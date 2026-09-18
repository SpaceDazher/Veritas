// S2-005 adversarial probe orchestrator (todo §8, probes A–L).
// Runs every probe against the production retrieval/synthesis path and binds
// evidence/s2-005-security-probes.json. Any probe failure exits non-zero.
//
//   node scripts/s2-005-security-probes.mjs            # run + print
//   node scripts/s2-005-security-probes.mjs --write    # bind evidence artifact
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runAllProbes } from '../src/lib/synthesis/probes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/s2-005-security-probes.json');

const report = await runAllProbes();
report.testedImplementationCommit = (() => {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unavailable';
  }
})();
report.executedAt = 'bound on the S2-005 branch';

if (process.argv.includes('--write')) {
  fs.writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
  console.error(`written: ${path.relative(ROOT, OUT)}`);
}
console.log(JSON.stringify({ ok: report.ok, probeCount: report.probeCount, failures: report.failures }, null, 2));
process.exit(report.ok ? 0 : 1);

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  // unreachable: top-level await above already ran
}
