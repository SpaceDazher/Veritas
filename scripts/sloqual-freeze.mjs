// SLOQUAL-001 contract freeze tool (author-time, not a gate).
//
// `--print` prints the contract with the scenario-manifest binding and the
// self-hash stamped, so the values can be pasted into the file. `--write`
// rewrites the contract in place with those stamps. Afterwards
// `npm run verify:sloqual-001` re-derives both digests on every run: a
// threshold edited after the freeze breaks the self-hash and stops the gate.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CONTRACT_PATH, MANIFEST_PATH } from '../src/lib/sloqual/index.mjs';
import { stampContract, verifyFreeze } from '../src/lib/sloqual/contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function main() {
  const write = process.argv.includes('--write');
  const contract = JSON.parse(fs.readFileSync(path.join(ROOT, CONTRACT_PATH), 'utf8'));
  const manifestBytes = fs.readFileSync(path.join(ROOT, MANIFEST_PATH));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const stamped = stampContract({contract, manifestBytes, manifest});
  if (write) {
    fs.writeFileSync(path.join(ROOT, CONTRACT_PATH), `${JSON.stringify(stamped, null, 2)}\n`);
  }
  const verification = verifyFreeze({contract: stamped, manifest, manifestBytes});
  const payload = {
    mode: write ? 'write' : 'print',
    contractPath: CONTRACT_PATH,
    manifestPath: MANIFEST_PATH,
    contractVersion: stamped.version,
    manifestVersion: stamped.manifest?.version ?? manifest.version,
    manifestSha256: stamped.scenarioManifest.sha256,
    selfHashSha256: stamped.selfHash.sha256,
    verification,
  };
  console.log(JSON.stringify(payload, null, 2));
  if (!write) console.log(JSON.stringify(stamped, null, 2));
  process.exit(verification.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
