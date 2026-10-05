import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createV12Draft, readV12BaseInputs, inspectV11PriorExecutionEvidence } from './s2-008-campaign-v12-approval.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS = path.join(ROOT, 'corpus/s2-008-campaign');
const PIN = path.join(ROOT, 'evidence/s2-008-campaign/model-image-pin-v12-preseal.json');
const OUT = path.join(CORPUS, 'preregistration.v12.draft.json');

export function createV12DraftOnDisk() {
  if (!fs.existsSync(PIN)) throw new Error('V12_PRESEAL_PIN_REQUIRED');
  const input = readV12BaseInputs();
  const draft = createV12Draft({
    ...input,
    pin: JSON.parse(fs.readFileSync(PIN, 'utf8')),
    priorExecutionEvidence: inspectV11PriorExecutionEvidence(),
  });
  fs.writeFileSync(OUT, JSON.stringify(draft, null, 2) + String.fromCharCode(10), { flag: 'wx', mode: 0o644 });
  return { written: OUT, preregistration_id: draft.preregistration_id, preregistration_digest: draft.preregistration_digest };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    process.stdout.write(JSON.stringify(createV12DraftOnDisk(), null, 2) + String.fromCharCode(10));
  } catch (error) {
    process.stderr.write(String(error?.message ?? error) + String.fromCharCode(10));
    process.exitCode = 2;
  }
}
