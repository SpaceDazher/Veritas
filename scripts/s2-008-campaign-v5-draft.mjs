import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createV5Draft, approveV5 } from './s2-008-campaign-v5-approval.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const read = (name) => fs.readFileSync(path.join(corpus, name));
const baseBytes = read('preregistration.v4.in-force.json');
const base = JSON.parse(baseBytes);
const pin = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v5-preseal.json')));
const write = (name, value) => fs.writeFileSync(path.join(corpus, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });

if (process.argv.includes('--approve')) {
  const principalIndex = process.argv.indexOf('--principal');
  const labelIndex = process.argv.indexOf('--label');
  const principal = process.argv[principalIndex + 1];
  const label = process.argv[labelIndex + 1];
  const draft = JSON.parse(read('preregistration.v5.draft.json'));
  const table = JSON.parse(read('frozen-table.v3.json'));
  const signed = approveV5({ draft, base, baseBytes, table, pin, principal, label });
  write('preregistration.v5.approved.json', signed);
  console.log(JSON.stringify({ file: 'preregistration.v5.approved.json', principal_id: signed.approval.principal_id,
    preregistration_digest: signed.preregistration_digest, in_force: signed.approval.in_force }));
} else {
  const draft = createV5Draft({ base, baseBytes, pin });
  write('preregistration.v5.draft.json', draft);
  console.log(JSON.stringify({ file: 'preregistration.v5.draft.json', preregistration_digest: draft.preregistration_digest,
    content_commitment: draft.executor.model_image.content_commitment, approval_status: draft.approval.status }));
}
