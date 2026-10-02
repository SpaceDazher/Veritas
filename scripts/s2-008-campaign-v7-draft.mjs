import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { approvalIdentityFromArgv, createV7Draft, approveV7 } from './s2-008-campaign-v7-approval.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const baseBytes = fs.readFileSync(path.join(corpus, 'preregistration.v6.in-force.json'));
const base = JSON.parse(baseBytes);
const pin = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v7-preseal.json')));
const write = (name, value) => fs.writeFileSync(path.join(corpus, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o644 });

if (process.argv.includes('--approve')) {
  const { principal, label } = approvalIdentityFromArgv(process.argv);
  const draft = JSON.parse(fs.readFileSync(path.join(corpus, 'preregistration.v7.draft.json'), 'utf8'));
  const table = JSON.parse(fs.readFileSync(path.join(corpus, 'frozen-table.v3.json'), 'utf8'));
  const signed = approveV7({ draft, base, baseBytes, table, pin, principal, label });
  write('preregistration.v7.approved.json', signed);
  console.log(JSON.stringify({
    file: 'preregistration.v7.approved.json',
    principal_id: signed.approval.principal_id,
    preregistration_digest: signed.preregistration_digest,
    in_force: signed.approval.in_force,
  }));
} else {
  const draft = createV7Draft({ base, baseBytes, pin });
  write('preregistration.v7.draft.json', draft);
  console.log(JSON.stringify({
    file: 'preregistration.v7.draft.json',
    preregistration_digest: draft.preregistration_digest,
    content_commitment: draft.executor.model_image.content_commitment,
    approval_status: draft.approval.status,
    model_call_timeout_ms: draft.executor.model_launch_timeout.per_model_call_timeout_ms,
    container_timeout_ms: draft.executor.model_launch_timeout.total_container_timeout_ms,
  }));
}
