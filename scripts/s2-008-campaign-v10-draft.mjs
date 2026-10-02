#!/usr/bin/env node
import fs from 'node:fs';
import {
  createV10Draft,
  readV10MeasurementOnDisk,
  readV10ReconciliationInputs,
} from './s2-008-campaign-v10-approval.mjs';

const dir = new URL('../corpus/s2-008-campaign/', import.meta.url);
const baseBytes = fs.readFileSync(new URL('preregistration.v9.in-force.json', dir));
const base = JSON.parse(baseBytes);
const pin = JSON.parse(fs.readFileSync(new URL('../evidence/s2-008-campaign/model-image-pin-v10-preseal.json', import.meta.url)));
const draft = createV10Draft({
  base,
  baseBytes,
  pin,
  measurement: readV10MeasurementOnDisk(),
  ...readV10ReconciliationInputs(),
});
fs.writeFileSync(
  new URL('preregistration.v10.draft.json', dir),
  JSON.stringify(draft, null, 2) + '\n',
  { flag: 'wx', mode: 0o644 },
);
console.log(JSON.stringify({
  status: draft.status,
  digest: draft.preregistration_digest,
  provider: draft.executor.provider,
  model: draft.executor.model,
  ceiling: draft.budget_reservation.granted_units,
  reconciliation_digest: draft.restart_reconciliation.canonical_digest,
}));