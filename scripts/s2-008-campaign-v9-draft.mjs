#!/usr/bin/env node
import fs from 'node:fs';
import { createV9Draft, readV9MeasurementOnDisk, readV9ReconciliationInputs } from './s2-008-campaign-v9-approval.mjs';

const dir = new URL('../corpus/s2-008-campaign/', import.meta.url);
const baseBytes = fs.readFileSync(new URL('preregistration.v8.in-force.json', dir));
const base = JSON.parse(baseBytes);
const pin = JSON.parse(fs.readFileSync(new URL('../evidence/s2-008-campaign/model-image-pin-v9-preseal.json', import.meta.url)));
const draft = createV9Draft({
  base, baseBytes, pin, measurement: readV9MeasurementOnDisk(), ...readV9ReconciliationInputs(),
});
fs.writeFileSync(new URL('preregistration.v9.draft.json', dir), `${JSON.stringify(draft, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
console.log(JSON.stringify({ status: draft.status, digest: draft.preregistration_digest, provider: draft.executor.provider,
  model: draft.executor.model, ceiling: draft.budget_reservation.granted_units,
  reconciliation_digest: draft.restart_reconciliation.canonical_digest }));
