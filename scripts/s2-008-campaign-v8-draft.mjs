#!/usr/bin/env node
import fs from 'node:fs';
import {createV8Draft,readV8MeasurementOnDisk} from './s2-008-campaign-v8-approval.mjs';
const dir=new URL('../corpus/s2-008-campaign/',import.meta.url);
const baseBytes=fs.readFileSync(new URL('preregistration.v7.in-force.json',dir));
const base=JSON.parse(baseBytes);
const pin=JSON.parse(fs.readFileSync(new URL('../evidence/s2-008-campaign/model-image-pin-v8-preseal.json',import.meta.url)));
const draft=createV8Draft({base,baseBytes,pin,measurement:readV8MeasurementOnDisk()});
fs.writeFileSync(new URL('preregistration.v8.draft.json',dir),JSON.stringify(draft,null,2)+'\n');
console.log(JSON.stringify({status:draft.status,digest:draft.preregistration_digest,provider:draft.executor.provider,model:draft.executor.model,ceiling:draft.budget_reservation.granted_units,confirmed_usd:null}));
