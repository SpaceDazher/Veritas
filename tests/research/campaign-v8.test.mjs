import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {canonicalDigest} from '../../src/lib/verifier/canonical-json.mjs';
import {preregistrationDigest, FROZEN_MEMBERS} from '../../scripts/s2-008-campaign-approve.mjs';
import {modelImagePaths} from '../../scripts/s2-008-campaign-model-image.mjs';
import {modelTrialArgv} from '../../scripts/s2-008-campaign-adapter.mjs';
import {assertV8ExecutorPolicy,V8_EXECUTOR_POLICY,V7_PI_SETTINGS} from '../../scripts/s2-008-campaign-credential-env.mjs';

const baseBytes=fs.readFileSync('corpus/s2-008-campaign/preregistration.v7.in-force.json');
const base=JSON.parse(baseBytes);
const table=JSON.parse(fs.readFileSync('corpus/s2-008-campaign/frozen-table.v3.json'));
function baseManifest() {
 const m=JSON.parse(fs.readFileSync('corpus/s2-008-campaign/manifest.json'));
 m.preregistration={...m.preregistration,file:'preregistration.v7.in-force.json',status:'IN_FORCE',preregistration_digest:base.preregistration_digest};
 return m;
}
const oldPin=JSON.parse(fs.readFileSync('evidence/s2-008-campaign/model-image-pin-v7-preseal.json'));
const measurement={input:10941,output:3,cacheRead:195,totalTokens:11139,traceSha256:'d'.repeat(64)};
function pin8() {
 const sources={...oldPin.first.sources,prereg:createHash('sha256').update(baseBytes).digest('hex')};
 const covers=Object.keys(sources).filter(x=>x!=='prereg').sort();
 const first={...oldPin.first,sources,source_digest:canonicalDigest(sources),
  content_commitment:canonicalDigest(Object.fromEntries(covers.map(x=>[x,sources[x]]))),content_commitment_covers:covers};
 return {...oldPin,schema:'s2-008-model-image-pin/8',image_tag:'localhost/veritas-s2-008-model:v8',
  first,second:structuredClone(first),commitment:{covers,excludes:['prereg']}};
}
test('v8 image paths stage v7 for preseal and dispatch the signed v8 with the shared cap',()=>{
 assert.equal(modelImagePaths('v8',{preseal:true}).stagedPrereg,'corpus/s2-008-campaign/preregistration.v7.in-force.json');
 assert.equal(modelImagePaths('v8').pinFile,'evidence/s2-008-campaign/model-image-pin-v8.json');
 const argv=modelTrialArgv({armId:base.trial_list[0].arm_id,seed:20260926,remainingTokens:5000000,preregRule:'s2-008-prereg-v8'});
 assert.ok(argv.includes('/opt/veritas/corpus/s2-008-campaign/preregistration.v8.in-force.json'));
 assert.deepEqual(argv.slice(-2),['--remaining-tokens','5000000']);
 assert.throws(()=>modelTrialArgv({armId:base.trial_list[0].arm_id,seed:1,preregRule:'s2-008-prereg-v8'}),/SHARED_TOKEN_CAP_REQUIRED/);
});
test('v8 returns the retry-disabled settings actually consumed by the arm',()=>{
 assert.deepEqual(assertV8ExecutorPolicy({...V8_EXECUTOR_POLICY,pi_settings:V7_PI_SETTINGS}).settings,V7_PI_SETTINGS);
});
test('v8 approval binds v7 bytes and v8 content, preserves science, and leaves USD unverified',async()=>{
 const {createV8Draft,approveV8}=await import('../../scripts/s2-008-campaign-v8-approval.mjs');
 const pin=pin8(), draft=createV8Draft({base,baseBytes,pin,measurement});
 for(const member of FROZEN_MEMBERS) assert.deepEqual(draft[member],base[member],member);
 assert.equal(draft.supersession.supersedes,base.preregistration_id);
 assert.equal(draft.budget_reservation.granted_units,5000000);
 assert.equal(draft.budget_reservation.ceiling_scope,'PER_RUN_A_OR_B');
 assert.equal(draft.budget_reservation.usd_reference.confirmed_usd,null);
 assert.equal(draft.budget_reservation.usd_reference.projection.tokens_estimate,4210542);
 assert.equal(draft.executor.model_image.built_image_pin,'evidence/s2-008-campaign/model-image-pin-v8.json');
 const args={base,baseBytes,pin,measurement,table,principal:'prn-owner',label:'Daniil',issuedAt:'2026-10-01T00:00:00.000Z'};
 const signed=approveV8({...args,draft});
 assert.equal(signed.approval.in_force,false); assert.equal(signed.approval.status,'APPROVED');
 for(const [key,value] of [['trial_list',[]],['metric',{wrong:true}],['seed_count',4]]) {
  const bad=structuredClone(draft); bad[key]=value; bad.preregistration_digest=preregistrationDigest(bad);
  assert.throws(()=>approveV8({...args,draft:bad}),new RegExp('APPROVAL_SCOPE_DRIFT:'+key));
 }
 for(const mutate of [
  d=>d.supersession.supersedes='xpr-s2-008c-04',
  d=>d.executor.model_image.built_image_pin='evidence/s2-008-campaign/model-image-pin-v7.json',
  d=>d.executor.pi_settings.retry.provider.maxRetries=1,
  d=>d.budget_reservation.granted_units=100000000,
  d=>d.budget_reservation.usd_reference.confirmed_usd=0]) {
  const bad=structuredClone(draft);mutate(bad);bad.preregistration_digest=preregistrationDigest(bad);
  assert.throws(()=>approveV8({...args,draft:bad}));
 }
 const wrongPin=structuredClone(pin);wrongPin.second.imageId='sha256:'+'1'.repeat(64);
 assert.throws(()=>approveV8({...args,draft,pin:wrongPin}),/PRESEAL_PIN/);
 assert.throws(()=>approveV8({...args,draft,issuedAt:null}),/IDENTITY/);
});

test('v8 seal carries exact v7 supersession, rejects unsigned or drifting body, and replays manifest',async()=>{
 const {createV8Draft,approveV8}=await import('../../scripts/s2-008-campaign-v8-approval.mjs');
 const {sealV8,assertV8ManifestBinding}=await import('../../scripts/s2-008-campaign-seal-v8.mjs');
 const pin=pin8(),draft=createV8Draft({base,baseBytes,pin,measurement});
 const signed=approveV8({draft,base,baseBytes,pin,measurement,table,principal:'prn-owner',label:'Daniil',issuedAt:'2026-10-01T00:00:00.000Z'});
 const manifest=baseManifest();
 const ledger=JSON.parse(fs.readFileSync('corpus/s2-008-campaign/source-ledger.v3.json'));
 const args={signed,draft,base,baseBytes,pin,measurement,table,manifest,ledger};
 const result=sealV8(args);
 assert.equal(result.prereg.approval.in_force,true);
 assert.equal(result.manifest.preregistration.file,'preregistration.v8.in-force.json');
 assert.equal(result.manifest.superseded_preregistration.file,'preregistration-v7-superseded.json');
 assert.equal(assertV8ManifestBinding({...result,base,table}).ok,true);
 assert.throws(()=>sealV8({...args,signed:draft}),/V8_NOT_APPROVED/);
 const wrong=structuredClone(signed);wrong.executor.model='other';
 assert.throws(()=>sealV8({...args,signed:wrong}),/V8_DIGEST_MISMATCH/);
 const badManifest=structuredClone(result.manifest);badManifest.supersession_history.pop();
 assert.throws(()=>assertV8ManifestBinding({...result,base,table,manifest:badManifest}),/V8_MANIFEST_BINDING_MISMATCH/);
});
test('v8 independent evaluation recognizes its version and refuses missing probes',async()=>{
 const {activeCampaignVersion,validateV8ProbeEvidence}=await import('../../scripts/s2-008-campaign-evaluate.mjs');
 assert.equal(activeCampaignVersion({preregistration:{file:'preregistration.v8.in-force.json'}}),'v8');
 const refused=validateV8ProbeEvidence({campaignProbes:null,securityControls:null,prereg:{rule:'s2-008-prereg-v8'},runA:{},runB:{}});
 assert.equal(refused.ok,false);
});

test('common preregistration contract covers v8 executor and rejects a retry bypass',async()=>{
 const {createV8Draft,approveV8}=await import('../../scripts/s2-008-campaign-v8-approval.mjs');
 const {assertPreregistration,preregistrationDigest:coreDigest}=await import('../../src/lib/research/index.mjs');
 const pin=pin8(),draft=createV8Draft({base,baseBytes,pin,measurement});
 const signed=approveV8({draft,base,baseBytes,pin,measurement,table,principal:'prn-owner',label:'Daniil',issuedAt:'2026-10-01T00:00:00.000Z'});
 assert.equal(coreDigest(signed),signed.preregistration_digest);
 assert.equal(assertPreregistration(signed).rule,'s2-008-prereg-v8');
 const bad=structuredClone(signed);bad.executor.pi_settings.retry.enabled=true;
 bad.preregistration_digest=preregistrationDigest(bad);
 assert.throws(()=>assertPreregistration(bad),/EXECUTOR_POLICY_INVALID/);
});

test('all campaign probes resolve and validate the sealed v8 document',async()=>{
 const {resolveProbePreregistrationPath,validateProbePreregistration}=await import('../../scripts/s2-008-campaign-probes.mjs');
 const {createV8Draft,approveV8}=await import('../../scripts/s2-008-campaign-v8-approval.mjs');
 const {sealV8}=await import('../../scripts/s2-008-campaign-seal-v8.mjs');
 const pin=pin8(),draft=createV8Draft({base,baseBytes,pin,measurement});
 const signed=approveV8({draft,base,baseBytes,pin,measurement,table,principal:'prn-owner',label:'Daniil',issuedAt:'2026-10-01T00:00:00.000Z'});
 const manifest=baseManifest();
 const ledger=JSON.parse(fs.readFileSync('corpus/s2-008-campaign/source-ledger.v3.json'));
 const sealed=sealV8({signed,draft,base,baseBytes,pin,measurement,table,manifest,ledger});
 assert.match(resolveProbePreregistrationPath('corpus/s2-008-campaign/preregistration.v8.in-force.json'),/preregistration.v8.in-force.json$/);
 assert.equal(validateProbePreregistration(sealed).ok,true);
 const bad=structuredClone(sealed);bad.prereg.executor.provider='zai-coding-cn';
 assert.equal(validateProbePreregistration(bad).ok,false);
});
