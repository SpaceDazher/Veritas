import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {canonicalDigest} from '../src/lib/verifier/canonical-json.mjs';
import {FROZEN_MEMBERS,preregistrationDigest,scientificBody,scopeDrift} from './s2-008-campaign-approve.mjs';
import {assertVersionedPresealPin} from './s2-008-campaign-v6-approval.mjs';
import {assertV6ModelTimeoutPolicy} from './s2-008-campaign-v6-timeout.mjs';
import {V8_EXECUTOR_POLICY,V7_PI_SETTINGS,assertV8ExecutorPolicy} from './s2-008-campaign-credential-env.mjs';
import {extractUsage} from './s2-008-campaign-arm-model.mjs';
export {approvalIdentityFromArgv} from './s2-008-campaign-v7-approval.mjs';

export function readV8MeasurementOnDisk({requireTrace=true}={}) {
 const source=new URL('../Stage%202/.bb/chats/thr_hj2st7xwcz/artifacts/pi-measurement-space-bunny-alpha.jsonl',import.meta.url);
 if(!fs.existsSync(source)&&!requireTrace) {
  const record=JSON.parse(fs.readFileSync(new URL('../evidence/s2-008-campaign/openrouter-measurement-v8.json',import.meta.url),'utf8'));
  if(record.kind!=='s2-008-openrouter-measurement/1'||record.provider!==V8_EXECUTOR_POLICY.provider||record.model!==V8_EXECUTOR_POLICY.model)
   throw new Error('V8_MEASUREMENT_INVALID');
  return record.measurement;
 }
 const bytes=fs.readFileSync(source);
 const u=extractUsage(bytes.toString('utf8'));
 if (!u) throw new Error('V8_MEASUREMENT_ABSENT');
 return {input:u.input,output:u.output,cacheRead:u.cacheRead??0,totalTokens:u.totalTokens,
  traceSha256:createHash('sha256').update(bytes).digest('hex')};
}
export function assertV8PresealPin(args) {
 return assertVersionedPresealPin({...args,version:8,requiredSources:['pi_runtime_tree','timeout_policy','credential_env_policy']});
}
export function createV8Draft({base,baseBytes,pin,measurement}) {
 if(base?.rule!=='s2-008-prereg-v7'||base.preregistration_id!=='xpr-s2-008c-07'
  ||base.approval?.in_force!==true||base.preregistration_digest!==preregistrationDigest(base))
  throw new Error('V8_BASE_NOT_IN_FORCE');
 const {commitment,covers}=assertV8PresealPin({pin,baseBytes});
 if(!measurement||!['input','output','cacheRead','totalTokens'].every(k=>Number.isSafeInteger(measurement[k])&&measurement[k]>=0)
  ||measurement.totalTokens<=0||!/^[0-9a-f]{64}$/.test(measurement.traceSha256??'')) throw new Error('V8_MEASUREMENT_INVALID');
 const calls=base.holdout_access.case_count*base.seed_count;
 const projected=calls*measurement.totalTokens;
 if(!Number.isSafeInteger(projected)||projected>base.budget_reservation.granted_units) throw new Error('V8_PROJECTION_EXCEEDS_CEILING');
 const draft={...base,rule:'s2-008-prereg-v8',preregistration_id:'xpr-s2-008c-08',
  executor:{...base.executor,...V8_EXECUTOR_POLICY,pi_settings:structuredClone(V7_PI_SETTINGS),
   inside_isolation:'LOCAL_RESTRICTED, digest-pinned, egress allowlist openrouter.ai:443 only',
   model_image:{...base.executor.model_image,content_commitment:commitment,covers,excludes:['prereg'],
    built_image_pin:'evidence/s2-008-campaign/model-image-pin-v8.json',
    built_image_pin_reason:'v8 built image binds this signed OpenRouter document; its acyclic content commitment excludes only the preregistration'}},
  budget_reservation:{...base.budget_reservation,reservation_id:'rsv-s2-008c-08',
   usd_reference:{confirmed_usd:null,confirmed_usd_status:'NOT_VERIFIED',
    why_null:'Client cost.total=0 is not an independently verified provider price.',
    measurement:structuredClone(measurement),measurement_basis:'one host-side call with tools ON; campaign runs with tools OFF',
    projection:{calls,cases_per_seed:base.holdout_access.case_count,seeds:base.seed_count,
     tokens_per_call:measurement.totalTokens,tokens_estimate:projected,status:'PROJECTION_NOT_MEASUREMENT',
     caveat:'Container configuration is not measured by this host trace. Actual usage is charged during execution; the ceiling is unchanged.'},
    ceiling_scope:'PER_RUN_A_OR_B',aggregate_spend:'Report A+B separately; historical unresolved v7 spend stays UNKNOWN'}},
  supersession:{supersedes:base.preregistration_id,superseded_digest:base.preregistration_digest,
   scope:'executor provider/model, egress and content binding; frozen science and 5M ceiling per A/B unchanged',
   reason:'v8 replaces the executor with OpenRouter stealth/space-bunny-alpha and restricts egress to openrouter.ai:443',
   unchanged:[...FROZEN_MEMBERS]},
  recorded_before_first_trial:{first_trial:'NOT_STARTED',proof:'No v8 trial has started. The interrupted v7 attempt remains recorded with unknown spend and is not retried.'},
  status:'DRAFT',approval:{status:null,authority:'HUMAN_OWNER',principal_id:null,label:null,issued_at:null,
   signed_digest_over:'the scientific body: every member except approval, status and preregistration_digest',
   in_force:false,becomes_in_force_when:'scripts/s2-008-campaign-prepare.mjs --seal-v8 records this digest and supersession in the corpus manifest'}};
 draft.preregistration_digest=preregistrationDigest(draft);
 const drift=scopeDrift(base,draft);
 if(drift) throw new Error('APPROVAL_SCOPE_DRIFT:'+drift.member);
 return draft;
}
export function approveV8({draft,base,baseBytes,pin,measurement,table,principal,label,issuedAt}) {
 if(typeof principal!=='string'||!/^prn-[a-z0-9-]+$/.test(principal)||typeof label!=='string'||!label.trim()
  ||typeof issuedAt!=='string'||!Number.isFinite(Date.parse(issuedAt))) throw new Error('V8_APPROVAL_IDENTITY_MISSING');
 if(draft?.rule!=='s2-008-prereg-v8'||draft.preregistration_id!=='xpr-s2-008c-08') throw new Error('V8_VERSION_MISMATCH');
 if(draft.status!=='DRAFT'||draft.approval?.status!==null) throw new Error('V8_ALREADY_SIGNED');
 if(draft.preregistration_digest!==preregistrationDigest(draft)) throw new Error('V8_DIGEST_MISMATCH');
 const drift=scopeDrift(base,draft);
 if(drift) throw new Error('APPROVAL_SCOPE_DRIFT:'+drift.member);
 if(draft.expected_table_digest!==canonicalDigest(table)) throw new Error('V8_TABLE_MISMATCH');
 assertV6ModelTimeoutPolicy(draft.executor?.model_launch_timeout);
 assertV8ExecutorPolicy(draft.executor);
 const expected=createV8Draft({base,baseBytes,pin,measurement});
 if(canonicalDigest(scientificBody(expected))!==canonicalDigest(scientificBody(draft))) throw new Error('V8_SCOPE_MISMATCH');
 const signed={...scientificBody(draft),status:'APPROVED',
  approval:{...draft.approval,status:'APPROVED',authority:'HUMAN_OWNER',principal_id:principal,label,issued_at:issuedAt,in_force:false}};
 return Object.freeze({...signed,preregistration_digest:preregistrationDigest(signed)});
}
