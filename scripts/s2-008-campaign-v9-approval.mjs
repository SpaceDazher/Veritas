import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {canonicalDigest} from '../src/lib/verifier/canonical-json.mjs';
import {FROZEN_MEMBERS,preregistrationDigest,scientificBody,scopeDrift} from './s2-008-campaign-approve.mjs';
import {assertVersionedPresealPin} from './s2-008-campaign-v6-approval.mjs';
import {assertV6ModelTimeoutPolicy} from './s2-008-campaign-v6-timeout.mjs';
import {V8_EXECUTOR_POLICY,V7_PI_SETTINGS,assertV8ExecutorPolicy} from './s2-008-campaign-credential-env.mjs';
import {extractUsage} from './s2-008-campaign-arm-model.mjs';
export {approvalIdentityFromArgv} from './s2-008-campaign-v7-approval.mjs';

export function readV9MeasurementOnDisk({requireTrace=true}={}) {
 const source=new URL('../Stage%202/.bb/chats/thr_hj2st7xwcz/artifacts/pi-measurement-space-bunny-alpha.jsonl',import.meta.url);
 if(!fs.existsSync(source)&&!requireTrace) {
  const record=JSON.parse(fs.readFileSync(new URL('../evidence/s2-008-campaign/openrouter-measurement-v8.json',import.meta.url),'utf8'));
  if(record.kind!=='s2-008-openrouter-measurement/1'||record.provider!==V8_EXECUTOR_POLICY.provider||record.model!==V8_EXECUTOR_POLICY.model)
   throw new Error('V9_MEASUREMENT_INVALID');
  return record.measurement;
 }
 const bytes=fs.readFileSync(source);
 const u=extractUsage(bytes.toString('utf8'));
 if (!u) throw new Error('V9_MEASUREMENT_ABSENT');
 return {input:u.input,output:u.output,cacheRead:u.cacheRead??0,totalTokens:u.totalTokens,
  traceSha256:createHash('sha256').update(bytes).digest('hex')};
}
const V8_A_RUN_ID='s2-008c-v8-a-4badb93620ff4fafb267';
const V8_A_RUN_SHA256='57424275104d16799ac67ea554ee684f84ff62d89e52c083db3f773915a7df05';
const V8_PREREG_DIGEST='f75f9852d1ecf7b7b1007128bc50e1354392c1ff45752b2415cd8e3e3368d917';
const EXCLUDED_SESSION_ID='01a0f69b-fe45-7164-bae6-d627bac92adf';
const RECONCILIATION_PATH=new URL('../evidence/s2-008-campaign/reconciliation-v8-a.json',import.meta.url);
const PRIOR_RUN_PATH=new URL('../evidence/s2-008-campaign/run-v8-a.json',import.meta.url);

export function readV9ReconciliationInputs() {
 return {
  reconciliation:JSON.parse(fs.readFileSync(RECONCILIATION_PATH,'utf8')),
  priorRunBytes:fs.readFileSync(PRIOR_RUN_PATH),
 };
}

export function assertV9PresealPin(args) {
 return assertVersionedPresealPin({...args,version:9,requiredSources:['pi_runtime_tree','timeout_policy','credential_env_policy']});
}

export function assertV8AReconciliation({reconciliation,priorRunBytes}) {
 if(!reconciliation||priorRunBytes===undefined||priorRunBytes===null) throw new Error('V9_RECONCILIATION_MISSING');
 const actualRunSha256=createHash('sha256').update(priorRunBytes).digest('hex');
 if(actualRunSha256!==V8_A_RUN_SHA256||reconciliation.prior_run_sha256!==actualRunSha256) throw new Error('V9_RECONCILIATION_PRIOR_RUN_HASH_MISMATCH');
 const digestMismatch=reconciliation.preregistration_digest!==V8_PREREG_DIGEST||
  reconciliation.prior_run_id!==V8_A_RUN_ID;
 if(digestMismatch) throw new Error('V9_RECONCILIATION_PREREG_BINDING_MISMATCH');
 const priorRun=JSON.parse(Buffer.from(priorRunBytes).toString('utf8'));
 if(priorRun.kind!=='s2-008-campaign-v8-predictions/1'||priorRun.status!=='BLOCKED'||
  priorRun.raw_run_id!==V8_A_RUN_ID||priorRun.preregistration_digest!==V8_PREREG_DIGEST) throw new Error('V9_RECONCILIATION_PRIOR_RUN_INVALID');
 if(reconciliation.kind!=='s2-008-v8-a-reconciliation/1'||reconciliation.status!=='RECONCILED'||
  reconciliation.method!=='OWNER_CONFIRMED_COMPLETE_PROVIDER_LOG'||
  reconciliation.provider!=='openrouter'||reconciliation.model!=='stealth/space-bunny-alpha') throw new Error('V9_RECONCILIATION_IDENTITY_INVALID');
 const expectedInterval={from:'2026-10-01T08:44:00.000Z',to_exclusive:'2026-10-01T08:45:00.000Z'};
 if(canonicalDigest(reconciliation.interval)!==canonicalDigest(expectedInterval)) throw new Error('V9_RECONCILIATION_INTERVAL_INVALID');
 const completeness=reconciliation.completeness;
 if(completeness?.confirmed_by!=='Daniil'||completeness.complete!==true||completeness.unfiltered!==true||
  completeness.includes_errors_and_cancellations!==true||completeness.statement!=='Да, полный список без фильтров'||
  reconciliation.completeness_verified_via_api!==false) throw new Error('V9_RECONCILIATION_COMPLETENESS_INVALID');
 if(reconciliation.matching_requests!==0||reconciliation.actual_tokens!==0||reconciliation.actual_usd!==0) throw new Error('V9_RECONCILIATION_MATCHING_ACTIVITY');
 if(reconciliation.provider_rows_verified_via_api!==true||reconciliation.excluded_session_id!==EXCLUDED_SESSION_ID||
  reconciliation.matching_basis!=='All five rows share one continuing tool-using session with three media inputs. A was a new text-only pi invocation with no tools, no attachments and no session.'||
  reconciliation.new_run_policy!=='Fresh separately signed successor and separate clean A/B copies; do not retry or overwrite old v8 A.'||
  reconciliation.scope!=='Only stopped v8 A. Prior v7 spend is not reconciled. Original run evidence is preserved unchanged.') throw new Error('V9_RECONCILIATION_EXCLUDED_ROWS_INVALID');
 const rows=reconciliation.rows;
 if(!Array.isArray(rows)||rows.length!==5) throw new Error('V9_RECONCILIATION_EXCLUDED_ROWS_INVALID');
 const ids=new Set();
 for(const row of rows) {
  const time=Date.parse(row.created_at);
  const apiTime=Date.parse(row.api_created_at);
  if(typeof row.generation_id!=='string'||!/^gen-[A-Za-z0-9-]+$/.test(row.generation_id)||ids.has(row.generation_id)||
   row.session_id!==EXCLUDED_SESSION_ID||!Number.isFinite(time)||time<Date.parse(expectedInterval.from)||time>=Date.parse(expectedInterval.to_exclusive)||
   apiTime!==time||!Number.isSafeInteger(row.input)||row.input<0||!Number.isSafeInteger(row.output)||row.output<0||
   !Number.isSafeInteger(row.cached)||row.cached<0||row.num_media_prompt!==3||
   (row.api_num_media_prompt!==undefined&&row.api_num_media_prompt!==null&&row.api_num_media_prompt!==3)||row.finish_reason!=='tool_calls'||
   (row.api_finish_reason!==undefined&&row.api_finish_reason!==null&&row.api_finish_reason!=='tool_calls')||row.match_to_campaign_A!==false||
   row.source_verified_via_api!==true) throw new Error('V9_RECONCILIATION_EXCLUDED_ROWS_INVALID');
  ids.add(row.generation_id);
 }
 return Object.freeze({ok:true,kind:reconciliation.kind,canonicalDigest:canonicalDigest(reconciliation),
  priorRunId:V8_A_RUN_ID,priorRunSha256:actualRunSha256,preregistrationDigest:V8_PREREG_DIGEST});
}

export function createV9Draft({base,baseBytes,pin,measurement,reconciliation,priorRunBytes}) {
 if(base?.rule!=='s2-008-prereg-v8'||base.preregistration_id!=='xpr-s2-008c-08'
  ||base.approval?.in_force!==true||base.preregistration_digest!==preregistrationDigest(base))
  throw new Error('V9_BASE_NOT_IN_FORCE');
 const reconciliationBinding=assertV8AReconciliation({reconciliation,priorRunBytes});
 const {commitment,covers}=assertV9PresealPin({pin,baseBytes});
 if(!measurement||!['input','output','cacheRead','totalTokens'].every(k=>Number.isSafeInteger(measurement[k])&&measurement[k]>=0)
  ||measurement.totalTokens<=0||!/^[0-9a-f]{64}$/.test(measurement.traceSha256??'')) throw new Error('V9_MEASUREMENT_INVALID');
 const calls=base.holdout_access.case_count*base.seed_count;
 const projected=calls*measurement.totalTokens;
 if(!Number.isSafeInteger(projected)||projected>base.budget_reservation.granted_units) throw new Error('V9_PROJECTION_EXCEEDS_CEILING');
 const draft={...base,rule:'s2-008-prereg-v9',preregistration_id:'xpr-s2-008c-09',
  executor:{...base.executor,...V8_EXECUTOR_POLICY,pi_settings:structuredClone(V7_PI_SETTINGS),
   inside_isolation:'LOCAL_RESTRICTED, digest-pinned, egress allowlist openrouter.ai:443 only',
   model_image:{...base.executor.model_image,content_commitment:commitment,covers,excludes:['prereg'],
    built_image_pin:'evidence/s2-008-campaign/model-image-pin-v9.json',
    built_image_pin_reason:'v9 built image binds this signed OpenRouter document; its acyclic content commitment excludes only the preregistration'}},
  budget_reservation:{...base.budget_reservation,reservation_id:'rsv-s2-008c-09',
   usd_reference:{confirmed_usd:null,confirmed_usd_status:'NOT_VERIFIED',
    why_null:'Client cost.total=0 is not an independently verified provider price.',
    measurement:structuredClone(measurement),measurement_basis:'one host-side call with tools ON; campaign runs with tools OFF',
    projection:{calls,cases_per_seed:base.holdout_access.case_count,seeds:base.seed_count,
     tokens_per_call:measurement.totalTokens,tokens_estimate:projected,status:'PROJECTION_NOT_MEASUREMENT',
     caveat:'Container configuration is not measured by this host trace. Actual usage is charged during execution; the ceiling is unchanged.'},
    ceiling_scope:'PER_RUN_A_OR_B',aggregate_spend:'Report A+B separately; historical unresolved v7 spend stays UNKNOWN'}},
  accounting_protocol:{schema:'s2-008-model-accounting/1',generation_id:'one unique observed assistant responseId for each v9 model call',
   usage_fields:['input','output','cacheRead','cacheWrite','totalTokens','reported_cost_usd'],
   prompt_token_basis:'input+cacheRead+cacheWrite',cost_basis:'executor-reported estimate; provider invoice not independently verified',
   partial_output:'per-case records become durable only after the isolated process returns; host power loss can leave only confirmed spend and an unknown attempt'},
  restart_reconciliation:{kind:reconciliationBinding.kind,file:'evidence/s2-008-campaign/reconciliation-v8-a.json',
   canonical_digest:reconciliationBinding.canonicalDigest,prior_run_id:reconciliationBinding.priorRunId,
   prior_run_sha256:reconciliationBinding.priorRunSha256,preregistration_digest:reconciliationBinding.preregistrationDigest},
  supersession:{supersedes:base.preregistration_id,superseded_digest:base.preregistration_digest,
   scope:'fresh run identity and reconciliation binding; frozen science, executor policy and 5M ceiling per A/B unchanged',
   reason:'v9 starts a fresh A/B copy only after the v8 A owner reconciliation is complete; provider, model, controls, and frozen science remain unchanged',
   unchanged:[...FROZEN_MEMBERS]},
  recorded_before_first_trial:{first_trial:'NOT_STARTED',proof:'The prior v8 A run is bound to the complete owner reconciliation showing zero matching campaign requests, zero campaign tokens and zero campaign cost. v7 remains separately unknown. v9 must use separate clean A/B copies.'},
  status:'DRAFT',approval:{status:null,authority:'HUMAN_OWNER',principal_id:null,label:null,issued_at:null,
   signed_digest_over:'the scientific body: every member except approval, status and preregistration_digest',
   in_force:false,becomes_in_force_when:'scripts/s2-008-campaign-prepare.mjs --seal-v9 records this digest and supersession in the corpus manifest'}};
 draft.preregistration_digest=preregistrationDigest(draft);
 const drift=scopeDrift(base,draft);
 if(drift) throw new Error('APPROVAL_SCOPE_DRIFT:'+drift.member);
 return draft;
}
export function approveV9({draft,base,baseBytes,pin,measurement,reconciliation,priorRunBytes,table,principal,label,issuedAt}) {
 if(typeof principal!=='string'||!/^prn-[a-z0-9-]+$/.test(principal)||typeof label!=='string'||!label.trim()
  ||typeof issuedAt!=='string'||!Number.isFinite(Date.parse(issuedAt))) throw new Error('V9_APPROVAL_IDENTITY_MISSING');
 if(draft?.rule!=='s2-008-prereg-v9'||draft.preregistration_id!=='xpr-s2-008c-09') throw new Error('V9_VERSION_MISMATCH');
 const reconciliationBinding=assertV8AReconciliation({reconciliation,priorRunBytes});
 if(draft.restart_reconciliation?.canonical_digest!==reconciliationBinding.canonicalDigest) throw new Error('V9_RECONCILIATION_BINDING_MISMATCH');
 if(draft.status!=='DRAFT'||draft.approval?.status!==null) throw new Error('V9_ALREADY_SIGNED');
 if(draft.preregistration_digest!==preregistrationDigest(draft)) throw new Error('V9_DIGEST_MISMATCH');
 const drift=scopeDrift(base,draft);
 if(drift) throw new Error('APPROVAL_SCOPE_DRIFT:'+drift.member);
 if(draft.expected_table_digest!==canonicalDigest(table)) throw new Error('V9_TABLE_MISMATCH');
 assertV6ModelTimeoutPolicy(draft.executor?.model_launch_timeout);
 assertV8ExecutorPolicy(draft.executor);
 const expected=createV9Draft({base,baseBytes,pin,measurement,reconciliation,priorRunBytes});
 if(canonicalDigest(scientificBody(expected))!==canonicalDigest(scientificBody(draft))) throw new Error('V9_SCOPE_MISMATCH');
 const signed={...scientificBody(draft),status:'APPROVED',
  approval:{...draft.approval,status:'APPROVED',authority:'HUMAN_OWNER',principal_id:principal,label,issued_at:issuedAt,in_force:false}};
 return Object.freeze({...signed,preregistration_digest:preregistrationDigest(signed)});
}
