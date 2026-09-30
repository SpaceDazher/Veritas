import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import { main, ARM_ERRORS } from '../../scripts/s2-008-campaign-arm-model.mjs';
import { modelTrialArgv } from '../../scripts/s2-008-campaign-adapter.mjs';
import { runV4Campaign } from '../../scripts/s2-008-campaign-run.mjs';

const MODEL = 'arm-model-zai-glm53flash';

function signed(granted = 100) {
  const body = {
    rule: 's2-008-prereg-v5',
    budget_reservation: { currency: 'tokens', granted_units: granted, trial_timeout_ms: 1000 },
    executor: { provider: 'zai-coding-cn', model: 'glm-5.3-flash', credential_env_name: 'ZAI_API_KEY' },
    status: 'APPROVED',
    approval: { status: 'APPROVED', signed_digest_over: 'scientific body', in_force: true },
  };
  return { ...body, preregistration_digest: preregistrationDigest(body) };
}

test('adapter passes validated remaining token cap as a numeric argv pair', () => {
  const args = modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: false, remainingTokens: 55 });
  assert.deepEqual(args.slice(-2), ['--remaining-tokens', '55']);
  assert.throws(() => modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: false }), /SHARED_TOKEN_CAP_REQUIRED/);
  assert.throws(() => modelTrialArgv({ armId: MODEL, seed: 20260926, dryRun: false, remainingTokens: -1 }), /SHARED_TOKEN_CAP_INVALID/);
});

test('arm uses min(signed grant, remaining cap) and exits nonzero at the shared limit', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-cap-'));
  try {
    const input = path.join(dir, 'in.json');
    const out = path.join(dir, 'out.json');
    const pre = path.join(dir, 'pre.json');
    writeFileSync(input, JSON.stringify([{case_id:'a',subject:'one'},{case_id:'b',subject:'two'},{case_id:'c',subject:'three'}]));
    writeFileSync(pre, JSON.stringify(signed(100)));
    let calls = 0;
    const code = await main([input,out,MODEL,pre,'1','--remaining-tokens','20'], {ZAI_API_KEY:'canary-credential-value'}, {
      startBridge: async () => ({host:'127.0.0.1',port:45123,stop:()=>true}),
      callModel: () => { calls += 1; return {text:'MINOR',usage:{totalTokens:10,cost:{total:0}},model_called:true}; },
    });
    assert.equal(code, 6);
    assert.equal(calls, 2);
    const report = JSON.parse(readFileSync(out,'utf8'));
    assert.equal(report.budget.granted_tokens,100);
    assert.equal(report.budget.launch_cap_tokens,20);
    assert.equal(report.budget.spent_tokens,20);
    assert.equal(report.budget.exhausted,true);
    assert.equal(report.stop.stopped_before_case,'c');
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('missing or invalid remaining cap refuses before bridge or pi', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-cap-'));
  try {
    const input=path.join(dir,'in.json'), out=path.join(dir,'out.json'), pre=path.join(dir,'pre.json');
    writeFileSync(input,JSON.stringify([{case_id:'a',subject:'one'}]));
    writeFileSync(pre,JSON.stringify(signed()));
    let starts=0;
    const deps={startBridge:async()=>{starts+=1;throw new Error('should not start');},callModel:()=>{starts+=1;throw new Error('should not call');}};
    assert.equal(await main([input,out,MODEL,pre,'1'],{ZAI_API_KEY:'canary-credential-value'},deps),11);
    assert.equal(await main([input,out,MODEL,pre,'1','--remaining-tokens','NaN'],{ZAI_API_KEY:'canary-credential-value'},deps),11);
    assert.equal(starts,0);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('signed v4 paid path refuses before any model launch until successor is sealed', async () => {
  const dir=mkdtempSync(path.join(tmpdir(),'veritas-cap-'));
  try {
    const prereg=JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/preregistration.v4.in-force.json',import.meta.url)));
    const manifest={preregistration:{file:'preregistration.v4.in-force.json',status:'IN_FORCE',preregistration_digest:prereg.preregistration_digest}};
    let launched=false;
    const result=await runV4Campaign({label:'cap-test',write:false,dryRun:false,prereg,manifest,
      dispatchableArms:[MODEL],runModel:async()=>{launched=true;throw new Error('paid launch');},
      buildRegex:()=>{launched=true;throw new Error('build');},
    });
    assert.equal(result.status,'BLOCKED');
    assert.match(result.reason,/MODEL_CAP_RESEAL_REQUIRED/);
    assert.equal(result.launches,0);
    assert.equal(launched,false);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});


test('v5 scientific body uses full-body digest so cap and pin fields cannot drift', async () => {
  const { preregistrationDigest } = await import('../../src/lib/research/preregistration.mjs');
  const { canonicalDigest } = await import('../../src/lib/verifier/canonical-json.mjs');
  const document = signed();
  const { approval, status, preregistration_digest, ...body } = document;
  assert.equal(preregistrationDigest(document), canonicalDigest(body));
  const edited = { ...document, budget_reservation: { ...document.budget_reservation, granted_units: 101 } };
  assert.notEqual(preregistrationDigest(edited), preregistrationDigest(document));
});


test('successor argv names v5 document and v5 pin is required before a paid launch', async () => {
  const { modelTrialArgv, assertPinnedModelImage } = await import('../../scripts/s2-008-campaign-adapter.mjs');
  const base = JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/preregistration.v4.in-force.json', import.meta.url)));
  const next = { ...base, rule: 's2-008-prereg-v5', executor: { ...base.executor, model_image: { ...base.executor.model_image, built_image_pin: 'evidence/s2-008-campaign/model-image-pin-v5.json' } } };
  assert.ok(modelTrialArgv({armId:MODEL,seed:20260926,remainingTokens:10,preregRule:next.rule}).some((value)=>value.includes('preregistration.v5.in-force.json')));
  assert.throws(() => assertPinnedModelImage({
    pin: JSON.parse(readFileSync(new URL('../../evidence/s2-008-campaign/model-image-pin-v4.json', import.meta.url))),
    prereg: next, inspect: () => { throw new Error('inspection must not run'); },
  }), /MODEL_IMAGE_PIN_VERSION_MISMATCH/);
});


test('v4 dry-run keeps the old no-cap argv while successor uses versioned names', async () => {
  const document=JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/preregistration.v4.in-force.json',import.meta.url)));
  const manifest={preregistration:{file:'preregistration.v4.in-force.json',status:'IN_FORCE',preregistration_digest:document.preregistration_digest}};
  let received='unseen';
  const result=await runV4Campaign({label:'cap-dry',arm:MODEL,seed:20260926,dryRun:true,write:false,
    prereg:document,manifest,
    runModel:async({remainingTokens})=>{
      received=remainingTokens;
      return {ok:true,output:{outcome_class:'DRY_RUN',budget:{currency:'tokens',spent_tokens:0,unreconciled_spend:false},executor:{model_calls:0},predictions:[]},
        record:{exit_code:0,image:'dry-image',predictions:null}};
    },
  });
  assert.equal(received,undefined);
  assert.equal(result.kind,'s2-008-campaign-v4-predictions/1');
  assert.equal(result.status,'DRY_RUN');
});


test('paid successor refuses a v4 image pin before any build or model launch', async () => {
  const next=JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/preregistration.v6.in-force.json',import.meta.url)));
  const manifest=JSON.parse(readFileSync(new URL('../../corpus/s2-008-campaign/manifest.json',import.meta.url)));
  let launched=false;
  const result=await runV4Campaign({label:'pin-gate',write:false,dryRun:false,prereg:next,manifest,
    modelPin:JSON.parse(readFileSync(new URL('../../evidence/s2-008-campaign/model-image-pin-v4.json',import.meta.url))),
    runModel:async()=>{launched=true;throw new Error('unexpected');},
    buildRegex:()=>{launched=true;throw new Error('unexpected');},
    resolveBaseFn:()=>({commit_sha:'a'.repeat(40),tree_sha:'b'.repeat(40),worktree_dirty:false}),
    now:()=>Date.parse('2026-09-30T00:00:00.000Z'),
  });
  assert.equal(result.status,'BLOCKED');
  assert.match(result.reason,/MODEL_IMAGE_PIN_INVALID/);
  assert.equal(launched,false);
});
