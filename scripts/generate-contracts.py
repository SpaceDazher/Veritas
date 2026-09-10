"""Deterministic S2-001 public contract fixtures. Never reads private input."""
import json
from pathlib import Path

def write(path, data):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')

def obj(properties, required=None):
    return {'type':'object','additionalProperties':False,'properties':properties,'required':list(properties) if required is None else required}
def arr(items, minimum=0): return {'type':'array','items':items,'minItems':minimum}
def enum(*values): return {'enum':list(values)}
s = {'type':'string','minLength':1}
ref = lambda name: {'$ref': f'{name}.schema.json'}
unknown = obj({'status':{'const':'NEEDS_INPUT'},'owner':{'const':'user'},'blocks':arr(s,1),'reason':s})
def unresolved(blocks, reason): return {'status':'NEEDS_INPUT','owner':'user','blocks':blocks,'reason':reason}
def schema(name, body):
    write(f'contracts/{name}.schema.json', {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':f'https://veritas.local/contracts/{name}.schema.json',**body})
schema('needs-input', unknown)
settings = {
 'target_revision':(['a.checkout','a.benchmark'],'Approved target commit and legal repository/tool access are not supplied.'),
 'agent_access':(['a.real-adapters','a.benchmark'],'Codex/pi versions, models, authorization methods, host resources and installation availability have not been verified.'),
 'repository_permissions':(['a.agent-write','a.checkout'],'Local ticket editing does not authorize future pilot writes, network access or tool execution.'),
 'task_cost':(['a.execute','b.experiment'],'Approved numeric per-task amount and currency required, including local opportunity or provider costs.'),
 'campaign_cost':(['a.benchmark','b.experiment'],'Approved numeric campaign ceiling and currency required.'),
 'daily_cost':(['a.execute','b.experiment'],'Approved numeric daily ceiling and currency required.'),
 'max_duration':(['a.execute','b.experiment'],'Approved numeric timeout required.'),
 'budget_owner':(['budget.approve'],'Authenticated accountable budget owner identity not supplied; user is the input owner, not assumed payer.'),
 'decision_owner':(['solution.approve','research.approve'],'Authenticated final decision owner identity not supplied.'),
 'source_allowlist':(['b.import'],'Specific documents, Telegram channels and lawful permissions not supplied.'),
 'research_question':(['b.freeze','b.analyze'],'Pilot topic approved; exact geography, time interval, populations and causal estimand not supplied.'),
 'freshness_windows':(['b.current-claims'],'Numeric maximum age per source category requires approval.'),
 'quality_thresholds':(['a.select','b.accept'],'Baseline, quality minimum, coverage floor, non-inferiority delta and statistical decision rule require preregistration.'),
 'independent_reviewer':(['a.independent-eval','b.independent-eval'],'Independent qualified reviewer identity and conflict-of-interest checks not supplied.')
}
profile_props = {'version':{'const':'1.0.0'},'id':s,'status':{'const':'NEEDS_INPUT'},'project':{'const':'Veritas Agent Board'},'parallel_jobs':{'const':1},'parallel_jobs_basis':{'const':'User-approved MVP: one concurrent job; not execution authorization.'},'settings':obj({k:ref('needs-input') for k in settings})}
schema('pilot-profile',obj(profile_props))
schema('task-brief',obj({'version':{'const':'1.0.0'},'id':s,'scenario':enum('A','B'),'revision':{'type':'integer','minimum':1},'status':enum('NEEDS_INPUT','FROZEN'),'goal':s,'project':s,'scope':enum('personal','project','shared'),'input_refs':arr(s,1),'output_ids':arr(s,1),'acceptance_cases':s,'profile_ref':s,'manifest_ref':s,'metric_policy_ref':s,'change_policy':{'const':'New revision and human reapproval; old evaluations invalidated.'},'execution_authorized':{'const':False},'unknowns':arr(ref('needs-input'),1)}))
safe_id = {'type':'string','pattern':'^[a-zA-Z0-9_-]+$','maxLength':100}
source = obj({'id':safe_id,'category':enum('markdown','obsidian','telegram','youtube','web','pdf','arxiv','hugging-face','github','manual','official','expert'),'scope':enum('personal','project','shared'),'permission':enum('REFERENCE_ONLY','NEEDS_INPUT'),'selection':{'const':'NOT_IMPORTED'},'safe_reference':{'type':'string','pattern':r'^(redacted:[a-zA-Z0-9_-]+|repo:[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*(?:\.(?:md|json|txt))?)$'},'freshness':ref('needs-input'),'access':ref('needs-input')})
schema('source-selection-manifest',obj({'version':{'const':'1.0.0'},'id':s,'scenario':enum('A','B'),'status':{'const':'NEEDS_INPUT'},'contains_private_content':{'const':False},'import_authorized':{'const':False},'sources':arr(source,1)}))
artifact = obj({'id':s,'path':{'type':['string','null']},'sha256':{'anyOf':[{'type':'string','pattern':'^[a-f0-9]{64}$'},{'type':'null'}]},'status':enum('NOT_RUN','PRESENT'),'acceptance_case':s},None)
artifact['allOf']=[{'if':{'properties':{'status':{'const':'PRESENT'}}},'then':{'properties':{'path':s,'sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'}}},'else':{'properties':{'path':{'type':'null'},'sha256':{'type':'null'}}}}]
metrics = obj({'status':{'const':'NOT_MEASURED'},'denominator':{'type':'integer','const':0},'reason':s})
outputs_a = ['codex-pi-roles','configurations','skills-instructions','development-process','shared-kanban','project-memory','handoff-rules','eval-sets','measured-metrics','clean-checkout-install','rollback','evidence-pack','limitations-selection-reasons','human-approval-request']
outputs_b = ['source-map','claim-register','support-contradiction-map','expert-lenses','timeline','evidence-map','hypothesis-cards','alternative-explanations','dated-forecasts','unknowns','next-experiments','human-review-package']
for name, outputs in [('solution-pack',outputs_a),('research-dossier',outputs_b)]:
    schema(name,obj({'version':{'const':'1.0.0'},'id':s,'brief_ref':s,'status':{'const':'HUMAN_REVIEW'},'execution_status':enum('NOT_RUN','MEASURED'),'artifacts':obj({k:artifact for k in outputs}),'metrics':metrics,'selection_claim':{'const':'No empirical selection; no claim of absolute superiority.'},'human_decision_ref':s,'limitations':arr(s,1)}))
schema('human-decision',obj({'version':{'const':'1.0.0'},'id':s,'artifact_ref':s,'artifact_digest':{'type':['string','null'],'pattern':'^[a-f0-9]{64}$'},'status':enum('NEEDS_INPUT','APPROVED','REJECTED','CHALLENGED'),'actor_type':enum('human','unassigned'),'actor_id':{'type':['string','null']},'producer_id':s,'decision_scope':enum('solution','research','budget','permissions','production'),'reason':s,'timestamp':{'type':['string','null']},'authority':{'const':'Requires server-authenticated human identity; JSON is not authorization.'},'pending':{'anyOf':[ref('needs-input'),{'type':'null'}]}}))
p=Path('contracts/human-decision.schema.json'); data=json.loads(p.read_text()); data['allOf']=[{'if':{'properties':{'status':{'enum':['APPROVED','REJECTED','CHALLENGED']}}},'then':{'properties':{'actor_type':{'const':'human'},'actor_id':s,'artifact_digest':{'type':'string','pattern':'^[a-f0-9]{64}$'},'timestamp':s,'pending':{'type':'null'}}},'else':{'properties':{'actor_type':{'const':'unassigned'},'actor_id':{'type':'null'},'pending':ref('needs-input')}}}]; write(str(p), data)
case = obj({'id':s,'kind':enum('artifact','negative','mvp'),'input':s,'operation':s,'oracle':s,'expected':enum('PASS','BLOCKED','NEEDS_INPUT','HUMAN_REVIEW'),'evidence_required':s,'execution':enum('CONTRACT_TEST','NOT_RUN')})
schema('acceptance-cases',obj({'version':{'const':'1.0.0'},'scenario':enum('A','B'),'cases':arr(case,1)}))
checks_a = [
 'Verify Codex and pi responsibilities, executor/reviewer separation and actual version discovery.',
 'Load pinned configurations from clean checkout; compare secrets-free config digests.',
 'Resolve every skill/instruction version and prohibit instruction authority escalation.',
 'Replay documented development stages with test and review gates.',
 'Assert Web/API/CLI share canonical task revision and all nine states.',
 'Resolve project memory references within ACL; agent chat is not canonical.',
 'Revoke previous lease before handoff; old fencing token cannot write.',
 'Freeze held-out corpus and identical tasks, models, seeds and budgets before comparison.',
 'Recompute all METRIC_POLICY numerators, denominators, coverage and confidence intervals.',
 'Install pinned dependencies in isolated clean checkout and run documented fixture demo.',
 'Revert candidate without deleting journal; verify pre-change baseline tests.',
 'Resolve hashed artifacts to brief, manifest, executions and independent review.',
 'Bound winner to frozen corpus; document ties, unknowns and rejected candidates.',
 'Require authenticated non-producer human decision bound to artifact hash; pending is not approved.'
]
checks_b = [
 'Resolve source provenance, immutable digest, retrieval time, license, ACL and upstream lineage.',
 'Each claim has exact span, explicit fact/observation/opinion/hypothesis/forecast type and temporal scope.',
 'Label support and contradiction edges; count unique upstream families, not URLs.',
 'Include AI, energy, economics, state policy, infrastructure and science lenses; record disagreements.',
 'Order events by source time and distinguish publication, observation and retrieval time.',
 'Every conclusion links to claim and source spans; missing access is unresolved, not success.',
 'Every novel relation has type, basis, alternatives, scope, falsifier and confidence rationale.',
 'Enumerate confounding, reverse causality, selection effects and common causes.',
 'Each forecast has issue date, target date, resolution criteria and resolving source; none fabricated.',
 'Unknown register has user owner and operation-local blocks.',
 'Preregister question, hypothesis, design, numeric budget, measurements, verifier and stop rules before launch.',
 'Present contested conclusions, evidence limits and human decision request without automatic approval.'
]
probes = [
 ('goal-change','Hidden goal change after freeze','BLOCKED'),('threshold-change','Threshold changed after results','BLOCKED'),('missing-budget','Absent numeric spending authorization','NEEDS_INPUT'),('unknown-model','Unknown model or access method','NEEDS_INPUT'),('absolute-best','Claim absolutely best solution','BLOCKED'),('self-approval','Single model approves its output','BLOCKED'),('private-export','Private note included in public artifact','BLOCKED'),('source-injection','Source instruction changes agent permissions','BLOCKED'),('opinion-as-fact','Expert opinion promoted to fact','HUMAN_REVIEW'),('causal-overclaim','Unsupported causal relation asserted as knowledge','HUMAN_REVIEW'),('missing-source','Missing source counted as successful empty import','NEEDS_INPUT'),('research-rollout','AgentOS research verdict used for production authorization','BLOCKED'),
 ('double-claim','Two agents claim the same task','BLOCKED'),('forged-capability','Agent self-attests unregistered capability','BLOCKED'),('expired-lease','Lease expires while old worker writes','BLOCKED'),('agent-crash','Agent process crashes with unknown side effects','BLOCKED'),('empty-response','Provider returns empty response','BLOCKED'),('done-no-artifacts','Agent reports DONE without artifacts','BLOCKED'),('failed-tests','Result fails required tests','BLOCKED'),('adapter-criteria','Adapter mutates acceptance criteria','BLOCKED'),('self-grant','Agent grants itself tools or permissions','BLOCKED'),('replay','Duplicate operation replays a side effect','BLOCKED'),('open-dependency','Task starts with incomplete dependency','BLOCKED'),('cancel-zombie','Cancelled worker keeps writing','BLOCKED'),('unknown-retry','Unknown outcome retried without reconciliation','BLOCKED'),('private-leak','Private task disclosed to another user','BLOCKED'),('state-divergence','UI and API return different canonical revisions','BLOCKED')
]
for scenario, outputs, checks in [('A',outputs_a,checks_a),('B',outputs_b,checks_b)]:
    cases=[{'id':f'{scenario}-OUT-{i+1:02}','kind':'artifact','input':name,'operation':'Verify supplied artifact against frozen brief','oracle':check,'expected':'PASS','evidence_required':f'{name}: digest + test report + reviewer identity','execution':'NOT_RUN'} for i,(name,check) in enumerate(zip(outputs,checks))]
    for i,(key, description, state) in enumerate(probes):
        if scenario=='A' or i<12:
            cases.append({'id':f'NEG-{i+1:02}','kind':'negative','input':key,'operation':description,'oracle':f'Policy returns {state}; dependent operation has no side effect. Unit fixture only, not runtime certification.','expected':state,'evidence_required':'evidence/contract-tests.json','execution':'CONTRACT_TEST'})
    if scenario=='A':
        for i, text in enumerate(['Two distinct real agent adapters execute through the same versioned contract; record binaries, versions, access and runs.','Generic CLI discovery and an additional approved agent work without changing core.','Scheduler chooses READY tasks by priority then ID, validates registered capabilities, dependencies and budget; emits explanation.','Crash, timeout, cancellation terminate process group, fence late writes and reconcile unknown effects.','Human creates small repository change; claim, workspace, execute, tests, IN_REVIEW, authenticated human decision, journal replay.','Atomic lease race integration test with two concurrent workers yields exactly one lease.','Replay produces zero duplicate external effects using persistent idempotency keys.']):
            cases.append({'id':f'A-MVP-{i+1:02}','kind':'mvp','input':'Approved local runner and isolated repository fixture','operation':text,'oracle':'Check canonical journal and real runtime evidence; mocks alone do not pass.','expected':'PASS','evidence_required':'Runtime test log, agent versions, journal and artifact hashes','execution':'NOT_RUN'})
    write(f'pilots/scenario-{scenario.lower()}/acceptance-cases.json',{'version':'1.0.0','scenario':scenario,'cases':cases})
write('evidence/probe-registry.json',[{'id':f'NEG-{i+1:02}','probe':key,'expected':state} for i,(key,_,state) in enumerate(probes)])
write('pilots/pilot-profile.json',{'version':'1.0.0','id':'PILOT-S2-001','status':'NEEDS_INPUT','project':'Veritas Agent Board','parallel_jobs':1,'parallel_jobs_basis':'User-approved MVP: one concurrent job; not execution authorization.','settings':{k:unresolved(*v) for k,v in settings.items()}})
for scenario, outputs in [('A',outputs_a),('B',outputs_b)]:
    root=f'pilots/scenario-{scenario.lower()}'
    write(f'{root}/task-brief.json',{'version':'1.0.0','id':f'TB-{scenario}-001','scenario':scenario,'revision':1,'status':'NEEDS_INPUT','goal':('Prepare reproducible Codex/pi SolutionPack for Veritas Agent Board, a canonical human/agent Kanban with versioned adapters.' if scenario=='A' else 'Investigate links between AI development, energy, economics, state policy, compute infrastructure and scientific technologies; precise question pending.'),'project':'Veritas Agent Board' if scenario=='A' else 'Cross-domain research pilot','scope':'project' if scenario=='A' else 'personal','input_refs':['user-approved-project-specification','pilots/pilot-profile.json'],'output_ids':outputs,'acceptance_cases':f'{root}/acceptance-cases.json','profile_ref':'pilots/pilot-profile.json','manifest_ref':f'{root}/source-selection-manifest.json','metric_policy_ref':'docs/product/METRIC_POLICY.md','change_policy':'New revision and human reapproval; old evaluations invalidated.','execution_authorized':False,'unknowns':[unresolved(*settings[k]) for k in (['target_revision','agent_access','repository_permissions','task_cost','campaign_cost','daily_cost','max_duration','quality_thresholds','independent_reviewer','decision_owner'] if scenario=='A' else ['source_allowlist','research_question','freshness_windows','task_cost','campaign_cost','daily_cost','max_duration','independent_reviewer','decision_owner'])]})
    categories=['github','manual'] if scenario=='A' else ['obsidian','telegram','official','arxiv','expert','web']
    write(f'{root}/source-selection-manifest.json',{'version':'1.0.0','id':f'SSM-{scenario}-001','scenario':scenario,'status':'NEEDS_INPUT','contains_private_content':False,'import_authorized':False,'sources':[{'id':f'{scenario}-SRC-{i+1:02}','category':cat,'scope':'project' if scenario=='A' else 'personal','permission':'NEEDS_INPUT','selection':'NOT_IMPORTED','safe_reference':f'redacted:{cat}-selection-pending','freshness':unresolved(['current-claims'],'Owner must approve category-specific numeric freshness window.'),'access':unresolved([f'{scenario.lower()}.import.{cat}'],'Specific safe source identifier and lawful technical access must be approved.')} for i,cat in enumerate(categories)]})
    name='solution-pack' if scenario=='A' else 'research-dossier'
    write(f'{root}/{name}.example.json',{'version':'1.0.0','id':f'{scenario}-OUTPUT-TEMPLATE','brief_ref':f'{root}/task-brief.json','status':'HUMAN_REVIEW','execution_status':'NOT_RUN','artifacts':{k:{'id':k,'path':None,'sha256':None,'status':'NOT_RUN','acceptance_case':f'{scenario}-OUT-{i+1:02}'} for i,k in enumerate(outputs)},'metrics':{'status':'NOT_MEASURED','denominator':0,'reason':'No authorized pilot executions; no empirical quality claims.'},'selection_claim':'No empirical selection; no claim of absolute superiority.','human_decision_ref':f'{root}/human-decision.example.json','limitations':['Template only. Required outputs not produced. Pilot execution blocked by unresolved inputs.']})
    write(f'{root}/human-decision.example.json',{'version':'1.0.0','id':f'HD-{scenario}-PENDING','artifact_ref':f'{root}/{name}.example.json','artifact_digest':None,'status':'NEEDS_INPUT','actor_type':'unassigned','actor_id':None,'producer_id':'s2-001-contract-builder','decision_scope':'solution' if scenario=='A' else 'research','reason':'No execution evidence or authenticated human approval.','timestamp':None,'authority':'Requires server-authenticated human identity; JSON is not authorization.','pending':unresolved([f'{scenario.lower()}.final-approval'],'An authenticated non-producer human must review the exact artifact digest.')})
# Adversarial hardening: a measured result cannot be an empty draft, and a frozen brief has no unresolved inputs.
for name,outputs in [('solution-pack',outputs_a),('research-dossier',outputs_b)]:
 p=f'contracts/{name}.schema.json'; data=json.loads(Path(p).read_text())
 measure=obj({'name':s,'numerator':{'type':'number','minimum':0},'denominator':{'type':'number','exclusiveMinimum':0},'coverage':{'type':'number','minimum':0,'maximum':1},'unit':s,'method_ref':s,'evidence_ref':s,'limitations':arr(s)})
 measured=obj({'status':{'const':'MEASURED'},'records':arr(measure,14)})
 data['properties']['metrics']={'oneOf':[metrics,measured]}
 data['allOf']=[{'if':{'properties':{'execution_status':{'const':'MEASURED'}}},'then':{'properties':{'metrics':measured,'artifacts':{'properties':{k:{'properties':{'status':{'const':'PRESENT'}}} for k in outputs}}}},'else':{'properties':{'metrics':metrics,'artifacts':{'properties':{k:{'properties':{'status':{'const':'NOT_RUN'}}} for k in outputs}}}}}]
 write(p,data)
p='contracts/task-brief.schema.json';data=json.loads(Path(p).read_text());data['properties']['unknowns']['minItems']=0;data['allOf']=[{'if':{'properties':{'status':{'const':'FROZEN'}}},'then':{'properties':{'unknowns':{'maxItems':0}}},'else':{'properties':{'unknowns':{'minItems':1}}}}];write(p,data)
# Future user-provided approvals are representable without inventing any fixture values.
p='contracts/pilot-profile.schema.json';data=json.loads(Path(p).read_text());confirmed={}
for key in settings:
 value = (obj({'amount':{'type':'number','minimum':0},'currency':{'type':'string','pattern':'^[A-Z]{3}$'}}) if key in ['task_cost','campaign_cost','daily_cost'] else {'type':'number','exclusiveMinimum':0} if key=='max_duration' else arr(s,1))
 confirmed[key]=obj({'status':{'const':'CONFIRMED'},'owner':s,'value':value,'unit':s,'approval_ref':s})
 data['properties']['settings']['properties'][key]={'oneOf':[ref('needs-input'),confirmed[key]]}
data['properties']['status']=enum('NEEDS_INPUT','READY');data['allOf']=[{'if':{'properties':{'status':{'const':'READY'}}},'then':{'properties':{'settings':obj(confirmed)}}}];write(p,data)
print('Generated schemas, acceptance matrices, safe pilot drafts and pending output templates.')
