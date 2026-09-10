import hashlib,json,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1])
files=['S1-019/S1-019_CLOSURE.md','S1-019/results/technical-decision.json','S1-019/operator-decision.json','S1-019/results/evidence/evidence-pack-84499e38f1b8a917798fc306d03252f7abace00527017d115c6ce11f202f96be.json','S1-020/S1-020_CLOSURE.md','S1-020/results/summary.json','S1-020/evaluation-record.json']
base=root/'research/tickets/stage-1'
# Resolve actual pack through the evaluation record; never claim a chain was independently rerun.
for pack in sorted((base/'S1-020/results/evidence').glob('evidence-pack-*.json')): files.append(str(pack.relative_to(base)))
records=[]
for f in files:
 p=base/f
 if not p.exists():raise SystemExit('Missing dependency evidence: '+f)
 data=p.read_bytes();records.append({'path':'research/tickets/stage-1/'+f,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
report={'veritas_base_commit':'57ce8a4a6a607c4a421ee12dc49c6dd854d404b5','veritas_base_files':['README.md'],'sandbox_origin':'Additional provided Next.js/PostgreSQL starter; no initial .git','branch':'codex/s2-001-product-contract','issue':'https://github.com/SpaceDazher/Veritas/issues/1','issue_http_status':200,'issue_dependencies':['S1-019','S1-020'],'agentos_commit':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'dependency_verdicts':{'S1-019':'PASS_WITH_LIMITS','S1-020':'PASS_WITH_LIMITS'},'production_authority':False,'goal_acceptance_authority':False,'verification_scope':'Read public closure/decision/evaluation records and resolve referenced evidence at pinned checkout; SHA-256 file integrity inventory only. Stage 1 runners and canonical artifact-chain algorithm NOT independently rerun.','records':records}
Path('evidence/baseline.json').write_text(json.dumps(report,indent=2)+'\n')
print('Baseline and safe dependency hash inventory saved; no private source content copied.')
