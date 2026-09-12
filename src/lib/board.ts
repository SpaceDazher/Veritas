import {db} from '@/db';
import {boardTasks,boardEvents} from '@/db/schema';
import {asc,desc,sql} from 'drizzle-orm';
const fixtures = [
 ['VT-001','Define the versioned adapter contract','One shared interface for every agent. Define discovery, capabilities and typed errors.','BACKLOG','High','Unassigned','Architecture',['Define all ten adapter methods','Document version negotiation','Enumerate typed errors']],
 ['VT-002','Set up project memory','Define a shared, versioned memory layer. Chat history is not canonical state.','BACKLOG','Medium','Unassigned','Knowledge',['Specify scoped memory references','Define retention and redaction']],
 ['VT-003','Document rollback & recovery','Capture a reproducible path back to the last known-good state.','BACKLOG','Low','Unassigned','Documentation',['Define rollback command contract','Preserve the audit journal']],
 ['VT-004','Build capabilities discovery','A machine-readable contract for agents to discover the board safely.','READY','High','Codex','API',['List all nine canonical states','Return contract version','Never expose credentials']],
 ['VT-005','Design atomic task leases','Make simultaneous claims safe with transactions and fencing tokens.','READY','High','pi','Core',['Exactly one active lease','Reject stale fencing tokens','Use database time']],
 ['VT-006','Define source provenance','Trace every claim back to a versioned, access-controlled source.','READY','Medium','Unassigned','Knowledge',['Record immutable snapshot hash','Preserve source scope and lineage']],
 ['VT-007','Create the canonical task model','A single source of truth across the Web, HTTP API and CLI.','RUNNING','High','Codex','Core',['Specify nine task states','Keep a transition journal','Require expected revision']],
 ['VT-008','Draft the scheduler policy','Match eligible tasks with registered capabilities and explain every choice.','RUNNING','Medium','pi','Orchestration',['One simultaneous job','Check dependencies and budget','Log deterministic selection']],
 ['VT-009','Map the human review flow','Keep humans in control of final decisions and critical actions.','RUNNING','Medium','Unassigned','Design',['Define approve and challenge','Prevent agent self-approval']],
 ['VT-010','Freeze the product contract','Define the first version of Veritas and its boundary with AgentOS.','IN_REVIEW','High','Unassigned','Documentation',['Record explicit unknowns','Separate research from production','Map acceptance cases']],
 ['VT-011','Review safety & autonomy gates','Fail closed on missing budgets, unknown access and permission changes.','IN_REVIEW','High','pi','Safety',['Block missing budget','Quarantine source instructions','Require human final approval']],
 ['VT-012','Specify cross-domain research','Link evidence, contradictions and hypotheses without inventing certainty.','IN_REVIEW','Medium','Unassigned','Research',['Type claims explicitly','Document alternative explanations','Keep private content out of Git']],
] as const;
export async function ensureBoard(){
 await db.transaction(async tx=>{
  for(const [id,title,description,status,priority,agent,category,criteria] of fixtures){
   const inserted=await tx.insert(boardTasks).values({id,title,description,status,priority,agent,category,criteria:[...criteria]}).onConflictDoNothing().returning();
   if(inserted.length) await tx.insert(boardEvents).values({taskId:id,action:'Fixture created',detail:'Synthetic planning fixture. Status and suggested agent do not represent a real execution.',revision:1,operationId:`seed-${id}`,snapshot:inserted[0]}).onConflictDoNothing();
  }
 });
}
export async function getBoard(){
 await ensureBoard();
 return db.transaction(async tx=>{
  await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`);
  const tasks=await tx.select().from(boardTasks).orderBy(asc(boardTasks.id));
  const events=await tx.select().from(boardEvents).orderBy(desc(boardEvents.id));
  return {mode:'PUBLIC_SYNTHETIC_DEMO',contractVersion:'1.0.0',canonicalRevision:events[0]?.id??0,tasks,events};
 });
}
export const capabilities={contractVersion:'1.0.0',mode:'PUBLIC_SYNTHETIC_DEMO',interfaces:['web','http','cli'],states:['BACKLOG','READY','CLAIMED','RUNNING','BLOCKED','IN_REVIEW','DONE','FAILED','CANCELLED'],operations:['tasks.list','tasks.create','tasks.edit-planning','events.list','capabilities'],adapters:[],executionEnabled:false,approvalEnabled:false,privateDataAllowed:false,limits:'Contract workspace only. No authentication, real adapters, leases or process runner. Do not submit private data.'};
