import {NextRequest,NextResponse} from 'next/server';
import {db} from '@/db';
import {boardTasks,boardEvents} from '@/db/schema';
import {and,eq} from 'drizzle-orm';
import {getBoard} from '@/lib/board';
import {randomUUID,createHash} from 'node:crypto';
export const dynamic='force-dynamic';
export async function GET(){return NextResponse.json(await getBoard());}
export async function POST(req:NextRequest){
 const origin=req.headers.get('origin');
 if(origin && origin!==new URL(req.url).origin && origin!==`${req.headers.get('x-forwarded-proto')||'https'}://${req.headers.get('host')}`) return NextResponse.json({error:'Cross-origin mutation blocked'},{status:403});
 let body;try{body=await req.json();}catch{return NextResponse.json({error:'Invalid JSON'},{status:400});}
 if(!body || typeof body!=='object'||Array.isArray(body))return NextResponse.json({error:'Object required'},{status:400});
 const {operationId,action}=body;
 if(typeof operationId!=='string'|| !/^[a-zA-Z0-9-]{8,80}$/.test(operationId))return NextResponse.json({error:'Valid operationId required'},{status:400});
 if(!['create','update'].includes(action))return NextResponse.json({error:'Execution and approval operations are not enabled'},{status:403});
 const allowed=action==='create'?['operationId','action','title','description','priority','criteria']:['operationId','action','id','revision','status','reason'];
 if(Object.keys(body).some(k=>!allowed.includes(k)))return NextResponse.json({error:'Unknown fields or authority changes are not permitted'},{status:400});
 const requestHash=createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(k=>[k,body[k]])))).digest('hex');
 try{
 const result=await db.transaction(async tx=>{
  const [previous]=await tx.select().from(boardEvents).where(eq(boardEvents.operationId,operationId));
  if(previous){if(previous.requestHash!==requestHash)throw new Error('CONFLICT: idempotency key reused with different payload');return {id:previous.taskId,replayed:true};}
  if(action==='create'){
   if(typeof body.title!=='string'||body.title.trim().length<3||body.title.length>160)throw new Error('Title must be 3–160 characters');
   if(typeof body.description!=='string'||body.description.length>2000)throw new Error('Description must be at most 2000 characters');
   if(!['Low','Medium','High'].includes(body.priority))throw new Error('Invalid priority');
   if(!Array.isArray(body.criteria)||body.criteria.length>12||!body.criteria.every((x:unknown)=>typeof x==='string'&&x.length>0&&x.length<=300))throw new Error('Invalid acceptance criteria');
   const id=`VT-${randomUUID().slice(0,8).toUpperCase()}`;
   const [task]=await tx.insert(boardTasks).values({id,title:body.title.trim(),description:body.description,priority:body.priority,criteria:body.criteria,status:'BACKLOG',agent:'Unassigned',category:'Platform'}).returning();
   await tx.insert(boardEvents).values({taskId:id,action:'Task created',detail:'Public planning task created. No execution authorization.',revision:1,operationId,requestHash,snapshot:task});
   return {id,replayed:false};
  }
  if(typeof body.id!=='string')throw new Error('Task ID is required');
  const [task]=await tx.select().from(boardTasks).where(eq(boardTasks.id,body.id)).for('update');
  if(!task)throw new Error('Task not found');
  if(!Number.isInteger(body.revision)||body.revision!==task.revision)throw new Error('CONFLICT: stale revision; refresh before editing');
  if(!['BACKLOG','READY','BLOCKED','IN_REVIEW','CANCELLED'].includes(body.status))throw new Error('BLOCKED: execution and DONE require unavailable runtime and human authority');
  const detail=typeof body.reason==='string'?body.reason.trim().slice(0,500):'';
  if(body.status==='BLOCKED'&&!detail)throw new Error('A blocking reason is required');
  const revision=task.revision+1;
  const [updated]=await tx.update(boardTasks).set({status:body.status,revision}).where(and(eq(boardTasks.id,task.id),eq(boardTasks.revision,task.revision))).returning();
  await tx.insert(boardEvents).values({taskId:task.id,action:`${task.status} → ${body.status}`,detail:detail||'Planning state changed; this is not a run or final approval.',revision,operationId,requestHash,snapshot:updated});
  return {id:task.id,replayed:false};
 });
 return NextResponse.json(result);
 }catch(e){
  const [previous]=await db.select().from(boardEvents).where(eq(boardEvents.operationId,operationId));
  if(previous){if(previous.requestHash!==requestHash)return NextResponse.json({error:'CONFLICT: idempotency key reused with different payload'},{status:409});return NextResponse.json({id:previous.taskId,replayed:true});}
  const message=e instanceof Error?e.message:'Operation failed';
  if(message.includes('CONFLICT'))return NextResponse.json({error:message},{status:409});
  if(message.includes('Failed query'))return NextResponse.json({error:'Database rejected operation'},{status:400});
  return NextResponse.json({error:message},{status:400});
 }
}
