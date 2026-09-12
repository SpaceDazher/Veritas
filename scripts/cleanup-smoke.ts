import 'dotenv/config';
import {db,pool} from '../src/db/index';
import {boardTasks,boardEvents} from '../src/db/schema';
import {inArray} from 'drizzle-orm';
import fs from 'node:fs';
async function main(){
 const report=JSON.parse(fs.readFileSync('evidence/workspace-smoke.json','utf8'));
 const ids:string[]=report.createdTaskIds;
 if(ids.length)await db.transaction(async tx=>{await tx.delete(boardEvents).where(inArray(boardEvents.taskId,ids));await tx.delete(boardTasks).where(inArray(boardTasks.id,ids));});
 console.log(`Removed ${ids.length} explicitly recorded synthetic test tasks and events. No other rows touched.`);
 await pool.end();
}
main().catch(e=>{console.error(e);process.exit(1)});
