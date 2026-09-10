import Workspace from '@/components/workspace';
import {getBoard} from '@/lib/board';
import fs from 'node:fs/promises';
import {join} from 'node:path';
export const dynamic='force-dynamic';
export default async function Home(){
 const board=await getBoard();
 const paths=['docs/product/PRODUCT_CONTRACT.md','docs/product/PILOT_PROFILE.md','docs/product/AUTONOMY_POLICY.md','docs/product/METRIC_POLICY.md','docs/product/HUMAN_APPROVAL_POLICY.md','docs/scenarios/SCENARIO_A_CODEX_PI_HARNESS.md','docs/scenarios/SCENARIO_B_CROSS_DOMAIN_RESEARCH.md','docs/decisions/OPEN_DECISIONS.md'];
 const documents=await Promise.all(paths.map(async path=>({path,title:path.split('/').pop()!.replace('.md','').split('_').map(x=>x.charAt(0)+x.slice(1).toLowerCase()).join(' '),content:await fs.readFile(join(process.cwd(),'docs',path.slice(5)),'utf8')})));
 const sources=JSON.parse(await fs.readFile('pilots/scenario-b/source-selection-manifest.json','utf8'));
 return <Workspace initial={{...board,tasks:board.tasks.map(t=>({...t,createdAt:t.createdAt.toISOString()})),events:board.events.map(e=>({...e,createdAt:e.createdAt.toISOString()}))}} documents={documents} sources={sources.sources}/>;
}
