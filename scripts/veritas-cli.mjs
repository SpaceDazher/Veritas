#!/usr/bin/env node
// Public demo client only. Not an executable agent adapter.
const base=process.env.VERITAS_URL||'http://localhost:3000';
const [command,...args]=process.argv.slice(2);
const help='Usage: node scripts/veritas-cli.mjs capabilities|discovery|tasks|events|create <public title>';
try{
 let response;
 if(['capabilities','discovery'].includes(command))response=await fetch(`${base}/api/capabilities`);
 else if(['tasks','events'].includes(command))response=await fetch(`${base}/api/board`);
 else if(command==='create'&&args.length)response=await fetch(`${base}/api/board`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'create',operationId:crypto.randomUUID(),title:args.join(' '),description:'Synthetic planning task created through CLI',priority:'Medium',criteria:[]})});
 else {console.log(help);process.exit(command?1:0);}
 const data=await response.json();if(!response.ok)throw new Error(JSON.stringify(data));
 console.log(JSON.stringify(command==='tasks'?data.tasks:command==='events'?data.events:data,null,2));
}catch(e){console.error(String(e));process.exit(1);}
