// S2-008 #12 — the egress forwarder, pinned as the PRIMITIVE the paid leg needs.
//
// The pieces for a working egress already exist: `createEgressForwarder` speaks
// HTTP CONNECT over a unix socket, and the profile's declared allowlist is exactly
// the z.ai API. What does NOT exist is the client half — pi is an
// openai-completions client that needs an HTTP proxy on a LOOPBACK PORT, not a
// unix socket, so something inside the container must bridge them.
//
// These cases pin the primitive that bridge will sit on, because it is the
// security boundary: the forwarder must admit the one declared destination and
// refuse everything else, and it must be impossible to build it into a
// pass-through. None of this contacts the model, spends a token, or starts a
// campaign: the allowlisted host is a REAL socket connection, and the refused
// ones are proved refused.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect, createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createEgressForwarder, parseConnectRequest } from '../../src/lib/isolation/egress.mjs';
import { ISOLATION_EGRESS_ALLOWLIST } from '../../src/lib/isolation/profile.mjs';

const ALLOWED = { host: 'open.bigmodel.cn', port: 443 };

/** The client half, written the way an in-container bridge would have to write it. */
function sendConnect(socketPath, host, port, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    const client = connect(socketPath);
    let buffer = '';
    const done = (verdict) => {
      try {
        client.destroy();
      } catch { /* the socket may already be gone */ }
      resolve(verdict);
    };
    const timer = setTimeout(() => done({ outcome: 'TIMEOUT', head: buffer.slice(0, 120) }), timeoutMs);
    client.setEncoding('utf8');
    client.on('connect', () => client.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    client.on('data', (chunk) => {
      buffer += chunk;
      clearTimeout(timer);
      if (buffer.length > 0) done({ outcome: 'ANSWERED', head: buffer.slice(0, 120) });
    });
    client.on('error', (error) => {
      clearTimeout(timer);
      done({ outcome: 'ERROR', head: String(error?.code ?? error?.message ?? '') });
    });
  });
}

/**
 * `createEgressForwarder` returns a HANDLE, not a bound server: nothing is bound
 * until its `listen()` promise resolves. Connecting first gives ENOENT, which is
 * neither an admission nor a refusal — just a race. The campaign's launcher must
 * await `listen()` for the same reason, and that is recorded here because it is
 * the kind of thing that looks like a policy failure when it is a startup race.
 */
async function withForwarder(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-egress-'));
  const socketPath = path.join(dir, 'egress.sock');
  const decisions = [];
  const server = createEgressForwarder({
    allowlist: ISOLATION_EGRESS_ALLOWLIST,
    socketPath,
    log: (decision) => decisions.push(decision),
  });
  await server.listen();
  try {
    return await fn({ socketPath, decisions, forwarder: server, dir });
  } finally {
    try {
      server.close();
    } catch { /* the handle may not expose a closer; the process exits anyway */ }
    rmSync(dir, { recursive: true, force: true });
  }
}

test('the declared allowlist is the one destination the paid leg needs, and nothing else', () => {
  assert.deepEqual(ISOLATION_EGRESS_ALLOWLIST.map((e) => ({ host: e.host, ports: [...e.ports] })), [
    { host: 'open.bigmodel.cn', ports: [443] },
  ]);
  // A second entry, or a wildcard, would be a wider exit than anyone measured.
  assert.equal(ISOLATION_EGRESS_ALLOWLIST.length, 1, 'the allowlist names more than one destination');
  assert.equal(ISOLATION_EGRESS_ALLOWLIST.some((e) => e.host === '*'), false);
});

test('a CONNECT request is parsed, and a malformed one is not', () => {
  // The parser returns the method too; a reader of this test should see that.
  assert.deepEqual(parseConnectRequest(`CONNECT ${ALLOWED.host}:443 HTTP/1.1\r\n\r\n`), { ...ALLOWED, method: 'CONNECT' });
  for (const bad of ['', 'hello', 'CONNECT nonsense HTTP/1.1', 'CONNECT host:0 HTTP/1.1', 'CONNECT :443 HTTP/1.1', 'CONNECT host:99999 HTTP/1.1']) {
    assert.equal(parseConnectRequest(bad), null, `${JSON.stringify(bad)} parsed as a request`);
  }
});

test('the allowlisted destination is ADMITTED and a real socket is opened', async () => {
  await withForwarder(async ({ socketPath, decisions }) => {
    const answer = await sendConnect(socketPath, ALLOWED.host, ALLOWED.port);
    assert.notEqual(answer.outcome, 'ERROR', `the allowed destination was not reachable: ${JSON.stringify(answer)}`);
    assert.match(answer.head, /HTTP\/1\.[01] 200|200 OK/, `the forwarder did not admit the allowlisted destination: ${JSON.stringify(answer)}`);
    // The log row is `{decision: 'ADMITTED'|'REFUSED', host, port, method}` —
    // a named outcome, not a boolean, and the code is the interface a reader uses.
    const admitted = decisions.filter((d) => d.decision === 'ADMITTED');
    assert.equal(admitted.length, 1, `expected exactly one admission, got ${JSON.stringify(decisions)}`);
    assert.equal(admitted[0].host, ALLOWED.host);
    assert.equal(admitted[0].port, ALLOWED.port);
    assert.equal(admitted[0].method, 'CONNECT');
    assert.equal(decisions.filter((d) => d.decision === 'REFUSED').length, 0, 'the allowed destination was also refused somewhere');
  });
});

test('EVERY other destination is refused, and each refusal is recorded', async () => {
  await withForwarder(async ({ socketPath, decisions }) => {
    const denied = [
      { host: 'evil.example.com', port: 443, why: 'a host that is not on the allowlist' },
      { host: ALLOWED.host, port: 22, why: 'the right host on the wrong port' },
      { host: 'open.bigmodel.cn', port: 8443, why: 'a neighbouring port' },
      { host: 'api.openai.com', port: 443, why: 'another provider entirely' },
    ];
    for (const target of denied) {
      const answer = await sendConnect(socketPath, target.host, target.port);
      assert.equal(/200 OK/.test(answer.head ?? ''), false, `${target.why} was admitted: ${JSON.stringify(answer)}`);
      assert.match(answer.head ?? '', /403 Forbidden/, `${target.why} was not answered 403: ${JSON.stringify(answer)}`);
      assert.ok(
        decisions.some((d) => d.decision === 'REFUSED' && d.host === target.host && d.port === target.port),
        `no refusal was recorded for ${target.host}:${target.port} (${target.why}); decisions: ${JSON.stringify(decisions)}`,
      );
    }
  });
});

test('a refusal records the DECISION and never the payload', async () => {
  await withForwarder(async ({ socketPath, decisions }) => {
    await sendConnect(socketPath, 'evil.example.com', 443);
    for (const decision of decisions) {
      assert.ok(['ADMITTED', 'REFUSED', 'UPSTREAM_FAILED'].includes(decision.decision),
        `an unnamed decision reached the log: ${JSON.stringify(decision)}`);
      assert.equal(typeof decision.host, 'string');
      // A forwarder that logged request bodies would leak whatever the model sent.
      assert.equal(Object.prototype.hasOwnProperty.call(decision, 'payload'), false, 'a decision carries a payload');
      assert.equal(Object.prototype.hasOwnProperty.call(decision, 'body'), false);
    }
  });
});

test('the forwarder cannot be built into a pass-through', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-egress-bad-'));
  try {
    assert.throws(
      () => createEgressForwarder({ allowlist: [{ host: '*', ports: [443] }], socketPath: path.join(dir, 'a.sock') }),
      (error) => /wildcard/i.test(String(error.message)),
      'a wildcard allowlist was accepted',
    );
    assert.throws(
      () => createEgressForwarder({ allowlist: [{ host: 'open.bigmodel.cn', ports: [0] }], socketPath: path.join(dir, 'b.sock') }),
      (error) => /wildcard/i.test(String(error.message)),
      'port 0 was accepted in an allowlist entry',
    );
    assert.throws(
      () => createEgressForwarder({ allowlist: [], socketPath: path.join(dir, 'c.sock') }),
      (error) => /malformed/i.test(String(error.message)),
      'an EMPTY allowlist was accepted, which is a forwarder with no policy',
    );
    assert.throws(
      () => createEgressForwarder({ allowlist: ISOLATION_EGRESS_ALLOWLIST, socketPath: '' }),
      (error) => /malformed/i.test(String(error.message)),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CONNECT preserves binary bytes, including data arriving with the headers', async () => {
 const bytes=Buffer.from([0,255,128,195,40,254,22,3,1]);
 const sockets=new Set();
 const echo=createServer(socket=>{
  sockets.add(socket);socket.on('close',()=>sockets.delete(socket));
  socket.on('data',chunk=>socket.write(chunk));
 });
 await new Promise(resolve=>echo.listen(0,'127.0.0.1',resolve));
 const dir=mkdtempSync(path.join(tmpdir(),'veritas-egress-binary-'));
 const socketPath=path.join(dir,'egress.sock');
 const port=echo.address().port;
 const f=createEgressForwarder({allowlist:[{host:'127.0.0.1',ports:[port]}],socketPath});
 await f.listen();
 try {
  for(const coalesced of [false,true]){
   const result=await new Promise((resolve,reject)=>{
    const client=connect(socketPath);let header=Buffer.alloc(0),body=Buffer.alloc(0),ready=false;
    const timer=setTimeout(()=>{client.destroy();reject(new Error('binary tunnel timeout'));},2000);
    const finish=fn=>{clearTimeout(timer);client.destroy();fn();};
    client.on('error',error=>finish(()=>reject(error)));
    client.on('connect',()=>{
     const head=Buffer.from('CONNECT 127.0.0.1:'+port+' HTTP/1.1\r\nHost: 127.0.0.1:'+port+'\r\n\r\n');
     client.write(coalesced?Buffer.concat([head,bytes]):head);
    });
    client.on('data',chunk=>{
     if(!ready){
      header=Buffer.concat([header,chunk]);const end=header.indexOf('\r\n\r\n');
      if(end<0)return;
      if(!header.subarray(0,end).toString('ascii').includes('200')){finish(()=>reject(new Error('CONNECT refused')));return;}
      ready=true;body=header.subarray(end+4);
      if(!coalesced)client.write(bytes);
     } else body=Buffer.concat([body,chunk]);
     if(body.length>=bytes.length)finish(()=>resolve(body));
    });
   });
   assert.deepEqual(result,bytes,'binary bytes changed; coalesced='+coalesced);
  }
 } finally {
  for(const socket of sockets)socket.destroy();
  await f.close();await new Promise(resolve=>echo.close(resolve));
  rmSync(dir,{recursive:true,force:true});
 }
});
