// S2-008 #12 — the in-container egress bridge, end to end.
//
// The bridge is the only thing between the model and the network, so these cases
// run the WHOLE path on this host: client -> loopback TCP -> bridge -> unix socket
// -> forwarder -> real socket. The allowlisted destination is reached and four other
// targets are refused, and the refusal is the forwarder's, relayed verbatim.
//
// What is asserted about the bridge is its SAFETY SHAPE, because that is the part
// a future change could quietly break: it opens exactly one kind of connection, it
// never dials a host, it binds loopback only, it forwards the destination the
// client asked for without rewriting it, and it logs events rather than payloads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createEgressForwarder } from '../../src/lib/isolation/egress.mjs';
import { ISOLATION_EGRESS_ALLOWLIST } from '../../src/lib/isolation/profile.mjs';
import { createBridge, requestHead } from '../../scripts/s2-008-egress-bridge.mjs';

const BRIDGE = path.resolve(import.meta.dirname, '../../scripts/s2-008-egress-bridge.mjs');
const ALLOWED = { host: 'open.bigmodel.cn', port: 443 };

/** CONNECT through a TCP port — the shape a real HTTP proxy client uses. */
function connectVia(port, host, targetPort, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    const client = connect({ host: '127.0.0.1', port });
    let head = '';
    const done = (outcome) => {
      clearTimeout(timer);
      try {
        client.destroy();
      } catch { /* already gone */ }
      resolve({ outcome, head: head.slice(0, 160) });
    };
    const timer = setTimeout(() => done('TIMEOUT'), timeoutMs);
    client.setEncoding('utf8');
    client.once('connect', () => client.write(`CONNECT ${host}:${targetPort} HTTP/1.1\r\nHost: ${host}:${targetPort}\r\n\r\n`));
    client.on('data', (chunk) => { head += chunk; if (head.length > 0) done('ANSWERED'); });
    client.once('error', (error) => done(`ERROR:${String(error?.code ?? '')}`));
  });
}

async function withPath(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-bridge-'));
  const socketPath = path.join(dir, 'egress.sock');
  const decisions = [];
  const forwarder = createEgressForwarder({
    allowlist: ISOLATION_EGRESS_ALLOWLIST,
    socketPath,
    log: (row) => decisions.push(row),
  });
  await forwarder.listen();
  const bridge = createBridge({ port: 0, socketPath });
  const { port } = await bridge.listen();
  try {
    return await fn({ port, socketPath, decisions, bridge, forwarder, dir });
  } finally {
    await bridge.close();
    await forwarder.close?.();
    rmSync(dir, { recursive: true, force: true });
  }
}

test('the whole path works for the ONE declared destination', async () => {
  await withPath(async ({ port, decisions }) => {
    const answer = await connectVia(port, ALLOWED.host, ALLOWED.port);
    assert.match(answer.head, /HTTP\/1\.[01] 200|200 OK/, `the declared destination was not reached: ${JSON.stringify(answer)}`);
    assert.ok(decisions.some((d) => d.decision === 'ADMITTED' && d.host === ALLOWED.host),
      `the forwarder never admitted it: ${JSON.stringify(decisions)}`);
  });
});

test('EVERY other destination is refused, by the forwarder, over the bridge', async () => {
  await withPath(async ({ port, decisions }) => {
    const denied = [
      { host: 'evil.example.com', port: 443, why: 'a host that is not on the allowlist' },
      { host: ALLOWED.host, port: 22, why: 'the right host on the wrong port' },
      { host: 'api.openai.com', port: 443, why: 'another provider' },
    ];
    for (const target of denied) {
      const answer = await connectVia(port, target.host, target.port);
      assert.match(answer.head, /403 Forbidden/, `${target.why} was not refused: ${JSON.stringify(answer)}`);
      assert.ok(decisions.some((d) => d.decision === 'REFUSED' && d.host === target.host && d.port === target.port),
        `no refusal recorded for ${target.host}:${target.port} (${target.why}); decisions: ${JSON.stringify(decisions)}`);
    }
  });
});

test('the bridge binds LOOPBACK only, and says so', async () => {
  await withPath(async ({ port, bridge }) => {
    // Under --network=none the container has nothing but loopback, so a bridge bound
    // to 0.0.0.0 would be reachable from the host. Assert the bind address.
    const address = bridge.server.address();
    assert.equal(address.address, '127.0.0.1', `the bridge is bound to ${address.address}, not loopback`);
    // And a port nobody chose is not exposed: the test asked for 0 and got a real
    // loopback port, not a wildcard one.
    assert.ok(port > 0);
  });
});

test('a missing socket is its OWN outcome, never an admission', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-bridge-nosock-'));
  try {
    const bridge = createBridge({ port: 0, socketPath: path.join(dir, 'absent.sock') });
    const { port } = await bridge.listen();
    try {
      const answer = await connectVia(port, ALLOWED.host, ALLOWED.port, 8000);
      assert.equal(/200 OK/.test(answer.head), false, `a missing socket produced an admission: ${JSON.stringify(answer)}`);
      // The client sees the connection die rather than a fabricated 200.
      assert.ok(['ERROR:ENOENT', 'TIMEOUT', 'ANSWERED'].includes(answer.outcome), `unexpected outcome ${answer.outcome}`);
      // And the bridge recorded it as the socket being unavailable, which is NOT
      // the policy refusing a destination.
      const events = bridge.events;
      assert.ok(events.length > 0, 'a failed handshake logged nothing');
      assert.equal(events.some((e) => e.outcome === 'SOCKET_UNAVAILABLE'), true,
        `the bridge did not name the missing socket: ${JSON.stringify(events)}`);
      // The log line and the resolved value call the same fact the same thing.
      assert.equal(events.every((e) => e.outcome !== undefined && e.event === undefined), true,
        `an event row uses a second name for the outcome: ${JSON.stringify(events)}`);
      assert.equal(events.some((e) => e.outcome === 'FORWARDED'), false, 'a forward happened with no socket');
    } finally {
      await bridge.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the bridge forwards the destination the client ASKED for, and logs no payload', async () => {
  await withPath(async ({ port, bridge, decisions }) => {
    await connectVia(port, ALLOWED.host, ALLOWED.port);
    // The forwarder is the component that decides, so the host it recorded must be
    // the one the client wrote — a bridge that rewrote the destination would be a
    // policy bypass wearing a transport costume.
    const admitted = decisions.find((d) => d.decision === 'ADMITTED');
    assert.equal(admitted.host, ALLOWED.host);
    for (const event of bridge.events) {
      assert.equal(Object.prototype.hasOwnProperty.call(event, 'payload'), false, 'a bridge event carries a payload');
      assert.equal(Object.prototype.hasOwnProperty.call(event, 'body'), false);
    }
    // And what it logs is the request LINE, which is the destination and the method
    // and nothing else.
    const forwarded = bridge.events.find((e) => e.outcome === 'FORWARDED');
    if (forwarded !== undefined) {
      assert.match(forwarded.request, /^CONNECT open\.bigmodel\.cn:443 HTTP\/1\.[01]$/,
        `the bridge logged something other than the request line: ${forwarded.request}`);
    }
  });
});

test('the bridge source opens no connection of its own and binds loopback', () => {
  // The safety property stated as a check on the TEXT, because it is the property a
  // future edit would break: the only net.connect in the file targets the socket
  // path, and there is no DNS or direct-dial call anywhere in it.
  const source = readFileSync(BRIDGE, 'utf8');
  const dials = [...source.matchAll(/net\.connect\(([^)]*)\)/g)].map((m) => m[1].trim());
  assert.ok(dials.length >= 1, 'the bridge opens no connection at all, so it forwards nothing');
  for (const dial of dials) {
    assert.match(dial, /socketPath/, `net.connect targets something other than the mounted socket: ${dial}`);
  }
  for (const forbidden of ['dns', 'lookup', 'net.connect(`', `net.connect('`, 'http.request', 'fetch(']) {
    assert.equal(source.includes(forbidden), false, `the bridge contains ${forbidden}, which would be a second egress path`);
  }
  assert.match(source, /server\.listen\(\{ host: '127\.0\.0\.1'/, 'the bridge does not bind loopback explicitly');
});

test('a malformed request is not forwarded as a destination', () => {
  assert.equal(requestHead(Buffer.from('no newline yet')), null);
  assert.equal(requestHead(Buffer.from('CONNECT h:1 HTTP/1.1\r\n\r\n')), 'CONNECT h:1 HTTP/1.1');
  // The head is the first LINE only: a body that follows is never part of what the
  // bridge inspects, and the forwarder decides on the line.
  assert.equal(requestHead(Buffer.from('CONNECT h:1 HTTP/1.1\r\nX: y\r\n\r\nsecret-body')), 'CONNECT h:1 HTTP/1.1');
});
