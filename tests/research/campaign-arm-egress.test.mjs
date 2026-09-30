// S2-008 #12, раздел B — the route the model actually travels over, proved for
// ZERO tokens.
//
// The paid arm runs under `--network=none` with exactly one bind mount: the unix
// socket the egress forwarder listens on. A TCP client cannot speak to a unix
// socket, so `pi` had no route to `open.bigmodel.cn:443` at all — the key and the
// forwarder were both in place, and the model still could not have been reached.
// These cases pin the three things that fix has to be true of, and each one is
// written so that removing the rule makes the case FAIL rather than pass quietly:
//
//   1. the port is READ from the bridge's BRIDGE_READY line, never configured —
//      including a source-level check that no fixed port can creep back in;
//   2. the bridge is up and CONFIRMED before the first model call, and a bridge
//      that fails fails the run rather than degrading into transport errors that
//      would be recorded as 126 UNPARSED predictions;
//   3. the proxy is assembled from the port that was read, and a dry run starts
//      no listener at all.
//
// NOT PROVEN HERE, and deliberately so: that `pi` reaches the provider through
// this route. That needs the credential, and the credential is the owner's. The
// end-to-end case is reported as NOT_RUN with that reason rather than simulated.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { preregistrationDigest } from '../../scripts/s2-008-campaign-approve.mjs';
import {
  ARM_ERRORS,
  APPROVED,
  EGRESS_SOCKET_IN_IMAGE,
  startEgressBridge,
  main,
  proxyEnvironment,
} from '../../scripts/s2-008-campaign-arm-model.mjs';

const ARM_ID = 'arm-model-zai-glm53flash';
const ENV_NAME = 'ZAI_API_KEY';
const ARM_SOURCE = path.resolve(import.meta.dirname, '../../scripts/s2-008-campaign-arm-model.mjs');

/** A child process stand-in whose stdout is scripted. No real bridge is spawned. */
function fakeChild(lines, { exitCode = null, stderr = '' } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killed = false;
  child.kill = () => { child.killed = true; return true; };
  // Everything is emitted on the next tick: a real child's output arrives after
  // the caller has attached its listeners, and emitting synchronously here would
  // test a race that cannot happen in production.
  child.emitOutput = () => {
    if (stderr) child.stderr.emit('data', stderr);
    if (lines.length) child.stdout.emit('data', lines.join('\n') + '\n');
    if (exitCode !== null) child.emit('exit', exitCode);
  };
  return child;
}

function spawnOf(child) {
  return () => { process.nextTick(() => child.emitOutput()); return child; };
}

function readyLine(port, host = '127.0.0.1') {
  return JSON.stringify({ event: 'BRIDGE_READY', port, socket: EGRESS_SOCKET_IN_IMAGE, host });
}

async function withDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'veritas-egress-'));
  try { return await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function prereg(overrides = {}) {
  const body = {
    budget_reservation: { currency: 'tokens', granted_units: 100_000_000, trial_timeout_ms: 120000 },
    executor: { provider: 'zai-coding-cn', model: 'glm-5.3-flash', credential_env_name: ENV_NAME },
    status: 'APPROVED',
    approval: {
      status: APPROVED,
      authority: 'HUMAN_OWNER',
      principal_id: 'prn-fixture',
      label: 'fixture',
      signed_digest_over: 'the scientific body: every member except approval, status and preregistration_digest',
      in_force: true,
    },
    ...overrides,
  };
  return { ...body, preregistration_digest: preregistrationDigest(body) };
}

function blindInput(n = 3) {
  return Array.from({ length: n }, (_, i) => ({
    case_id: `case-${String(i).padStart(3, '0')}`,
    subject: `evidence: reseal manifest ${i}`,
    committed_at: 1790421856,
  }));
}

async function writeCase(dir, { pre = prereg() } = {}) {
  const input = path.join(dir, 'in.json');
  const out = path.join(dir, 'out.json');
  const preregPath = path.join(dir, 'pre.json');
  writeFileSync(input, JSON.stringify(blindInput()));
  writeFileSync(preregPath, JSON.stringify(pre));
  return { input, out, preregPath };
}

test('the port is READ from BRIDGE_READY, and no fixed port exists in the arm', async () => {
  // A port that came from the line, not from the code: the bridge is asked for
  // port 0 and whatever it reports is what the arm gets.
  const child = fakeChild([JSON.stringify({ event: 'BRIDGE_READY', port: 45123, socket: EGRESS_SOCKET_IN_IMAGE, host: '127.0.0.1' })]);
  const bridge = await startEgressBridge({ spawnImpl: spawnOf(child) });
  assert.equal(bridge.port, 45123, 'the reported port was not the one the arm kept');
  assert.equal(bridge.host, '127.0.0.1');
  bridge.stop();

  // The source-level half: a hard-coded port in the arm would make the number in
  // the record a claim about the host rather than an observation of it.
  const source = readFileSync(ARM_SOURCE, 'utf8');
  assert.ok(
    /startEgressBridge[\s\S]{0,400}?'--port', '0'/.test(source),
    'the bridge is not started on port 0, so a fixed port may have crept into the code',
  );
  const hardCoded = /HTTPS_PROXY\s*[:=]\s*[`'"]?http:\/\/127\.0\.0\.1:\d/.exec(source);
  assert.equal(hardCoded, null, `a fixed proxy port is hard-coded in the arm: ${hardCoded?.[0]}`);
});

test('a bridge that never reports a port is a REFUSAL, and the run fails on it', async () => {
  // Three ways a bridge can fail to be a route, and none of them may leave the
  // arm calling a model anyway.
  const silent = await startEgressBridge({
    spawnImpl: spawnOf(fakeChild([])), timeoutMs: 60,
  }).then(() => 'resolved', (error) => error.message);
  assert.match(silent, /EGRESS_BRIDGE_NOT_READY:timeout/, 'a silent bridge was treated as a route');

  const died = await startEgressBridge({
    spawnImpl: spawnOf(fakeChild([], { exitCode: 1, stderr: 'EACCES /run/egress.sock' })), timeoutMs: 1000,
  }).then(() => 'resolved', (error) => error.message);
  assert.match(died, /EGRESS_BRIDGE_NOT_READY:exit=1/, 'a dead bridge was treated as a route');
  assert.match(died, /EACCES/, 'the bridge stderr was thrown away instead of reported');

  // A port of 0, or a listener that is not loopback, is not a usable route even
  // though the line parsed. Accepting either is how a "connected" run talks to
  // something that was never the forwarder.
  for (const line of [
    readyLine(0),
    readyLine(45123, '0.0.0.0'),
    JSON.stringify({ event: 'BRIDGE_READY', port: '45123', socket: EGRESS_SOCKET_IN_IMAGE, host: '127.0.0.1' }),
    JSON.stringify({ event: 'SOMETHING_ELSE', port: 45123 }),
  ]) {
    const message = await startEgressBridge({ spawnImpl: spawnOf(fakeChild([line])), timeoutMs: 80 })
      .then(() => 'resolved', (error) => error.message);
    assert.match(message, /EGRESS_BRIDGE_NOT_READY/, `this line was accepted as a route: ${line}`);
  }
});

test('the bridge is up and confirmed BEFORE the first model call, and its failure stops the run', async () => {
  await withDir(async (dir) => {
    const { input, out, preregPath } = await writeCase(dir);

    // A bridge that cannot start: the run must refuse. The observable that makes
    // this a real gate rather than a comment is what is NOT there afterwards — a
    // record full of UNPARSED transport failures would look like a model that
    // disagreed with every case, and would be scored as such.
    const refused = await main([input, out, ARM_ID, preregPath, '20260926', '--remaining-tokens', '5000000'], { [ENV_NAME]: 'x'.repeat(20) }, {
      startBridge: async () => { throw new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:exit=1:EACCES /run/egress.sock`); },
    }).then(() => 'resolved', (error) => error.message);
    assert.match(refused, /EGRESS_BRIDGE_NOT_READY/, 'a dead bridge did not stop the run');
    assert.throws(() => readFileSync(out, 'utf8'), 'the failed run still wrote a record to be read as a result');

    // A live bridge: the port the line reported reaches the record as an
    // observation, and the dry run stays out of it entirely.
    const live = await main([input, out, ARM_ID, preregPath, '20260926', '--remaining-tokens', '5000000'], { [ENV_NAME]: 'x'.repeat(20) }, {
      startBridge: async () => ({ port: 45123, host: '127.0.0.1', stop: () => true }),
    });
    const record = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(record.executor.egress_route.port, 45123, 'the port that was read did not reach the record');
    assert.equal(record.executor.egress_route.port_source, 'BRIDGE_READY', 'the record does not say where the port came from');
    assert.equal(record.executor.egress_route.via, 'in-container loopback bridge');
    assert.ok(live !== 0 || record.executor.model_calls === 0, 'the run reported a status its own record contradicts');

    // A dry run must not start a listener. A bridge listening during a run whose
    // record says it spent nothing and reached nothing is a live socket with no
    // receipt for it.
    let started = 0;
    await main([input, out, ARM_ID, preregPath, '20260926', '--dry-run'], {}, {
      startBridge: async () => { started += 1; return { port: 1, host: '127.0.0.1', stop: () => true }; },
    });
    assert.equal(started, 0, 'a dry run started an egress bridge');
    assert.equal(JSON.parse(readFileSync(out, 'utf8')).executor.egress_route, null, 'a dry run reported a route it never used');
  });
});

test('the proxy is assembled from the port that was read, and cannot be assembled without one', () => {
  const env = proxyEnvironment({ PATH: '/usr/bin:/bin' }, { port: 45123 });
  assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:45123', 'the proxy does not point at the bridge that was read');
  assert.equal(env.HTTP_PROXY, 'http://127.0.0.1:45123');
  assert.equal(env.PATH, '/usr/bin:/bin', 'the rest of the environment was not carried through');

  // Without a port there is no route, and inventing one is the failure this
  // function exists to prevent.
  for (const bad of [undefined, null, 0, -1, 70000, 1.5, '45123']) {
    assert.throws(
      () => proxyEnvironment({}, { port: bad }),
      /EGRESS_BRIDGE_NOT_READY/,
      `a proxy was built without a port: ${JSON.stringify(bad)}`,
    );
  }
});
