#!/usr/bin/env node
// A STUB executor binary for tests/agentboard/real-executor.test.mjs.
//
// WHY THIS FILE EXISTS
// --------------------
// src/lib/executors/transport.mjs drives a genuinely installed codex or pi
// process. Testing that boundary must not cost a model invocation, and a
// fixture that could be mistaken for a real run is worse than no fixture. So:
// this is a REAL PROCESS (it is spawned, it is a process-group leader, it
// really exits with a real status) that emits the OUTPUT SHAPE the two CLIs
// emit, and it is never described as a real adapter anywhere: every run through
// it is recorded as NOT_RUN_REAL_ADAPTER and the tests assert exactly that.
//
// It takes NO flags of its own. Its behaviour is chosen by a directive inside
// the PROMPT — the last argv element, which is DATA the transport is forbidden
// to interpret as a flag. That is deliberate: it exercises the real code path in
// which the prompt is the only channel the caller has.
//
//   STUB_MODE=ok              codex shape, exit 0, writes --output-last-message
//   STUB_MODE=empty           codex shape, exit 0, no last message -> EMPTY_RESPONSE
//   STUB_MODE=provider_error  codex shape, item.completed error + turn.failed, exit 1
//   STUB_MODE=pi_402          pi shape, exit 0, stopReason "error", `402:` message
//   STUB_MODE=pi_ok           pi shape, exit 0, assistant text, usage + cost
//   STUB_MODE=hang            sleeps forever, no children (the timeout arm)
//   STUB_MODE=group           sleeps forever AFTER spawning two children that
//                             inherit its process group (the real group-kill arm)
//   STUB_MODE=selfkill        SIGKILLs itself: an exit no transport signalled
//
// No network, no filesystem outside the paths the transport passes in, no
// credential, no clock of its own: every instant comes from the parent.
import fs from 'node:fs';
import { spawn } from 'node:child_process';

const argv = process.argv.slice(2);
const prompt = argv.length > 0 ? argv[argv.length - 1] : '';
const mode = (/STUB_MODE=([a-z0-9_]+)/.exec(prompt) ?? [])[1] ?? 'ok';

function flagValue(name) {
  const at = argv.indexOf(name);
  return at === -1 ? null : (argv[at + 1] ?? null);
}

const lastMessagePath = flagValue('--output-last-message');
const toolsCsv = flagValue('--tools');
const skillFlags = argv.reduce((count, token) => (token === '--skill' ? count + 1 : count), 0);

function emit(record) {
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

function codexSession() {
  emit({ type: 'thread.started', thread_id: 'stub-thread-0001' });
  emit({ type: 'turn.started' });
}

function codexUsage() {
  return {
    input_tokens: 41,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 3,
    reasoning_output_tokens: 0,
  };
}

function piSession() {
  emit({ type: 'session', id: 'stub-session-0001', version: 3, cwd: process.cwd() });
  emit({ type: 'agent_start' });
  emit({ type: 'turn_start' });
}

function piUsage(total) {
  return {
    input: 57,
    output: 5,
    cacheRead: 0,
    cacheWrite: 0,
    reasoning: 0,
    totalTokens: 62,
    cost: { input: 3.414e-5, output: 1.128e-5, cacheRead: 0, cacheWrite: 0, total },
  };
}

function writeLastMessage(text) {
  if (lastMessagePath === null) return;
  fs.writeFileSync(lastMessagePath, text, 'utf8');
}

function sleepForever() {
  setInterval(() => {}, 1 << 30);
}

if (mode === 'hang') {
  piSession();
  sleepForever();
} else if (mode === 'group') {
  // Two children that INHERIT this process's group: they are what a pid-only
  // kill would leave behind, so they are the point of this mode.
  for (let index = 0; index < 2; index += 1) {
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
    child.unref();
  }
  piSession();
  sleepForever();
} else if (mode === 'selfkill') {
  codexSession();
  emit({ type: 'turn.started' });
  process.kill(process.pid, 'SIGKILL');
  sleepForever();
} else if (mode === 'provider_error') {
  codexSession();
  emit({ type: 'item.completed', item: { type: 'error', message: 'stub: model metadata not found' } });
  emit({ type: 'turn.failed', error: { message: 'stub: the provider refused the request' } });
  process.exitCode = 1;
} else if (mode === 'pi_402') {
  // The measured pi shape: exit 0 on a total model failure. An adapter that maps
  // the exit code to success promotes this to a green run; this stub exists to
  // prove that the real transport does not.
  piSession();
  emit({
    type: 'message_end',
    message: {
      role: 'assistant',
      model: 'stub-model',
      provider: 'openrouter',
      api: 'openai-completions',
      stopReason: 'error',
      content: [],
      errorMessage: '402: {"message":"This request requires more credits.","code":402}',
    },
  });
  emit({ type: 'turn_end', usage: piUsage(0), toolResults: [] });
  process.exitCode = 0;
} else if (mode === 'pi_ok') {
  piSession();
  emit({
    type: 'message_end',
    message: {
      role: 'assistant',
      model: 'stub-model',
      provider: 'openrouter',
      api: 'openai-completions',
      stopReason: 'stop',
      content: [{ type: 'text', text: `PONG tools=${toolsCsv ?? 'none'} skills=${skillFlags}` }],
      usage: piUsage(4.542e-5),
    },
  });
  emit({ type: 'turn_end', usage: piUsage(4.542e-5), toolResults: [] });
  emit({ type: 'agent_end', willRetry: false });
  process.exitCode = 0;
} else if (mode === 'empty') {
  codexSession();
  emit({ type: 'turn.completed', usage: codexUsage() });
  writeLastMessage('');
  process.exitCode = 0;
} else {
  codexSession();
  emit({ type: 'item.completed', item: { type: 'agent_message', text: 'PONG' } });
  emit({ type: 'turn.completed', usage: codexUsage() });
  writeLastMessage('PONG');
  process.exitCode = 0;
}
