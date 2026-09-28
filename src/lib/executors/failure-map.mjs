// Fail-closed mapping of an executor's OWN output (issue #45, SPEC §2 file 5,
// decision D11). The two CLIs disagree about failure: codex exits 1 with
// turn.failed, while pi exits 0 on a total model failure, so the exit code is
// never the sole classifier and neither is the assistant record alone.
//
// Pure: no clock, no I/O, no process. Everything here is recomputable from the
// executor's own bytes.
import { isPlainObject, wireDigest } from './internals.mjs';
import { NeedsInput } from '../agentboard/errors.mjs';

// --- the executor's own output ---------------------------------------------

// A JSONL line that is not a JSON object is DATA, not a record: it is skipped
// rather than coerced, and a skipped line can never become a success.
function parseJsonl(text) {
  const out = [];
  for (const line of String(text ?? '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) continue;
    try {
      const value = JSON.parse(trimmed);
      if (isPlainObject(value)) out.push(value);
    } catch {
      // A truncated final line is expected when a process is killed.
    }
  }
  return out;
}

function firstString(...candidates) {
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) return candidate;
  }
  return null;
}

// The pi assistant message is a content block array; `type:'text'` blocks carry
// the answer. Confirmed against the installed package's own event emitter
// (pi-coding-agent dist/core/agent-session.js emits `message_end` carrying the
// assistant `message`; the text blocks are {type:'text', text}).
function textFromBlocks(blocks) {
  if (!Array.isArray(blocks)) return null;
  const parts = blocks
    .filter((block) => isPlainObject(block) && (block.type === 'text' || block.type === undefined))
    .map((block) => (typeof block.text === 'string' ? block.text : null))
    .filter((value) => typeof value === 'string' && value.length > 0);
  return parts.length > 0 ? parts.join('') : null;
}

function lastAssistantText(records) {
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index];
    if (record.type !== 'message_end' && record.type !== 'message_update' && record.type !== 'turn_end') continue;
    const message = isPlainObject(record.message) ? record.message : null;
    if (message === null || message.role !== 'assistant') continue;
    const text = textFromBlocks(message.content)
      ?? firstString(message.text, record.text)
      ?? textFromBlocks(record.content);
    if (typeof text === 'string' && text.trim().length > 0) return text;
  }
  return null;
}

/** The executor's OWN token/cost report. Never estimated, never a price list. */
export function extractUsage(provider, records) {
  const empty = {
    input_tokens: null,
    output_tokens: null,
    reasoning_tokens: null,
    cache_read_tokens: null,
    cache_write_tokens: null,
    proxy_tokens: null,
    cost_usd_micros: null,
    cost_basis: 'NOT_REPORTED_BY_EXECUTOR',
    model_id: null,
    tool_calls: 0,
    executor_session_id: null,
  };
  let last = null;
  for (const record of records) {
    // pi carries the terminal usage on the record; a nested `message.usage` is
    // accepted too because the two observed shapes differ between record kinds.
    const direct = isPlainObject(record.usage) ? record.usage : null;
    const nested = isPlainObject(record.message) && isPlainObject(record.message.usage) ? record.message.usage : null;
    const usage = direct ?? nested;
    if (usage === null) continue;
    if (provider === 'codex' && record.type === 'turn.completed') last = usage;
    if (provider === 'pi'
      && (record.type === 'turn_end' || record.type === 'message_end' || record.type === 'message_update')) last = usage;
  }
  let sessionId = null;
  let modelId = null;
  let toolCalls = 0;
  for (const record of records) {
    if (record.type === 'thread.started' && typeof record.thread_id === 'string') sessionId = record.thread_id;
    if (record.type === 'session' && typeof record.id === 'string') sessionId = record.id;
    const message = isPlainObject(record.message) ? record.message : null;
    if (message !== null && message.role === 'assistant' && typeof message.model === 'string') modelId = message.model;
    if (provider === 'codex' && record.type === 'item.completed') toolCalls += 1;
    if (provider === 'pi' && record.type === 'turn_end' && Array.isArray(record.toolResults)) toolCalls = record.toolResults.length;
  }
  if (last === null) {
    return { ...empty, model_id: modelId, tool_calls: toolCalls, executor_session_id: sessionId };
  }
  if (provider === 'codex') {
    const input = intOrNull(last.input_tokens);
    const output = intOrNull(last.output_tokens);
    const reasoning = intOrNull(last.reasoning_output_tokens);
    return {
      input_tokens: input,
      output_tokens: output,
      reasoning_tokens: reasoning,
      cache_read_tokens: intOrNull(last.cached_input_tokens),
      cache_write_tokens: intOrNull(last.cache_write_input_tokens),
      proxy_tokens: sumOrNull([input, output, reasoning]),
      // Measured on this host: codex's JSONL reports no cost at all and its
      // ChatGPT-account auth exposes no per-token billing, so a codex cost
      // figure would be an assumption. The basis says so out loud.
      cost_usd_micros: null,
      cost_basis: 'PROXY_TOKENS_NO_USD_REPORTED',
      model_id: modelId,
      tool_calls: toolCalls,
      executor_session_id: sessionId,
    };
  }
  const input = intOrNull(last.input);
  const output = intOrNull(last.output);
  const reasoning = intOrNull(last.reasoning);
  const cost = isPlainObject(last.cost) ? Number(last.cost.total) : Number.NaN;
  const hasCost = Number.isFinite(cost) && cost >= 0;
  return {
    input_tokens: input,
    output_tokens: output,
    reasoning_tokens: reasoning,
    cache_read_tokens: intOrNull(last.cacheRead),
    cache_write_tokens: intOrNull(last.cacheWrite),
    proxy_tokens: sumOrNull([input, output, reasoning]),
    cost_usd_micros: hasCost ? Math.round(cost * 1e6) : null,
    cost_basis: hasCost ? 'EXECUTOR_REPORTED_USD' : 'PROXY_TOKENS_NO_USD_REPORTED',
    model_id: modelId,
    tool_calls: toolCalls,
    executor_session_id: sessionId,
  };
}

function intOrNull(value) {
  return Number.isInteger(value) ? value : null;
}

function sumOrNull(values) {
  return values.every((value) => Number.isInteger(value))
    ? values.reduce((total, value) => total + value, 0)
    : null;
}

/**
 * Classify the executor's own records. NEVER the exit code alone: measured on
 * this host, codex exits 1 on a model error while pi exits 0 on the same class
 * of failure, so an exit-code mapping would promote a 402 to a green run.
 */
export function readExecutorOutcome({ provider, exitCode, signal, stdoutText, stderrText, lastMessageText }) {
  const records = parseJsonl(stdoutText);
  const usage = extractUsage(provider, records);

  let failure = null;
  if (provider === 'codex') {
    for (const record of records) {
      if (record.type === 'turn.failed' || record.type === 'error'
        || (record.type === 'item.completed' && isPlainObject(record.item) && record.item.type === 'error')) {
        failure = {
          reason: 'EXECUTOR_ERROR_RECORD',
          message: firstString(
            record.message,
            isPlainObject(record.item) ? record.item.message : null,
            isPlainObject(record.error) ? record.error.message : null,
          ),
        };
        break;
      }
    }
  } else if (provider === 'pi') {
    for (const record of records) {
      const message = isPlainObject(record.message) ? record.message : record;
      if (!isPlainObject(message)) continue;
      if (message.stopReason === 'error' || typeof message.errorMessage === 'string') {
        failure = {
          reason: 'EXECUTOR_STOP_REASON_ERROR',
          message: firstString(message.errorMessage, record.errorMessage),
        };
        break;
      }
    }
  }
  // pi reports a credit limit only as a free-text `402:` prefix on a free-text
  // message. The prefix match is documented, brittle, and recorded as a
  // limitation of this mapping rather than a stable contract.
  const creditLimited = failure !== null && typeof failure.message === 'string' && /^402:/.test(failure.message);

  const assistantText = provider === 'codex'
    ? (typeof lastMessageText === 'string' && lastMessageText.trim().length > 0 ? lastMessageText : null)
    : lastAssistantText(records);

  return {
    records,
    usage,
    failure: failure === null ? null : { ...failure, credit_limited: creditLimited },
    assistant_text: assistantText,
    exit_code: Number.isInteger(exitCode) ? exitCode : null,
    signal: signal ?? null,
    stderr_digest: wireDigest(String(stderrText ?? '')),
  };
}