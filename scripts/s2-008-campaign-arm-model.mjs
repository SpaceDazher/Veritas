// S2-008 REAL CAMPAIGN — the PAID arm: the real model-calling executor.
//
// This file is COPIED into the derived executor image and executed by the
// container, like the zero-spend arm beside it. The difference is everything that
// makes it a paid leg: the predictor is an INSTALLED, MODEL-CALLING executor
// (pi, on GLM 5.3 flash from z.ai), it contacts an external service, and it is
// therefore bounded by a budget reservation in TOKENS rather than in launches.
//
//   node <this file> <input.json> <out.json> <arm_id> <prereg.json> <seed> [--dry-run]
//
// WHY --dry-run EXISTS, and why it is not a way to fake a result
// The shape of the run — the blindness guard, the budget stop, the unparseable
// handling, the output contract, the provenance — is everything that can go
// wrong AROUND the model call, and none of it needs the model. A dry run executes
// the entire path with a scripted stand-in and emits the SAME record shape with
// `model_called: false` and `dry_run: true`, so it can be verified offline for
// zero tokens. What a dry run cannot produce is a measurement, and the record
// says so in a field a reader is meant to check: `outcome_class: DRY_RUN`. A dry
// run is never a pass. It is the receipt for the plumbing.
//
// THE BLINDNESS GUARD is the same as the zero-spend arm and is not optional: if
// a label ever reaches the predictor, the run is void.
//
// TOKEN ACCOUNTING IS PI'S OWN REPORT, not an estimate. `--mode json` emits
// `turn_end` / `agent_end` with `usage.totalTokens` and `usage.cost.total`. The
// `message_update` streaming events report ZEROS mid-stream and are deliberately
// ignored: counting those would report a spent budget of 0 and the reservation
// would govern nothing.
//
// A MODEL IS NOT A DETERMINISTIC FUNCTION. This arm therefore records, per case,
// the digest of the raw text the model returned, so a repeat run can be COMPARED
// against the committed one. It never claims the model is a function of the input,
// and the run's reproducibility statement is about the frozen inputs and the
// recorded outputs, not about the model.
//
// PARALLELISM IS 1, on purpose. AUTONOMY_POLICY records it as an MVP constraint
// and it also keeps the spend bounded: one call in flight, one case at a time, so
// exhausting the reservation stops the run between cases rather than inside it.
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';


/** The only value that lets a preregistration be run under. */
export const APPROVED = 'APPROVED';

export const ARM_ERRORS = Object.freeze({
  PREREG_NOT_APPROVED: 'PREREGISTRATION_NOT_APPROVED',
  PREREG_DIGEST_MISMATCH: 'PREREGISTRATION_DIGEST_MISMATCH',
  PREREG_NOT_IN_FORCE: 'PREREGISTRATION_NOT_IN_FORCE',
  USAGE: 'arm-model-usage',
  BLIND_INPUT_EMPTY: 'BLIND_INPUT_EMPTY',
  BLIND_INPUT_CARRIES_LABEL: 'BLIND_INPUT_CARRIES_LABEL',
  UNKNOWN_ARM: 'UNKNOWN_ARM',
  NO_CREDENTIAL: 'EXECUTOR_CREDENTIAL_ABSENT',
  PROVIDER_UNREACHABLE: 'MODEL_ENDPOINT_UNREACHABLE',
  NO_USAGE_REPORTED: 'MODEL_USAGE_NOT_REPORTED',
  BUDGET_EXHAUSTED: 'BUDGET_EXHAUSTED',
  SHARED_CAP_REQUIRED: 'SHARED_TOKEN_CAP_REQUIRED',
  SHARED_CAP_INVALID: 'SHARED_TOKEN_CAP_INVALID',
  BRIDGE_NOT_READY: 'EGRESS_BRIDGE_NOT_READY',
});

/**
 * Where the model reaches the network FROM, inside the container.
 *
 * The container runs with `--network=none` and exactly one bind mount: the unix
 * socket the egress forwarder listens on, at `/run/egress.sock` (see
 * `buildInvocation`). Nothing else crosses the boundary — no repository path, no
 * host file. A TCP client cannot speak to a unix socket, so `pi` has no route to
 * `open.bigmodel.cn:443` until something inside the container bridges loopback
 * TCP to that socket. That something is `s2-008-egress-bridge.mjs`, baked into
 * the image rather than mounted, because a program that can change between build
 * and run is not a program a digest can commit to.
 *
 * The port is NOT a constant anywhere. The bridge is started on port 0 and the
 * number it actually bound is read back from its `BRIDGE_READY` line; a fixed
 * port in the code would be a guess about the host's state that the record then
 * reports as a measurement.
 */
export const BRIDGE_SCRIPT_IN_IMAGE = '/opt/veritas/scripts/s2-008-egress-bridge.mjs';
export const EGRESS_SOCKET_IN_IMAGE = '/run/egress.sock';

/** The only answers that count. Anything else is UNPARSED, never guessed. */
export const LABEL_SET = Object.freeze(['MAJOR', 'MINOR']);
export const UNPARSED = 'UNPARSED';

const CHUNK = 16 * 1024;

/** The prompt. Fixed text plus the subject line — the same subject a regex read. */
export function buildPrompt(subject) {
  return [
    'Classify this git commit subject as MAJOR or MINOR.',
    'MAJOR = changes behaviour, contracts, security, data, or the acceptance of a stage.',
    'MINOR = wording, formatting, comments, or bookkeeping that does not change behaviour.',
    'Answer with exactly one word, MAJOR or MINOR, and nothing else.',
    '',
    `Subject: ${String(subject ?? '')}`,
  ].join('\n');
}

/**
 * The answer must BE a label, not CONTAIN one.
 *
 * The first version took the first label-shaped token anywhere in the text, and
 * the test caught what that would have done to a measurement: 'maybe major-ish'
 * and 'not major' both scored MAJOR, because a hyphen and a negation are word
 * boundaries. A hedging or refusing answer silently becomes a prediction, which
 * is the one thing this arm must never do — the whole point of the closed label
 * set is that an unusable answer is UNPARSED, and UNPARSED counts as a
 * disagreement rather than as a guess.
 *
 * So the rule is: strip surrounding whitespace and trailing punctuation, and
 * accept only if what remains is exactly one of the two labels. Everything else
 * is UNPARSED.
 */
export function parseLabel(text) {
  const trimmed = String(text ?? '').trim().replace(/[.!?,;:]+$/, '').trim();
  return LABEL_SET.includes(trimmed.toUpperCase()) ? trimmed.toUpperCase() : UNPARSED;
}

function finalAgentEnd(stdout) {
  let final = null;
  for (const line of String(stdout ?? '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const event = JSON.parse(trimmed);
      if (event?.type === 'agent_end') final = event;
    } catch {}
  }
  return final;
}

/** Sum billed assistant messages from pi's one authoritative final agent_end. */
export function extractUsage(stdout) {
  const messages = finalAgentEnd(stdout)?.messages;
  if (!Array.isArray(messages)) return null;
  const billed = messages.filter((message) => message?.role === 'assistant');
  if (billed.length === 0) return null;
  const seenIds = new Set();
  const totals = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { total: 0 } };
  for (const message of billed) {
    if (typeof message.id === 'string') {
      if (seenIds.has(message.id)) continue;
      seenIds.add(message.id);
    }
    const usage = message.usage;
    if (!usage || typeof usage !== 'object' ||
        !Number.isSafeInteger(usage.totalTokens) || usage.totalTokens < 0 ||
        !usage.cost || typeof usage.cost !== 'object' ||
        !Number.isFinite(usage.cost.total) || usage.cost.total < 0) return null;
    for (const field of ['input', 'output', 'cacheRead', 'cacheWrite']) {
      const value = usage[field];
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) return null;
      totals[field] += value ?? 0;
    }
    totals.totalTokens += usage.totalTokens;
    totals.cost.total += usage.cost.total;
  }
  if (!Number.isSafeInteger(totals.totalTokens) || !Number.isFinite(totals.cost.total)) return null;
  return totals;
}

/** Only assistant text blocks can become a prediction; thinking and tool payloads are ignored. */
export function assistantMessageText(message) {
  if (message?.role !== 'assistant') return '';
  if (typeof message.content === 'string') return message.content;
  if (!Array.isArray(message.content)) return '';
  return message.content
    .filter((block) => block?.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text)
    .join('\n');
}

export function modelCallArgv({ provider, model, prompt }) {
  return [
    '--print', '--mode', 'json',
    '--provider', provider,
    '--model', model,
    '--no-session', '--no-tools', '--no-extensions', '--no-skills',
    prompt,
  ];
}

/** The credential: present or not, and NEVER printed. The NAME is publishable. */
export function readCredential(envName, env) {
  const value = env?.[envName];
  return typeof value === 'string' && value.length >= 8;
}

/**
 * Start the in-container bridge and WAIT for it to report the port it bound.
 *
 * The order the campaign depends on is a launch-order fact, not a convention:
 * the forwarder's socket must be listening, the container must be up with the
 * socket mounted, the bridge must be up, the credential env-file must have been
 * handed over, and only then may a model call happen. This function owns the one
 * stage of that order that lives inside the container, and it fails closed: a
 * bridge that never says `BRIDGE_READY` is a refusal to call the model, because
 * calling it without a route either wastes the reservation on transport errors or
 * — worse — succeeds by some path this arm did not measure.
 */
export function startEgressBridge({
  script = BRIDGE_SCRIPT_IN_IMAGE,
  socketPath = EGRESS_SOCKET_IN_IMAGE,
  execPath = process.execPath,
  timeoutMs = 15_000,
  spawnImpl = spawn,
} = {}) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(execPath, [script, '--port', '0', '--socket', socketPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let settled = false;
    let stderr = '';
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(reject, new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:timeout:${timeoutMs}ms`));
    }, timeoutMs);
    child.stderr?.on('data', (chunk) => { stderr += String(chunk); });
    child.on('error', (error) => finish(reject, new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:spawn:${String(error?.message ?? error).slice(0, 120)}`)));
    child.on('exit', (code) => {
      finish(reject, new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:exit=${String(code)}:${stderr.slice(-200)}`));
    });
    let buffered = '';
    child.stdout?.on('data', (chunk) => {
      buffered += String(chunk);
      const lines = buffered.split('\n');
      buffered = lines.pop() ?? '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{')) continue;
        let event;
        try {
          event = JSON.parse(trimmed);
        } catch {
          continue;
        }
        if (event.event !== 'BRIDGE_READY') continue;
        // The port must be a NUMBER in the line, not a string that parses. A
        // permissive Number() here would put "45123" into the published record as
        // a string while the proxy used 45123, so the record and the route would
        // disagree about their own types — and the record is what a reader checks.
        const port = event.port;
        if (typeof port !== 'number' || !Number.isInteger(port) || port <= 0 || port > 65535 || event.host !== '127.0.0.1') {
          finish(reject, new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:bad-ready-line`));
          return;
        }
        // The port is bound NOW. Cancelling the exit guard would let a bridge
        // that dies a moment later be reported as a live route, so the child is
        // handed to the caller instead: it lives until the arm exits.
        child.removeAllListeners('exit');
        clearTimeout(timer);
        settled = true;
        resolve(Object.freeze({ port, host: '127.0.0.1', child, stop: () => { try { child.kill('SIGTERM'); } catch { /* already gone */ } return true; } }));
        return;
      }
    });
  });
}

/** The proxy environment pi runs under. Built ONLY from the port just read. */
export function proxyEnvironment(base, { port, host = '127.0.0.1' } = {}) {
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`${ARM_ERRORS.BRIDGE_NOT_READY}:no-port-to-proxy`);
  }
  return Object.freeze({
    ...(base ?? {}),
    HTTPS_PROXY: `http://${host}:${port}`,
    HTTP_PROXY: `http://${host}:${port}`,
  });
}

/** One model call. Dry runs skip it and say so. */
export function callModel(subject, { provider, model, envName, env, dryRun, timeoutMs, piSettings = null, execFile = execFileSync }) {
  if (dryRun) {
    return { text: 'MINOR', usage: { totalTokens: 0, cost: { total: 0 } }, model_called: false };
  }
  if (!readCredential(envName, env)) {
    throw new Error(`${ARM_ERRORS.NO_CREDENTIAL}:${envName}`);
  }
  let stdout;
  let runtimeEnv = env;
  let settingsDir = null;
  if (piSettings !== null) {
    try {
      if (piSettings.config_dir_env !== 'PI_CODING_AGENT_DIR' ||
          piSettings.retry?.enabled !== false || piSettings.retry?.maxRetries !== 0 ||
          piSettings.retry?.provider?.maxRetries !== 0 || piSettings.cacheWarming !== 'off' ||
          piSettings.compaction?.enabled !== false ||
          Object.keys(piSettings).sort().join(',') !== 'cacheWarming,compaction,config_dir_env,retry' ||
          Object.keys(piSettings.retry).sort().join(',') !== 'enabled,maxRetries,provider' ||
          Object.keys(piSettings.retry.provider).join(',') !== 'maxRetries' ||
          Object.keys(piSettings.compaction).join(',') !== 'enabled') throw new Error('V7_PI_SETTINGS_POLICY_INVALID');
      const { config_dir_env: _configDirEnv, ...settings } = piSettings;
      settingsDir = fs.mkdtempSync(path.join(os.tmpdir(), 's2-008-pi-settings-'));
      fs.writeFileSync(path.join(settingsDir, 'settings.json'), JSON.stringify(settings) + '\n', { mode: 0o600, flag: 'wx' });
      runtimeEnv = { ...env, PI_CODING_AGENT_DIR: settingsDir };
    } catch {
      if (settingsDir) fs.rmSync(settingsDir, { recursive: true, force: true });
      throw new Error('V7_PI_SETTINGS_MATERIALIZATION_FAILED');
    }
  }
  try {
    stdout = execFile('pi', modelCallArgv({
      provider, model, prompt: buildPrompt(subject),
    }), { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 1 << 26, env: runtimeEnv });
  } catch (error) {
    throw new Error(`${ARM_ERRORS.PROVIDER_UNREACHABLE}:${String(error?.message ?? error).slice(0, 160)}`);
  } finally {
    if (settingsDir) fs.rmSync(settingsDir, { recursive: true, force: true });
  }
  const usage = extractUsage(stdout);
  if (usage === null || !Number.isInteger(usage.totalTokens) || usage.totalTokens <= 0) throw new Error(`${ARM_ERRORS.NO_USAGE_REPORTED}`);
  const final = finalAgentEnd(stdout);
  const messages = final?.messages;
  const assistantMessages = Array.isArray(messages)
    ? messages.filter((message) => message?.role === 'assistant') : [];
  const text = assistantMessageText(assistantMessages.at(-1));
  const responseIds = assistantMessages.map((message) => message?.responseId).filter((value) => typeof value === 'string' && value.trim() !== '');
  const singleResponseId = assistantMessages.length === 1 && responseIds.length === 1 ? responseIds[0] : null;
  const finalMessage = assistantMessages.at(-1);
  const sessionId = final?.session_id ?? final?.sessionId ?? finalMessage?.session_id ?? finalMessage?.sessionId ?? null;
  const promptTokens = usage.input + usage.cacheRead + usage.cacheWrite;
  const usageComponentsConsistent = usage.totalTokens === promptTokens + usage.output;
  const correlationIssue = assistantMessages.length !== 1 ? 'MULTIPLE_BILLED_MESSAGES' : singleResponseId === null ? 'GENERATION_ID_MISSING' : null;
  const accounting = {
    generation_id: singleResponseId,
    ...(typeof sessionId === 'string' && sessionId.trim() !== '' ? { session_id: sessionId } : {}),
    correlation_status: correlationIssue === null ? 'CORRELATED' : 'UNAVAILABLE',
    correlation_issue: correlationIssue,
    input: usage.input, output: usage.output, cacheRead: usage.cacheRead, cacheWrite: usage.cacheWrite,
    prompt_tokens: promptTokens,
    prompt_token_basis: 'input+cacheRead+cacheWrite',
    totalTokens: usage.totalTokens, reported_cost_usd: usage.cost.total,
    usage_components_consistent: usageComponentsConsistent,
    usage_component_issue: usageComponentsConsistent ? null : 'TOKEN_COMPONENT_MISMATCH',
    ...(assistantMessages.length !== 1 ? { observed_generation_ids: responseIds } : {}),
  };
  return { text, usage, model_called: true, accounting };
}

/**
 * The outcome class, and why it is four values and not two.
 *
 * A dry run that ran to completion and a dry run that stopped on its budget are
 * DIFFERENT facts, and a run that measured and a run that stopped are different
 * too. Collapsing them into MEASURED/DRY_RUN/INFRA is what let a first version
 * of this file report DRY_RUN for a run that had in fact stopped early — a
 * reader checking one field would learn nothing. Nothing here is ever a pass;
 * the class describes what happened, and the decision belongs to the comparator.
 */
export function classifyOutcome({ dryRun, stopped, measured }) {
  if (dryRun) return stopped ? 'DRY_RUN_BUDGET_STOPPED' : 'DRY_RUN';
  if (stopped) return 'INFRA';
  return measured ? 'MEASURED' : 'NOT_RUN';
}

export async function main(argv, env = process.env, deps = {}) {
  const startBridge = deps.startBridge ?? startEgressBridge;
  const invokeModel = deps.callModel ?? callModel;
  const writeStdout = deps.writeStdout ?? ((text) => process.stdout.write(text));
  const capPositions = argv.flatMap((value, index) => value === '--remaining-tokens' ? [index] : []);
  const capPosition = capPositions.length === 1 ? capPositions[0] : -1;
  const capText = capPosition >= 0 ? argv[capPosition + 1] : undefined;
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  const positional = argv.filter((a, index) => !a.startsWith('--') && !(capPosition >= 0 && index === capPosition + 1));
  if (capPositions.length > 1 || [...flags].some((flag) => flag !== '--dry-run' && flag !== '--remaining-tokens')) {
    process.stderr.write(`${ARM_ERRORS.SHARED_CAP_INVALID}:flags\n`);
    return 11;
  }
  if (positional.length < 5) {
    process.stderr.write(`usage: arm-model <input.json> <out.json> <arm_id> <prereg.json> <seed> [--dry-run]\n`);
    return 2;
  }
  const [inputPath, outPath, armId, preregPath, seedText] = positional;
  const dryRun = flags.has('--dry-run');
  if (armId !== 'arm-model-zai-glm53flash') {
    process.stderr.write(`${ARM_ERRORS.UNKNOWN_ARM}:${armId}\n`);
    return 2;
  }
  const seed = Number(seedText);
  if (!Number.isInteger(seed) || seed < 0) {
    process.stderr.write(`seed must be a non-negative integer, got ${seedText}\n`);
    return 2;
  }

  const rows = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  if (!Array.isArray(rows) || rows.length === 0) {
    process.stderr.write(`${ARM_ERRORS.BLIND_INPUT_EMPTY}\n`);
    return 3;
  }
  const leaking = rows.findIndex((row) => Object.hasOwn(row ?? {}, 'label'));
  if (leaking >= 0) {
    process.stderr.write(`${ARM_ERRORS.BLIND_INPUT_CARRIES_LABEL}:row=${String(leaking)}\n`);
    return 4;
  }

  const prereg = JSON.parse(fs.readFileSync(preregPath, 'utf8'));

  // AN UNAPPROVED PREREGISTRATION IS NOT A PREREGISTRATION. v2 exists on disk as a
  // draft with `approval.status: null`, and a draft that a run could pick up would
  // turn "the owner has not signed this" into "the run happened anyway". The
  // approval is checked BEFORE the budget, because an unapproved document has no
  // budget worth reading.
  if (prereg.approval?.status !== APPROVED) {
    process.stderr.write(`${ARM_ERRORS.PREREG_NOT_APPROVED}:${String(prereg.preregistration_id ?? 'unknown')}:${String(prereg.approval?.status ?? 'none')}\n`);
    return 7;
  }

  // THE APPROVAL MUST TRAVEL WITH THE DOCUMENT. `approval.status` alone is a
  // string anyone can type, and the digest is the only thing that says WHICH
  // document was signed. So the arm recomputes the digest over the scientific
  // body — every member except approval, status and the digest itself — and
  // refuses a mismatch. Edit the rule, the band, the baseline or a seed after the
  // signature and the recomputed digest no longer matches, so an approved run
  // cannot be a run of a different experiment.
  const { canonicalDigest } = await import('../src/lib/verifier/canonical-json.mjs');
  const { approval: _approval, preregistration_digest: _declared, status: _status, ...body } = prereg;
  const recomputed = canonicalDigest(body);
  if (recomputed !== String(prereg.preregistration_digest ?? '')) {
    process.stderr.write(`${ARM_ERRORS.PREREG_DIGEST_MISMATCH}:signed=${String(prereg.preregistration_digest ?? '').slice(0, 16)}:recomputed=${recomputed.slice(0, 16)}\n`);
    return 8;
  }
  if (prereg.approval?.signed_digest_over !== undefined && prereg.approval.in_force !== true) {
    // A signature that has not been sealed into the corpus manifest by
    // `--seal-v2` is a signature of a document that is not yet the one in force.
    process.stderr.write(`${ARM_ERRORS.PREREG_NOT_IN_FORCE}:${String(prereg.preregistration_id ?? 'unknown')}\n`);
    return 9;
  }

  const reservation = prereg.budget_reservation ?? {};
  const granted = Number(reservation.granted_units);
  const currency = String(reservation.currency ?? '');
  // ZERO IS NOT MISSING. `granted_units: 0` is a preregistered ceiling that this
  // run may not exceed, and the honest outcome is a budget stop before the first
  // case. A reservation with NO ceiling, or a negative one, is malformed and is
  // refused outright. Conflating them would let an absent budget read as a
  // permission, which is the one substitution AUTONOMY_POLICY names by name:
  // 'Missing is not zero, and zero is not permission'.
  if (currency !== 'tokens' || !Number.isFinite(granted) || granted < 0) {
    process.stderr.write(`BUDGET_RESERVATION_NOT_IN_TOKENS:${currency}\n`);
    return 5;
  }
  // The signed grant is a campaign ceiling. A later seed receives only what
  // earlier seeds have not already spent, never a fresh grant of that amount.
  // Missing/invalid paid caps refuse BEFORE bridge or pi can start.
  let launchCap = granted;
  if (capPosition < 0 && !dryRun) {
    process.stderr.write(`${ARM_ERRORS.SHARED_CAP_REQUIRED}\n`);
    return 11;
  }
  if (capPosition >= 0) {
    if (typeof capText !== 'string' || !/^(0|[1-9]\d*)$/.test(capText) ||
        !Number.isSafeInteger(Number(capText))) {
      process.stderr.write(`${ARM_ERRORS.SHARED_CAP_INVALID}\n`);
      return 11;
    }
    launchCap = Math.min(granted, Number(capText));
  }
  const provider = String(prereg.executor?.provider ?? 'zai-coding-cn');
  const model = String(prereg.executor?.model ?? 'glm-5.3-flash');
  const envName = String(prereg.executor?.credential_env_name ?? 'ZAI_API_KEY');
  let timeoutPolicy = null;
  let piSettings = null;
  let piSettingsDigest = null;
  let timeoutMs = Number(reservation.trial_timeout_ms ?? 120000);
  if (['s2-008-prereg-v6','s2-008-prereg-v7','s2-008-prereg-v8','s2-008-prereg-v9','s2-008-prereg-v10'].includes(prereg.rule)) {
    try {
      const { assertV6ModelTimeoutPolicy } = await import('./s2-008-campaign-v6-timeout.mjs');
      timeoutPolicy = assertV6ModelTimeoutPolicy(prereg.executor?.model_launch_timeout);
    } catch {
      process.stderr.write('V6_MODEL_TIMEOUT_POLICY_INVALID\n');
      return 12;
    }
    if (rows.length !== timeoutPolicy.holdout_case_count) {
      process.stderr.write('V6_MODEL_TIMEOUT_CASE_COUNT_MISMATCH\n');
      return 12;
    }
    timeoutMs = timeoutPolicy.per_model_call_timeout_ms;
    if (['s2-008-prereg-v7','s2-008-prereg-v8','s2-008-prereg-v9','s2-008-prereg-v10'].includes(prereg.rule)) {
      try {
        const { assertV8ExecutorPolicy, assertV7ExecutorPolicy, createV7PiSettingsFile } = await import('./s2-008-campaign-credential-env.mjs');
        piSettings = (['s2-008-prereg-v8','s2-008-prereg-v9','s2-008-prereg-v10'].includes(prereg.rule) ? assertV8ExecutorPolicy : assertV7ExecutorPolicy)(prereg.executor).settings;
        const settingsBytes = JSON.stringify(createV7PiSettingsFile(piSettings)) + String.fromCharCode(10);
        piSettingsDigest = createHash('sha256').update(settingsBytes).digest('hex');
      } catch {
        process.stderr.write('V7_CREDENTIAL_ENV_OR_RETRY_POLICY_INVALID\n');
        return 13;
      }
    }
  }

  const predictions = [];
  const accounting = [];
  const requireGenerationId = prereg.rule === 's2-008-prereg-v9' || prereg.rule === 's2-008-prereg-v10';
  const generationIdsSeen = new Set();
  let spent = 0;
  let usd = 0;
  let modelCalls = 0;
  let modelAttempts = 0;
  let unreconciledSpend = false;
  let stop = null;
  // THE THIRD STAGE OF THE LAUNCH ORDER, and the one that lives in here. The
  // forwarder's socket is already listening and the container already has it
  // mounted (that is `buildInvocation`'s job, on the host); what is left before a
  // model call is the route. Under `--network=none` there is none until the bridge
  // is up, so it is brought up and CONFIRMED here rather than assumed — a run
  // that started calling without it would spend its reservation on transport
  // errors and report them as UNPARSED predictions, which is the quiet-zero
  // failure the whole outcome-class contract exists to prevent.
  //
  // A dry run starts nothing: there is no call to route, and a bridge listening
  // during a dry run would be a live listener in a run whose record says it spent
  // nothing and reached nothing.
  let bridge = null;
  let modelEnv = env;
  if (!dryRun) {
    bridge = await startBridge();
    modelEnv = proxyEnvironment(env, bridge);
  }
  for (const [index, row] of rows.entries()) {
    if (spent >= launchCap) {
      // A budget stop is an OUTCOME. It is not a retry, not a zero, and not a
      // silent truncation: it is recorded with what had been spent.
      stop = Object.freeze({ reason: ARM_ERRORS.BUDGET_EXHAUSTED, spent_tokens: spent, granted_tokens: launchCap, signed_grant_tokens: granted, usd_spent: usd, stopped_before_case: String(row.case_id), overrun_tokens: Math.max(0, spent - launchCap) });
      break;
    }
    let result;
    if (!dryRun) modelAttempts += 1;
    try {
      result = invokeModel(String(row.subject ?? ''), { provider, model, envName, env: modelEnv, dryRun, timeoutMs, piSettings });
    } catch (error) {
      const code = String(error?.message ?? error).split(':')[0];
      // A transport or usage failure may already have spent tokens. Stop now:
      // treating it as an unparsed answer with zero usage would bypass the cap.
      unreconciledSpend = code !== ARM_ERRORS.NO_CREDENTIAL;
      stop = Object.freeze({
        reason: code,
        unreconciled_spend: unreconciledSpend,
        spent_tokens_confirmed: spent,
        stopped_before_case: String(row.case_id),
      });
      break;
    }
    if (!dryRun && (!Number.isInteger(result?.usage?.totalTokens) || result.usage.totalTokens <= 0)) {
      unreconciledSpend = true;
      stop = Object.freeze({
        reason: ARM_ERRORS.NO_USAGE_REPORTED,
        unreconciled_spend: true,
        spent_tokens_confirmed: spent,
        stopped_before_case: String(row.case_id),
      });
      break;
    }
    spent += result.usage.totalTokens;
    usd += Number(result.usage?.cost?.total ?? 0);
    if (result.model_called) modelCalls += 1;
    if (result.model_called && result.accounting) {
      const accountRow = { case_id: String(row.case_id), ...result.accounting };
      let correlationIssue = accountRow.correlation_issue;
      if (requireGenerationId && accountRow.correlation_status === 'CORRELATED' && generationIdsSeen.has(accountRow.generation_id)) {
        correlationIssue = 'DUPLICATE_GENERATION_ID';
        accountRow.correlation_status = 'UNAVAILABLE';
        accountRow.correlation_issue = correlationIssue;
      }
      accounting.push(accountRow);
      if (requireGenerationId && accountRow.usage_components_consistent !== true) {
        const issue = accountRow.usage_component_issue ?? 'TOKEN_COMPONENT_STATUS_MISSING';
        stop = Object.freeze({ reason: 'MODEL_CALL_ACCOUNTING_COMPONENTS_UNAVAILABLE', accounting_issue: issue,
          unreconciled_spend: false, spent_tokens_confirmed: spent, usd_spent: usd, stopped_before_case: String(row.case_id) });
        break;
      }
      if (requireGenerationId && (accountRow.correlation_status !== 'CORRELATED' || typeof accountRow.generation_id !== 'string' || accountRow.generation_id.trim() === '')) {
        stop = Object.freeze({ reason: 'MODEL_CALL_CORRELATION_UNAVAILABLE', correlation_issue: correlationIssue ?? 'GENERATION_ID_MISSING',
          unreconciled_spend: false, spent_tokens_confirmed: spent, usd_spent: usd, stopped_before_case: String(row.case_id) });
        break;
      }
      if (typeof accountRow.generation_id === 'string' && accountRow.generation_id !== '') generationIdsSeen.add(accountRow.generation_id);
    } else if (result.model_called) {
      const accountRow = { case_id: String(row.case_id), generation_id: null, correlation_status: 'UNAVAILABLE',
        correlation_issue: 'ACCOUNTING_MISSING', input: result.usage.input ?? 0, output: result.usage.output ?? 0,
        cacheRead: result.usage.cacheRead ?? 0, cacheWrite: result.usage.cacheWrite ?? 0,
        prompt_tokens: (result.usage.input ?? 0) + (result.usage.cacheRead ?? 0) + (result.usage.cacheWrite ?? 0),
        prompt_token_basis: 'input+cacheRead+cacheWrite', totalTokens: result.usage.totalTokens,
        reported_cost_usd: Number(result.usage?.cost?.total ?? 0) };
      accountRow.usage_components_consistent = accountRow.totalTokens === accountRow.prompt_tokens + accountRow.output;
      accountRow.usage_component_issue = accountRow.usage_components_consistent ? null : 'TOKEN_COMPONENT_MISMATCH';
      accounting.push(accountRow);
      if (requireGenerationId && accountRow.usage_components_consistent !== true) {
        const issue = accountRow.usage_component_issue ?? 'TOKEN_COMPONENT_STATUS_MISSING';
        stop = Object.freeze({ reason: 'MODEL_CALL_ACCOUNTING_COMPONENTS_UNAVAILABLE', accounting_issue: issue,
          unreconciled_spend: false, spent_tokens_confirmed: spent, usd_spent: usd, stopped_before_case: String(row.case_id) });
        break;
      }
      if (requireGenerationId) {
        stop = Object.freeze({ reason: 'MODEL_CALL_CORRELATION_UNAVAILABLE', correlation_issue: 'ACCOUNTING_MISSING',
          unreconciled_spend: false, spent_tokens_confirmed: spent, usd_spent: usd, stopped_before_case: String(row.case_id) });
        break;
      }
    }
    predictions.push({
      case_id: row.case_id,
      predicted: parseLabel(result.text),
      // The raw answer's digest, so a repeat can be COMPARED. The text itself is
      // not committed: it may carry the subject line, and a record is read by
      // more people than the run is reproducible for.
      raw_sha256: createHash('sha256').update(String(result.text ?? '')).digest('hex'),
    });
    if (spent >= launchCap) {
      stop = Object.freeze({
        reason: ARM_ERRORS.BUDGET_EXHAUSTED,
        spent_tokens: spent, granted_tokens: launchCap, signed_grant_tokens: granted,
        usd_spent: usd, stopped_before_case: rows[index + 1]?.case_id ?? null,
        overrun_tokens: Math.max(0, spent - launchCap),
      });
      break;
    }
  }

  bridge?.stop();
  const out = {
    kind: 's2-008-campaign-adapter-predict-model/1',
    accounting_schema: 's2-008-model-accounting/1',
    accounting,
    arm_id: armId,
    seed,
    n_cases: rows.length,
    predictions,
    budget: {
      currency,
      granted_tokens: granted,
      launch_cap_tokens: launchCap,
      spent_tokens: spent,
      usd_spent: usd,
      measured_by: "pi --mode json final agent_end.messages assistant usage.totalTokens summed once per billed assistant message; pi runtime cost is an estimate, provider invoice not independently verified",
      exhausted: stop?.reason === ARM_ERRORS.BUDGET_EXHAUSTED,
      unreconciled_spend: unreconciledSpend,
    },
    stop,
    dry_run: Boolean(dryRun),
    outcome_class: classifyOutcome({ dryRun, stopped: stop !== null, measured: modelCalls > 0 && stop === null }),
    executor: {
      provider,
      model,
      credential_env_name: envName,
      pi_settings_sha256: piSettingsDigest,
      credential_present: readCredential(envName, env),
      credential_in_argv: false,
      // What the call travelled over, and where the number came from. The port is
      // reported as READ, never as configured, because there is no configured one.
      egress_route: bridge === null
        ? null
        : { via: 'in-container loopback bridge', host: bridge.host, port: bridge.port, port_source: 'BRIDGE_READY' },
      model_calls: modelCalls,
      model_attempts: modelAttempts,
      parallel_calls: 1,
      model_launch_timeout: timeoutPolicy,
      accounting_policy: requireGenerationId ? 'GENERATION_ID_REQUIRED' : 'GENERATION_ID_OPTIONAL',
    },
    container: {
      node_version: process.version,
      pid: process.pid,
      argv_tail: [armId, seedText, ...(dryRun ? ['--dry-run'] : [])],
      cwd: process.cwd(),
      labels_seen: false,
    },
  };
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  writeStdout(`ADAPTER_OK arm=${armId} seed=${seed} n=${rows.length} predictions=${predictions.length} tokens=${spent} usd=${usd.toFixed(6)} dry_run=${dryRun} pid=${process.pid} node=${process.version}\n`);
  const payload = Buffer.from(JSON.stringify(out), 'utf8').toString('base64');
  const chunks = Math.ceil(payload.length / CHUNK) || 1;
  for (let index = 0; index < chunks; index += 1) {
    writeStdout(`ADAPTER_JSON ${index + 1}/${chunks} ${payload.slice(index * CHUNK, (index + 1) * CHUNK)}\n`);
  }
  writeStdout(`ADAPTER_JSON_END ${payload.length}\n`);
  // A budget stop is a non-zero exit: the run did not complete, and a gate that
  // cannot tell that from a complete run is not a gate.
  return stop === null ? 0 : stop.reason === ARM_ERRORS.BUDGET_EXHAUSTED ? 6 : 10;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  // The EXIT CODE IS THE EXIT CODE `main` returned. An earlier version of this line
  // did `process.exitCode = signed === null ? 1 : 0`, which threw away every numeric
  // refusal code: the arm printed PREREGISTRATION_NOT_APPROVED or _DIGEST_MISMATCH and
  // still exited 0. A guard that refuses in its output and reports success in its status
  // is the silent-zero class this whole track exists to remove, and it was reintroduced
  // here by a refactor. A test now runs the arm as a process and reads the status.
  main(process.argv.slice(2), process.env).then((code) => {
    process.exitCode = typeof code === 'number' ? code : 1;
  });
}
