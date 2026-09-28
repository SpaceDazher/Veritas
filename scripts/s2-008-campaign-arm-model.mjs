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
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** The only value that lets a preregistration be run under. */
export const APPROVED = 'APPROVED';

export const ARM_ERRORS = Object.freeze({
  PREREG_NOT_APPROVED: 'PREREGISTRATION_NOT_APPROVED',
  USAGE: 'arm-model-usage',
  BLIND_INPUT_EMPTY: 'BLIND_INPUT_EMPTY',
  BLIND_INPUT_CARRIES_LABEL: 'BLIND_INPUT_CARRIES_LABEL',
  UNKNOWN_ARM: 'UNKNOWN_ARM',
  NO_CREDENTIAL: 'EXECUTOR_CREDENTIAL_ABSENT',
  PROVIDER_UNREACHABLE: 'MODEL_ENDPOINT_UNREACHABLE',
  NO_USAGE_REPORTED: 'MODEL_USAGE_NOT_REPORTED',
  BUDGET_EXHAUSTED: 'BUDGET_EXHAUSTED',
});

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

/** pi's own final usage, from turn_end / agent_end. Streaming zeros are ignored. */
export function extractUsage(stdout) {
  let best = null;
  for (const line of String(stdout ?? '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let event;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (event.type !== 'turn_end' && event.type !== 'agent_end') continue;
    const usage = event.usage;
    if (!usage || typeof usage !== 'object') continue;
    if (typeof usage.totalTokens !== 'number') continue;
    if (best === null || usage.totalTokens > best.totalTokens) best = usage;
  }
  return best;
}

/** The credential: present or not, and NEVER printed. The NAME is publishable. */
export function readCredential(envName, env) {
  const value = env?.[envName];
  return typeof value === 'string' && value.length >= 8;
}

/** One model call. Dry runs skip it and say so. */
export function callModel(subject, { provider, model, envName, env, dryRun, timeoutMs }) {
  if (dryRun) {
    return { text: 'MINOR', usage: { totalTokens: 0, cost: { total: 0 } }, model_called: false };
  }
  if (!readCredential(envName, env)) {
    throw new Error(`${ARM_ERRORS.NO_CREDENTIAL}:${envName}`);
  }
  let stdout;
  try {
    stdout = execFileSync('pi', [
      '--print', '--mode', 'json',
      '--provider', provider,
      '--model', model,
      '--no-session',
      buildPrompt(subject),
    ], { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 1 << 26, env });
  } catch (error) {
    throw new Error(`${ARM_ERRORS.PROVIDER_UNREACHABLE}:${String(error?.message ?? error).slice(0, 160)}`);
  }
  const usage = extractUsage(stdout);
  if (usage === null) throw new Error(`${ARM_ERRORS.NO_USAGE_REPORTED}`);
  let text = '';
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let event;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (event.type === 'message_end' && typeof event.message?.content === 'string') text = event.message.content;
  }
  return { text, usage, model_called: true };
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

export function main(argv, env = process.env) {
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  const positional = argv.filter((a) => !a.startsWith('--'));
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
  const provider = String(prereg.executor?.provider ?? 'zai-coding-cn');
  const model = String(prereg.executor?.model ?? 'glm-5.3-flash');
  const envName = String(prereg.executor?.credential_env_name ?? 'ZAI_API_KEY');
  const timeoutMs = Number(reservation.trial_timeout_ms ?? 120000);

  const predictions = [];
  let spent = 0;
  let usd = 0;
  let modelCalls = 0;
  let stop = null;
  for (const row of rows) {
    if (spent >= granted) {
      // A budget stop is an OUTCOME. It is not a retry, not a zero, and not a
      // silent truncation: it is recorded with what had been spent.
      stop = Object.freeze({ reason: ARM_ERRORS.BUDGET_EXHAUSTED, spent_tokens: spent, granted_tokens: granted, usd_spent: usd, stopped_before_case: String(row.case_id) });
      break;
    }
    let result;
    try {
      result = callModel(String(row.subject ?? ''), { provider, model, envName, env, dryRun, timeoutMs });
    } catch (error) {
      const code = String(error?.message ?? error).split(':')[0];
      // A failed case is recorded as itself, not guessed and not skipped silently.
      predictions.push({ case_id: row.case_id, predicted: UNPARSED, failure: code });
      continue;
    }
    spent += Number(result.usage?.totalTokens ?? 0);
    usd += Number(result.usage?.cost?.total ?? 0);
    if (result.model_called) modelCalls += 1;
    predictions.push({
      case_id: row.case_id,
      predicted: parseLabel(result.text),
      // The raw answer's digest, so a repeat can be COMPARED. The text itself is
      // not committed: it may carry the subject line, and a record is read by
      // more people than the run is reproducible for.
      raw_sha256: createHash('sha256').update(String(result.text ?? '')).digest('hex'),
    });
  }

  const out = {
    kind: 's2-008-campaign-adapter-predict-model/1',
    arm_id: armId,
    seed,
    n_cases: rows.length,
    predictions,
    budget: {
      currency,
      granted_tokens: granted,
      spent_tokens: spent,
      usd_spent: usd,
      measured_by: "pi --mode json turn_end.usage.totalTokens — the executor's own report; the streaming message_update zeros are ignored",
      exhausted: stop !== null,
    },
    stop,
    dry_run: Boolean(dryRun),
    outcome_class: classifyOutcome({ dryRun, stopped: stop !== null, measured: modelCalls > 0 && stop === null }),
    executor: {
      provider,
      model,
      credential_env_name: envName,
      credential_present: readCredential(envName, env),
      credential_in_argv: false,
      model_calls: modelCalls,
      parallel_calls: 1,
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
  process.stdout.write(`ADAPTER_OK arm=${armId} seed=${seed} n=${rows.length} predictions=${predictions.length} tokens=${spent} usd=${usd.toFixed(6)} dry_run=${dryRun} pid=${process.pid} node=${process.version}\n`);
  const payload = Buffer.from(JSON.stringify(out), 'utf8').toString('base64');
  const chunks = Math.ceil(payload.length / CHUNK) || 1;
  for (let index = 0; index < chunks; index += 1) {
    process.stdout.write(`ADAPTER_JSON ${index + 1}/${chunks} ${payload.slice(index * CHUNK, (index + 1) * CHUNK)}\n`);
  }
  process.stdout.write(`ADAPTER_JSON_END ${payload.length}\n`);
  // A budget stop is a non-zero exit: the run did not complete, and a gate that
  // cannot tell that from a complete run is not a gate.
  return stop === null ? 0 : 6;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  process.exitCode = main(process.argv.slice(2), process.env);
}
