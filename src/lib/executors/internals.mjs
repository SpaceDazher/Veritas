// Shared, unexported-from-the-package helpers of the S2-007R executor tree
// (issue #45, SPEC §2 D1). adapters.mjs keeps its own; these are re-derived
// here so no private board symbol is imported.
//
// Nothing in this file is authority: it validates shapes and computes digests.
import { AclDenied, BlockedPolicy, MalformedResult, NeedsInput } from '../agentboard/errors.mjs';
import { ID_PREFIXES } from '../agentboard/constants.mjs';
import { CONFIG_SURFACES, CONFIGURATION_AXIS_MEASUREMENT, CONFIGURATION_AXIS_NAME, PROVIDER_ARGV_ALLOWLIST, REAL_EXECUTOR_VERSION } from './constants.mjs';
import { canonicalDigest } from '../verifier/canonical-json.mjs';
import { createHash } from 'node:crypto';
import path from 'node:path';

// --- the configuration axis (issue #45, round 3) ---------------------------
//
// A surface is a NAMED value with an exact argv consequence, resolved from the
// table in constants.mjs and never assembled by a caller. The three functions
// below are the whole axis, and each one refuses rather than guesses:
//
//   surfaceFlagsFor        the flags one end of the axis selects for one provider
//   resolveConfigurationSurface   the validated surface of a transport instance
//   configurationAxisFor   whether this provider can be compared at all
//
// The last one is the important one. Round 2's finding was that A and B produced
// an IDENTICAL normalised argv for both providers, so a comparison would have
// differenced a cell with itself. That is decided here, structurally, from the
// flags each end selects — before any process is spawned and before any
// comparison record is written.

/** The flags one end of the configuration axis selects for one provider. */
export function surfaceFlagsFor(provider, configuration) {
  const spec = PROVIDER_ARGV_ALLOWLIST[provider];
  if (spec === undefined) throw new NeedsInput(`REAL_PROVIDER_UNKNOWN:${String(provider)}`);
  const surface = Object.prototype.hasOwnProperty.call(CONFIG_SURFACES, String(configuration))
    ? CONFIG_SURFACES[String(configuration)]
    : null;
  if (surface === null) {
    throw new NeedsInput(
      `CONFIGURATION_UNKNOWN:${String(provider)}:${String(configuration)}: one of ${Object.keys(CONFIG_SURFACES).join(', ')}`,
    );
  }
  const flags = surface.provider_flags[provider];
  if (flags === undefined) {
    throw new NeedsInput(`CONFIGURATION_NOT_DECLARED_FOR_PROVIDER:${String(provider)}:${surface.configuration}`);
  }
  return Object.freeze([...flags]);
}

/**
 * The validated surface of a transport instance. An absent configuration is a
 * refusal rather than a default: a transport that does not know which context
 * surface it was given cannot be one half of a comparison, and defaulting it to
 * the limited build would make every unmarked run quietly a B cell.
 */
export function resolveConfigurationSurface(provider, value) {
  const name = requireString(value, 'configuration');
  const surface = Object.prototype.hasOwnProperty.call(CONFIG_SURFACES, name) ? CONFIG_SURFACES[name] : null;
  if (surface === null) {
    throw new NeedsInput(
      `CONFIGURATION_UNKNOWN:${String(provider)}:${name}: one of ${Object.keys(CONFIG_SURFACES).join(', ')}`,
    );
  }
  const flags = surfaceFlagsFor(provider, name);
  // A surface may only ever select a token the ALLOWLIST already permits. The
  // final argv is checked again by assertArgvAllowed immediately before the
  // spawn, so this is the earlier half: a configuration that wants a flag the
  // allowlist does not carry is a configuration error, named as one, and never a
  // free-form passthrough.
  const spec = PROVIDER_ARGV_ALLOWLIST[provider];
  for (const flag of flags) {
    if (!spec.tokens.includes(flag)) {
      throw new NeedsInput(`CONFIGURATION_FLAG_NOT_ALLOWLISTED:${String(provider)}:${flag}`);
    }
  }
  return Object.freeze({
    axis: CONFIGURATION_AXIS_NAME,
    configuration: surface.configuration,
    name: surface.name,
    surface_flags: Object.freeze([...flags]),
    surface_note: surface.surface_note,
  });
}

/**
 * Whether this provider can take part in an A/B comparison, and why.
 *
 * `distinguishable: false` is a REFUSAL of the comparison, not a null result:
 * a provider whose two ends select the same argv cannot produce a delta, and
 * the only honest statement about such a pair is that it is the same command
 * run twice. The reason names the measurement that settles it.
 */
export function configurationAxisFor(provider) {
  const flagsA = surfaceFlagsFor(provider, 'A');
  const flagsB = surfaceFlagsFor(provider, 'B');
  const distinguishable = flagsA.length !== flagsB.length || flagsA.some((flag, at) => flag !== flagsB[at]);
  const measured = CONFIGURATION_AXIS_MEASUREMENT[provider] ?? null;
  return Object.freeze({
    axis: CONFIGURATION_AXIS_NAME,
    provider,
    configurations: Object.freeze(Object.keys(CONFIG_SURFACES)),
    configuration_a_flags: flagsA,
    configuration_b_flags: flagsB,
    distinguishable,
    reason: distinguishable ? null : (
      `${provider} exposes no flag that suppresses a context surface, so configuration A and configuration B select `
      + 'the identical argv and a comparison between them would difference one command with itself. '
      + (measured === null ? '' : `Measured: ${measured.evidence}. `)
      + 'The provider is recorded as EXCLUDED from the comparison for this reason, not as "no difference observed".'
    ),
    measured,
  });
}

// --- the argv digests a comparison asserts on -------------------------------
//
// Two digests, always both, because one of them is a false positive waiting to
// happen: codex's argv carries `--output-last-message <evidence>/<run_id>/raw/
// last-message.txt` and `-C <per-run project copy>`, so two cells of one
// provider differ by the RUN alone and the raw digest would report a
// configuration difference that is only a file name. Normalisation folds the
// per-run values out — the resolved project directory, the evidence root, the
// injected workspace roots and the run id — and NOTHING else, so a difference
// that survives normalisation is a difference in the command itself.
export function normaliseArgvForComparison(argv, folds) {
  const ordered = [...(folds ?? [])]
    .filter((fold) => typeof fold?.from === 'string' && fold.from.length > 0)
    // Longest first: a project copy lives inside a workspace root, so folding
    // the root first would leave the tail of the inner path unfolded.
    .sort((left, right) => right.from.length - left.from.length);
  const separator = path.sep === '\\' ? '\\' : null;
  return argv.map((token) => {
    let value = String(token);
    for (const fold of ordered) value = value.split(fold.from).join(fold.to);
    return separator === null ? value : value.split(separator).join('/');
  });
}

/**
 * The raw and the NORMALISED digest of one argv, plus the normalised array so a
 * third party can see what was folded. The two are separated by NUL rather than
 * a space: a token may legally contain a space (the prompt does), and a
 * space-joined digest would let two different argvs collide.
 */
export function argvDigests(argv, folds) {
  const normalisedArgv = normaliseArgvForComparison(argv, folds);
  return Object.freeze({
    raw: wireDigest(argv.join('\u0000')),
    normalised: wireDigest(normalisedArgv.join('\u0000')),
    normalised_argv: Object.freeze(normalisedArgv),
    // Only the LABELS are published, never the per-run paths that were folded:
    // the normalised argv above already shows what each one became.
    folds: Object.freeze([...(folds ?? [])].map((fold) => Object.freeze({ label: fold.to, kind: fold.kind ?? null }))),
  });
}

// Re-derived from policy.assertWorkspaceWithin for a path-valued argument (a
// skill directory). The CWD goes through policy.assertWorkspaceWithin itself;
// this mirrors the same rule so a skill path cannot be a traversal, an absolute
// path, or a symlink out of its configured root.
export function assertDescendant(absPath, root, label, realpath) {
  const from = path.resolve(root);
  const to = path.resolve(absPath);
  if (from === to) throw new AclDenied(`${label}_ROOT_IS_THE_PATH`, `${label} may not be the root itself`);
  const relative = path.relative(from, to);
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new AclDenied(`${label}_OUTSIDE_ROOT`, `${label} is not inside its configured root`);
  }
  if (relative.includes('\u0000')) throw new AclDenied(`${label}_MALFORMED`, `${label} contains a NUL byte`);
  if (typeof realpath === 'function') {
    const resolve = (value) => {
      try {
        const out = realpath(value);
        return typeof out === 'string' && out.length > 0 ? out : null;
      } catch {
        return null;
      }
    };
    const fromReal = resolve(from);
    const toReal = resolve(to);
    if (fromReal === null || toReal === null) {
      throw new AclDenied(`${label}_UNRESOLVABLE`, `${label} could not be resolved`);
    }
    const prefix = fromReal.endsWith(path.sep) ? fromReal : fromReal + path.sep;
    if (toReal !== fromReal && !toReal.startsWith(prefix)) {
      throw new AclDenied(`${label}_LINK_ESCAPE`, `${label} resolves outside its configured root`);
    }
  }
  return true;
}


// --- small local helpers (adapters.mjs keeps its own; these are not exported) --

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function requireObject(value, label) {
  if (!isPlainObject(value)) throw new NeedsInput(`${label}: object required`);
  return value;
}

export function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new NeedsInput(`${label}: non-empty string required`);
  return value;
}

export function requireArray(value, label) {
  if (!Array.isArray(value)) throw new NeedsInput(`${label}: array required`);
  return value;
}

export function requireInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) throw new NeedsInput(`${label}: non-negative integer required`);
  return value;
}

export function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}

export function sortedUnique(list) {
  return [...new Set(list)].sort();
}

export function wireDigest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function requireClock(clock) {
  if (typeof clock === 'string' || clock instanceof Date) {
    const fixed = new Date(clock);
    if (Number.isNaN(fixed.getTime())) throw new NeedsInput('CLOCK_SHAPE: ISO string or Date required');
    return { now: () => new Date(fixed.getTime()) };
  }
  if (isPlainObject(clock) && typeof clock.now === 'function') {
    const probe = clock.now();
    if (!(probe instanceof Date) || Number.isNaN(probe.getTime())) {
      throw new NeedsInput('CLOCK_SHAPE: now() must return a valid Date');
    }
    return { now: () => clock.now() };
  }
  throw new NeedsInput('CLOCK_REQUIRED: an injected clock is mandatory; the process clock is never read');
}

export function timestampOf(clock) {
  const value = clock.now();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new NeedsInput('CLOCK_SHAPE: now() must return a valid Date');
  }
  return value.toISOString();
}

export function derivedId(name, seed) {
  const prefix = ID_PREFIXES[name];
  if (typeof prefix !== 'string') throw new NeedsInput(`ID_KIND_UNKNOWN:${name}`);
  return `${prefix}${canonicalDigest({ name, seed: String(seed) }).slice(0, 32)}`;
}

export function requireIdFactory(ids) {
  if (ids === undefined || ids === null) return (name, seed) => derivedId(name, seed);
  if (typeof ids !== 'function') throw new NeedsInput('ID_FACTORY_SHAPE: (name, seed) => id required');
  return (name, seed) => {
    const prefix = ID_PREFIXES[name];
    const value = ids(name, seed);
    if (typeof prefix !== 'string' || typeof value !== 'string' || !value.startsWith(prefix)) {
      throw new MalformedResult(
        `ID_FACTORY_SHAPE:${name}`,
        `injected id for ${name} must be a string starting with ${String(prefix)}`,
      );
    }
    return value;
  };
}

// Re-derived from adapters.mjs: a key outside the set is a REFUSED call, never
// a silently ignored field. An unknown argument is how a caller tries to hand

// --- the argv allowlist, enforced on the final array ------------------------

export function assertArgvAllowed(provider, argv) {
  const spec = PROVIDER_ARGV_ALLOWLIST[provider];
  if (spec === undefined) throw new NeedsInput(`REAL_PROVIDER_UNKNOWN:${String(provider)}`);
  const bare = new Set(spec.tokens.filter((token) => !token.includes(':')));
  const valued = new Map(spec.tokens.filter((token) => token.includes(':')).map((token) => {
    const at = token.indexOf(':');
    return [token.slice(0, at), token.slice(at + 1)];
  }));
  const flags = argv.slice(0, argv.length - spec.positional);
  const positionals = argv.slice(argv.length - spec.positional);
  for (const value of positionals) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new NeedsInput(`ARGV_POSITIONAL_EMPTY:${provider}`);
    }
    // A prompt that begins with '-' would be parsed as a flag by the child. The
    // prompt is DATA and may never introduce one.
    if (value.startsWith('-')) {
      throw new NeedsInput('PROMPT_LOOKS_LIKE_A_FLAG', 'the prompt may not begin with "-"');
    }
    if (value.includes('\u0000')) throw new NeedsInput('PROMPT_HAS_NUL_BYTE', 'the prompt contains a NUL byte');
  }
  for (let index = 0; index < flags.length; index += 1) {
    const token = flags[index];
    if (bare.has(token)) continue;
    if (!valued.has(token)) {
      throw new BlockedPolicy(`ARGV_TOKEN_NOT_ALLOWLISTED:${provider}:${token}`);
    }
    const pinned = valued.get(token);
    const next = flags[index + 1];
    if (next === undefined) throw new NeedsInput(`ARGV_VALUE_MISSING:${provider}:${token}`);
    if (pinned !== '' && next !== pinned) {
      throw new BlockedPolicy(`ARGV_VALUE_NOT_ALLOWLISTED:${provider}:${token}=${next}`);
    }
    index += 1;
  }
  return argv;
}
