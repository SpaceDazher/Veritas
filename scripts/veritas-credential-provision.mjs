// S2-002 #12 — provision the executor credential WITHOUT it ever being an argument.
//
// WHY THIS IS A SCRIPT AND NOT A COMMAND LINE YOU TYPE
// The value must reach podman's secret store and must not appear in a shell
// history, in a process list, or in this script's own argv. So the value is READ
// FROM somewhere (a file or stdin) and the argv carries only a PATH and a NAME.
//
//   node scripts/veritas-credential-provision.mjs \
//     --handle sec-veritas-executor-credential \
//     --env-name ZAI_API_KEY \
//     --from-file /path/to/key.txt
//   … --from-stdin < /path/to/key.txt
//
// A `--api-key <value>`-shaped argument is REFUSED, not ignored: a script that
// merely declined to read it would still have put it in the process list, which
// is the leak the whole descriptor design exists to prevent.
//
// WHAT IT PRINTS: the handle, the env name, the value's FINGERPRINT (16 hex of
// SHA-256, enough to prove two runs used the same credential and useless to
// anyone holding only the fingerprint) and the store's own confirmation. Never the
// value, never a prefix of it, never a length of it.
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  fingerprint,
  materializeSecret,
  secretMountPath,
  SECRET_ERRORS,
  spoolCredentialEnvFile,
} from '../src/lib/isolation/secrets.mjs';
import { declaredSecretHandles, SANDBOX_ISOLATION_EXECUTOR } from '../src/lib/isolation/profile.mjs';

export const PROVISION_ERRORS = Object.freeze({
  VALUE_IN_ARGV: 'CREDENTIAL_VALUE_PRESENT_IN_ARGV',
  SOURCE_MISSING: 'CREDENTIAL_SOURCE_MISSING',
  SOURCE_UNREADABLE: 'CREDENTIAL_SOURCE_UNREADABLE',
  SOURCE_EMPTY: 'CREDENTIAL_SOURCE_EMPTY',
  HANDLE_NOT_IN_PROFILE: 'CREDENTIAL_HANDLE_NOT_IN_PROFILE',
  ENV_NAME_REQUIRED: 'CREDENTIAL_ENV_NAME_REQUIRED',
  STORE_FAILED: 'CREDENTIAL_STORE_FAILED',
});

/** Anything that looks like a value, refused rather than ignored. */
const VALUE_SHAPED_ARG = /^--?(api[-_]?key|token|secret|password|bearer|credential)(=|$)/i;

export function parseArgs(argv) {
  const out = { handle: null, envName: null, fromFile: null, fromStdin: false, keepEnvFile: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (VALUE_SHAPED_ARG.test(token)) {
      throw new Error(`${PROVISION_ERRORS.VALUE_IN_ARGV}:${token.split('=')[0]}`);
    }
    const take = () => {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`${PROVISION_ERRORS.SOURCE_MISSING}:${token}`);
      i += 1;
      return value;
    };
    if (token === '--handle') out.handle = take();
    else if (token === '--env-name') out.envName = take();
    else if (token === '--from-file') out.fromFile = take();
    else if (token === '--from-stdin') out.fromStdin = true;
    else if (token === '--keep-env-file') out.keepEnvFile = true;
    else if (token === '--help' || token === '-h') out.help = true;
    else if (token.startsWith('-')) throw new Error(`${PROVISION_ERRORS.SOURCE_MISSING}:unknown-argument:${token}`);
    // A bare positional argument is where a value usually ends up by accident.
    else throw new Error(`${PROVISION_ERRORS.VALUE_IN_ARGV}:positional-argument`);
  }
  return out;
}

/** Read the value. Trimmed of ONE trailing newline, which a text file always has. */
export function readCredential(args, { readFile = readFileSync, stdin = null } = {}) {
  if (args.fromStdin) {
    const raw = stdin === null ? readFileSync(0, 'utf8') : stdin;
    return typeof raw === 'string' ? raw.replace(/\r?\n$/, '') : '';
  }
  if (typeof args.fromFile !== 'string' || args.fromFile.length === 0) return '';
  if (!existsSync(args.fromFile)) throw new Error(`${PROVISION_ERRORS.SOURCE_UNREADABLE}:absent`);
  return readFile(args.fromFile, 'utf8').replace(/\r?\n$/, '');
}

/**
 * Provision: read -> spool the env file -> materialise the podman secret ->
 * unlink the spool, always. The env file is the delivery channel for the run and
 * is spooled here so the caller never has to construct one.
 */
export function provision(args, { podman = spawnSync, podmanArgv = [], spoolDir, value: injected = null } = {}) {
  if (typeof args.envName !== 'string' || args.envName.length === 0) {
    throw new Error(`${PROVISION_ERRORS.ENV_NAME_REQUIRED}:--env-name`);
  }
  const declared = declaredSecretHandles(SANDBOX_ISOLATION_EXECUTOR);
  if (!declared.includes(args.handle)) {
    throw new Error(`${PROVISION_ERRORS.HANDLE_NOT_IN_PROFILE}:${String(args.handle)}`);
  }
  const value = injected ?? readCredential(args);
  if (typeof value !== 'string' || value.length < 8) {
    throw new Error(`${PROVISION_ERRORS.SOURCE_EMPTY}:too-short-to-be-a-credential`);
  }
  const dir = spoolDir ?? mkdtempSync(path.join(tmpdir(), 'veritas-cred-'));
  const owned = spoolDir === undefined;
  const envFile = spoolCredentialEnvFile(args.handle, args.envName, value, { spoolDir: dir });
  let stored = null;
  try {
    stored = materializeSecret(args.handle, value, { spoolDir: dir, podman, podmanArgv });
  } finally {
    // The env file holds the value. Leaving it for a run to pick up later would be
    // the same leak as leaving it in argv, so the caller must ask for it
    // explicitly with --keep-env-file and owns the unlink.
    if (!args.keepEnvFile) envFile.unlink();
    if (owned) rmSync(dir, { recursive: true, force: true });
  }
  return Object.freeze({
    handle: args.handle,
    env_name: args.envName,
    mount_path: secretMountPath(args.handle),
    fingerprint: fingerprint(value),
    value_in_argv: false,
    value_printed: false,
    env_file: args.keepEnvFile ? envFile.path : null,
    env_file_bytes: envFile.bytes,
    store: stored === null ? null : { handle: stored.handle ?? args.handle, created: true },
    declared_by_profile: true,
  });
}

const USAGE = `veritas-credential-provision — deliver the executor credential without putting it in an argv

  --handle <sec-…>        the descriptor the PROFILE declares (required)
  --env-name <NAME>       the variable the executor reads (required)
  --from-file <path>      read the value from a file
  --from-stdin            read the value from stdin
  --keep-env-file         keep the 0600 env file for the run instead of unlinking it

Prints the handle, the env name, the value's 16-hex fingerprint and the store
confirmation. Never the value.
`;

function main() {
  const argv = process.argv.slice(2);
  const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
  if (!isMain) return null;
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${String(error.message)}\n\n${USAGE}`);
    process.exitCode = 2;
    return null;
  }
  if (args.help || argv.length === 0) {
    process.stdout.write(USAGE);
    process.exitCode = args.help ? 0 : 2;
    return null;
  }
  try {
    const record = provision(args);
    process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
    process.exitCode = 0;
    return record;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      status: 'NOT_RUN',
      ok: false,
      code: String(error?.message ?? 'PROVISION_FAILED').split(':')[0],
      error: String(error?.message ?? error).slice(0, 300),
    }, null, 2)}\n`);
    process.exitCode = 3;
    return null;
  }
}

main();
