const VERSIONED_IN_FORCE_FILE = /^preregistration\.v\d+\.in-force\.json$/;
const SEAL_VERSIONS = new Set([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

export function parsePrepareMode(argv = []) {
  if (!Array.isArray(argv)) throw new Error('PREPARE_MODE_INVALID');
  const modes = [];
  for (const token of argv) {
    if (token === '--check') modes.push('check');
    else if (token === '--selftest') modes.push('selftest');
    else if (typeof token === 'string' && token.startsWith('--seal-v')) {
      const match = /^--seal-v(2|[3-9]|1[0-5])$/.exec(token);
      if (!match || !SEAL_VERSIONS.has(Number(match[1]))) throw new Error('PREPARE_VERSION_INVALID');
      modes.push('seal-v' + match[1]);
    } else throw new Error('PREPARE_MODE_INVALID');
  }
  if (modes.length > 1) throw new Error('PREPARE_MODE_INVALID');
  return modes[0] ?? 'write';
}

export function assertPrepareWriteAllowed(manifest) {
  const active = manifest?.preregistration;
  if (active?.status === 'IN_FORCE' && VERSIONED_IN_FORCE_FILE.test(active.file ?? '')) {
    throw new Error('VERSIONED_IN_FORCE_REFUSES_DEFAULT_WRITE');
  }
  return true;
}
