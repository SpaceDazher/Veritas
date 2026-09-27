// S2-002 process-tree fixture: one definition of "a tree a naive kill misses",
// shared by the frozen corpus runner, the adversarial probes, the cancellation
// verification stage and the regression suite.
//
// Honesty boundary: this is a test instrument, not a containment boundary. It
// spawns a child that itself starts a descendant in a way that a group- or
// parent-only kill provably cannot reach, and that publishes the descendant's
// own pid, so callers can verify liveness independently of the adapter's
// verdict instead of trusting the adapter's own verdict.
//
//   POSIX  - setsid(2) moves the descendant into a new session.
//   Windows- Start-Process starts an independent process that does not inherit
//            the parent's stdio handles, so the run can finish while the
//            descendant is still alive. The chain is nested with
//            -EncodedCommand so no level has to quote the level below it.
import fs from 'node:fs';
import path from 'node:path';

const PS_QUOTE = (value) => `'${String(value).replace(/'/g, "''")}'`;
const PS_ENCODE = (script) => Buffer.from(script, 'utf16le').toString('base64');
// Single quotes, so the OUTER shell does not expand the inner script. With
// double quotes the outer /bin/sh expanded `$$` to its own pid, so the
// published pid was the root's — the very process the adapter already tracks.
// Every "independent ground truth" check downstream was then reading the
// adapter's own root back to itself instead of the descendant it claims to
// observe independently.
const SH_QUOTE = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;

export const TREE_PID_FILE = 'tree.pid';

export function buildEscapingProcessTree(root, { platform = process.platform, depth = 1 } = {}) {
  const pidFile = path.join(root, TREE_PID_FILE);
  if (platform === 'win32') {
    let inner = `$p = Start-Process -FilePath 'ping.exe' -ArgumentList '-n','60','127.0.0.1' -PassThru -WindowStyle Hidden;` +
      ` Set-Content -LiteralPath ${PS_QUOTE(pidFile)} -Value $p.Id;` +
      ` Start-Sleep -Seconds 60`;
    for (let level = 1; level < depth; level += 1) {
      inner = `$p = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','${PS_ENCODE(inner)}' -PassThru -WindowStyle Hidden;` +
        ` Start-Sleep -Seconds 60`;
    }
    return {
      platform: 'win32',
      command: 'powershell.exe',
      args: ['-NoProfile', '-NonInteractive', '-EncodedCommand', PS_ENCODE(inner)],
      pidFile,
    };
  }
  const posixPidFile = pidFile.split('\\').join('/');
  let inner = `echo $$ > ${posixPidFile}; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do sleep 5; done`;
  for (let level = 1; level < depth; level += 1) inner = `/bin/sh -c ${SH_QUOTE(inner)}`;
  return {
    platform: 'posix',
    command: '/bin/sh',
    args: ['-c', `setsid /bin/sh -c ${SH_QUOTE(inner)} & sleep 60`],
    pidFile,
  };
}

export function readPublishedPids(pidFile) {
  try {
    return fs.readFileSync(pidFile, 'utf8')
      .split(/\s+/)
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0);
  } catch {
    return [];
  }
}

// Waits until the deepest process has published its pid, so a caller never
// races process creation and never treats "no pid file yet" as "no tree".
export async function waitForPublishedPids(pidFile, { attempts = 40, intervalMs = 100 } = {}) {
  let pids = [];
  for (let attempt = 0; attempt < attempts && pids.length === 0; attempt += 1) {
    await new Promise((resolveTimer) => setTimeout(resolveTimer, intervalMs));
    pids = readPublishedPids(pidFile);
  }
  return pids;
}
