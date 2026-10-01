import { createEgressForwarder } from '../src/lib/isolation/egress.mjs';
import { egressAllowlistForProvider } from '../src/lib/isolation/profile.mjs';

const socketPath = process.argv[2];
const provider = process.argv[3] ?? 'zai-coding-cn';
const allowlist = egressAllowlistForProvider(provider);
if (typeof socketPath !== 'string' || socketPath.length === 0) {
  process.stderr.write('FORWARDER_SOCKET_REQUIRED\n');
  process.exitCode = 2;
} else {
  const forwarder = createEgressForwarder({ allowlist, socketPath });
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await forwarder.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => { void close(); });
  process.on('SIGINT', () => { void close(); });
  try {
    await forwarder.listen();
    process.stdout.write(JSON.stringify({ event: 'FORWARDER_READY', socket: socketPath, provider, allowlist }) + '\n');
  } catch {
    process.stderr.write('FORWARDER_LISTEN_FAILED\n');
    process.exitCode = 3;
  }
}
