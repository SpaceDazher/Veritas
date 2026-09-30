import { createEgressForwarder } from '../src/lib/isolation/egress.mjs';
import { ISOLATION_EGRESS_ALLOWLIST } from '../src/lib/isolation/profile.mjs';

const socketPath = process.argv[2];
if (typeof socketPath !== 'string' || socketPath.length === 0) {
  process.stderr.write('FORWARDER_SOCKET_REQUIRED\n');
  process.exitCode = 2;
} else {
  const forwarder = createEgressForwarder({ allowlist: ISOLATION_EGRESS_ALLOWLIST, socketPath });
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
    process.stdout.write(JSON.stringify({ event: 'FORWARDER_READY', socket: socketPath }) + '\n');
  } catch {
    process.stderr.write('FORWARDER_LISTEN_FAILED\n');
    process.exitCode = 3;
  }
}
