// S2-008 #12 — the in-container egress BRIDGE: a loopback TCP port to the unix socket.
//
// WHY THIS PROGRAM EXISTS AT ALL
// `createEgressForwarder` (src/lib/isolation/egress.mjs) speaks HTTP CONNECT over
// a UNIX socket, and the profile mounts exactly one socket into the container. But
// `pi` is an openai-completions client: it speaks HTTP CONNECT to an HTTP PROXY on
// a TCP PORT. There was no client half anywhere, so the paid leg had no path from
// the model to the single destination the policy allows. This is that half, and it
// is the only thing between the model and the network.
//
// THE PROPERTY THAT MAKES IT SAFE: THE BRIDGE HAS NO OUTBOUND PATH OF ITS OWN.
// It resolves nothing, dials no host, and opens exactly one kind of connection — to
// the unix socket the profile mounted. The allowlist, the refusal codes and every
// logged decision stay in the forwarder, which is on the HOST side of the boundary.
// A bridge that could dial anything would be a second, unaudited egress, which is
// the exact thing the `--network=none` profile exists to prevent.
//
// It binds 127.0.0.1 only. Under `--network=none` the container has nothing but
// loopback, so this port is unreachable from the host and from anywhere else in
// that network namespace; the only way out is the socket.
//
//   node bridge.mjs --port <port> --socket <path>
//
// It logs CONNECTION EVENTS and never payload bytes, like the forwarder.
import net from 'node:net';

export const BRIDGE_ERRORS = Object.freeze({
  ARGS: 'BRIDGE_ARGUMENTS_INCOMPLETE',
  BIND: 'BRIDGE_BIND_FAILED',
  SOCKET_MISSING: 'BRIDGE_SOCKET_MISSING',
  HANDSHAKE: 'BRIDGE_HANDSHAKE_FAILED',
});

/** The first line of an HTTP request, and only the first line. Never the body. */
export function requestHead(buffer) {
  const end = buffer.indexOf('\r\n');
  if (end === -1) return null;
  return buffer.subarray(0, end).toString('utf8');
}

/**
 * Pipe one client connection to the forwarder. Resolves with what happened, so a
 * test can read the outcome instead of inferring it from a timeout.
 *
 * The head the client sent is forwarded VERBATIM — the bridge does not rewrite the
 * destination, so the policy sees the destination the model actually asked for and
 * not one this program chose.
 */
export function bridgeConnection(client, socketPath, { log = () => {}, onForwarded } = {}) {
  return new Promise((resolve) => {
    const head = [];
    let settled = false;
    const finish = (outcome, detail) => {
      if (settled) return;
      settled = true;
      // One name for the same fact in both the log line and the resolved value:
      // a program that calls it `event` in one place and `outcome` in another costs
      // a reader the difference, and nothing buys it.
      log({ outcome, ...detail });
      resolve({ outcome, ...detail });
    };
    let buffered = Buffer.alloc(0);
    const onClientData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (requestHead(buffered) === null) return; // wait for the request line
      client.removeListener('data', onClientData);

      // The one and only connection this program opens.
      const upstream = net.connect(socketPath);
      upstream.once('error', (error) => {
        // A missing socket is NOT an admission and NOT a refusal by the policy: the
        // forwarder is not there. Reported as its own outcome so nobody reads it
        // as "the destination was refused by the allowlist".
        finish('SOCKET_UNAVAILABLE', { code: String(error?.code ?? 'UNKNOWN') });
        client.destroy();
      });
      upstream.once('connect', () => {
        upstream.write(buffered);
        // Relay the forwarder's own answer — 200 or 403 — before piping, so the
        // client learns the verdict from the component that made it.
        const onUpstreamData = (reply) => {
          upstream.removeListener('data', onUpstreamData);
          client.write(reply);
          const line = requestHead(reply) ?? '';
          head.push(line);
          onForwarded?.(line);
          upstream.pipe(client);
          client.pipe(upstream);
          finish('FORWARDED', { request: requestHead(buffered) ?? '', response: line });
        };
        upstream.on('data', onUpstreamData);
        upstream.on('error', () => {
          client.destroy();
          finish('UPSTREAM_FAILED', {});
        });
      });
    };
    client.on('data', onClientData);
    client.once('error', (error) => finish('CLIENT_ERROR', { code: String(error?.code ?? 'UNKNOWN') }));
    client.once('close', () => finish('CLIENT_CLOSED', {}));
  });
}

export function parseArgs(argv) {
  const out = { port: null, socket: null };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const take = () => {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`${BRIDGE_ERRORS.ARGS}:${token}`);
      i += 1;
      return value;
    };
    if (token === '--port') out.port = Number(take());
    else if (token === '--socket') out.socket = take();
    else if (token === '--help' || token === '-h') out.help = true;
    else throw new Error(`${BRIDGE_ERRORS.ARGS}:unknown-argument:${token}`);
  }
  return out;
}

/** Bind loopback only. There is no option to bind elsewhere, by design. */
export function createBridge({ port, socketPath, log = () => {} }) {
  // port 0 means "an ephemeral port", and it is allowed on purpose: the launcher
  // reads the chosen port back from the BRIDGE_READY line and puts it in the proxy
  // environment, so nothing has to agree on a fixed number in advance. A fixed
  // port is still what the campaign will use; 0 is here so a test never collides.
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`${BRIDGE_ERRORS.ARGS}:port`);
  if (typeof socketPath !== 'string' || socketPath.length === 0) throw new Error(`${BRIDGE_ERRORS.ARGS}:socket`);
  const events = [];
  const server = net.createServer((client) => {
    void bridgeConnection(client, socketPath, { log: (event) => { events.push(event); log(event); } });
  });
  return {
    server,
    events,
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      // 127.0.0.1 and nothing else: under --network=none this is unreachable from
      // the host, and a future `--network=slirp4netns` must not silently widen it.
      server.listen({ host: '127.0.0.1', port }, () => resolve({ port: server.address().port }));
    }),
    close: () => new Promise((resolve) => server.close(() => resolve(true))),
  };
}

const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${String(error.message)}\n`);
    process.exitCode = 2;
  }
  if (args && args.help) {
    process.stdout.write('bridge --port <port> --socket <path>\n  loopback TCP -> the mounted unix socket; no outbound path of its own\n');
  } else if (args) {
    const bridge = createBridge({
      port: args.port,
      socketPath: args.socket,
      log: (event) => process.stdout.write(`${JSON.stringify(event)}\n`),
    });
    bridge.listen().then(({ port }) => {
      process.stdout.write(`${JSON.stringify({ event: 'BRIDGE_READY', port, socket: args.socket, host: '127.0.0.1' })}\n`);
    }).catch((error) => {
      process.stderr.write(`${BRIDGE_ERRORS.BIND}:${String(error?.code ?? error?.message ?? 'UNKNOWN')}\n`);
      process.exitCode = 3;
    });
  }
}
