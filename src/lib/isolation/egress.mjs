// S2-002 A-MVP-04 — the network allowlist, enforced by something.
//
// WHY A FORWARDER EXISTS. Rootless podman cannot express `network.policy:
// 'allowlist'`. Measured on this host: `--network=slirp4netns` installs a
// default route to 10.0.2.2 for EVERY destination, and a `connect()` to an
// arbitrary host succeeds, so a profile that names one host would be naming
// something the runtime does not enforce. `--network=none` is the opposite
// extreme and is fully enforced: /proc/net/route inside the container is
// header-only and `connect()` to the model API host answers `EAI_AGAIN`.
//
// The pairing that makes an allowlist real is therefore:
//
//     --network=none            the container has no route at all
//     + one mounted unix socket the launcher chose
//     + a forwarder that admits exactly the profile's {host, ports}
//
// The kernel denies everything; the forwarder grants the named destinations.
// Neither half alone would do, and the container cannot reach the forwarder by
// any other route, which is what makes the grant the only exit rather than one
// of two.
//
// WHAT THE FORWARDER CAN AND CANNOT SEE. It speaks `CONNECT` and then pipes
// bytes in both directions. TLS is end-to-end between the executor and the API
// host, so the forwarder never holds a credential and never terminates a
// session; what it reads is the request line, i.e. destination host and port.
// That is also why it is a sufficient enforcement point for a network axis and
// an insufficient one for anything else — the TLS peer is authenticated by the
// executor, not by this process.
import net from 'node:net';
import { chmodSync, unlinkSync } from 'node:fs';

export const EGRESS_ERRORS = Object.freeze({
  NOT_ALLOWLISTED: 'EGRESS_NOT_ALLOWLISTED',
  MALFORMED: 'EGRESS_REQUEST_MALFORMED',
  UPSTREAM: 'EGRESS_UPSTREAM_UNREACHABLE',
});

const MAX_REQUEST_LINE = 4096;

/**
 * Every refusal is one line of JSON on the refusal stream and one HTTP status
 * with a machine-readable header. A refusal that cannot be told apart from a
 * connection that simply dropped is not usable as a negative control, because
 * "no bytes came back" is also what a crashed forwarder looks like — measured,
 * not assumed: a first version of this probe declared its allowlist as a `Set`
 * and called `.some()` on it, the forwarder died, and all three probes read
 * `ECONNREFUSED`.
 */
function refuse(socket, code, detail, log) {
  const payload = JSON.stringify({ refused: code, detail, at: detail.host ? `${detail.host}:${detail.port}` : null });
  log?.({ decision: 'REFUSED', code, ...detail });
  socket.end(
    `HTTP/1.1 403 Forbidden\r\n`
    + `X-Veritas-Refusal: ${code}\r\n`
    + `Content-Type: application/json\r\n`
    + `Content-Length: ${Buffer.byteLength(payload)}\r\n`
    + 'Connection: close\r\n\r\n'
    + payload,
  );
}

/**
 * Parse the REQUEST LINE only.
 *
 * The input is the whole header block, and anchoring the regex to the end of it
 * with `$` is the bug this comment exists for: a `CONNECT` request carries
 * `Host:` after the request line, so `$` never matches and every request is
 * refused as `EGRESS_REQUEST_MALFORMED`. Measured — that is exactly what the
 * first live run answered, three times, for three well-formed CONNECTs
 * including the allowlisted one. The negative control "refused" was passing for
 * the wrong reason, which is the failure mode the admitted-pair inversion exists
 * to catch.
 */
export function parseConnectRequest(block) {
  const requestLine = String(block).split('\r\n')[0];
  const match = /^(?:CONNECT|GET|POST)\s+(\S+)\s+HTTP\/(?:1\.0|1\.1)\s*$/.exec(requestLine);
  if (!match) return null;
  const target = match[1];
  const colon = target.lastIndexOf(':');
  if (colon <= 0) return null;
  const host = target.slice(0, colon);
  const port = Number(target.slice(colon + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return Object.freeze({ host, port, method: requestLine.split(' ')[0] });
}

/**
 * @param {object} options
 * @param {ReadonlyArray<{host: string, ports: ReadonlyArray<number>}>} options.allowlist
 * @param {string} options.socketPath  unix socket to bind; the only path out of the container
 * @param {(decision: object) => void} [options.log]  records every decision, never payload bytes
 * @param {(host: string, port: number) => boolean} [options.preflight]  extra gate, e.g. a policy call
 */
export function createEgressForwarder({ allowlist, socketPath, log, preflight } = {}) {
  if (!Array.isArray(allowlist) || allowlist.length === 0) throw new Error(`${EGRESS_ERRORS.MALFORMED}:allowlist`);
  if (typeof socketPath !== 'string' || socketPath.length === 0) throw new Error(`${EGRESS_ERRORS.MALFORMED}:socketPath`);
  // A wildcard host would make the forwarder a pass-through. The profile gate
  // already refuses one; refusing it again here means the forwarder cannot be
  // built into a pass-through even by a caller that skipped that gate.
  for (const entry of allowlist) {
    if (!entry || entry.host === '*' || entry.ports?.includes(0)) {
      throw new Error(`${EGRESS_ERRORS.MALFORMED}:wildcard`);
    }
  }
  try { unlinkSync(socketPath); } catch { /* absent is the normal case */ }

  const admits = (host, port) => allowlist.some((entry) => entry.host === host && entry.ports.includes(port));

  const server = net.createServer((client) => {
    client.setEncoding('utf8');
    let head = '';
    const onData = (chunk) => {
      head += chunk;
      if (head.length > MAX_REQUEST_LINE) {
        client.off('data', onData);
        refuse(client, EGRESS_ERRORS.MALFORMED, { host: null, port: null }, log);
        return;
      }
      const end = head.indexOf('\r\n\r\n');
      if (end === -1) return;
      client.off('data', onData);
      const request = parseConnectRequest(head.slice(0, end));
      if (!request) {
        refuse(client, EGRESS_ERRORS.MALFORMED, { host: null, port: null }, log);
        return;
      }
      const decision = {
        decision: 'ADMITTED',
        host: request.host,
        port: request.port,
        method: request.method,
      };
      if (!admits(request.host, request.port)) {
        refuse(client, EGRESS_ERRORS.NOT_ALLOWLISTED, request, log);
        return;
      }
      if (typeof preflight === 'function' && preflight(request.host, request.port) !== true) {
        refuse(client, EGRESS_ERRORS.NOT_ALLOWLISTED, request, log);
        return;
      }
      const upstream = net.connect(request.port, request.host, () => {
        log?.(decision);
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        client.removeAllListeners('end');
        client.removeAllListeners('close');
        upstream.pipe(client);
        client.pipe(upstream);
      });
      upstream.on('error', () => {
        log?.({ ...decision, decision: 'UPSTREAM_FAILED' });
        client.destroy();
      });
    };
    client.on('data', onData);
  });

  return {
    socketPath,
    allowlist: allowlist.map((entry) => ({ host: entry.host, ports: [...entry.ports] })),
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, () => {
        // The container runs as 65534:65534 and the socket is created 0755 by
        // the umask, so without this the container gets EACCES on the one path
        // it is allowed to take. 0777 on a unix socket grants `connect` to any
        // local uid, which is bounded by the allowlist the forwarder enforces
        // and is recorded rather than left implicit.
        chmodSync(socketPath, 0o777);
        resolve({ socketPath });
      });
    }),
    close: () => new Promise((resolve) => {
      server.close(() => {
        try { unlinkSync(socketPath); } catch { /* already gone */ }
        resolve();
      });
    }),
  };
}
