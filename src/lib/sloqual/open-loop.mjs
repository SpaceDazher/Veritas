// SLOQUAL-001 open-loop arrival model (no coordinated omission).
//
// The whole schedule of planned arrival instants is computed up front from
// the frozen scenario rate and seed. A request that starts late is still
// measured against its planned instant, so host saturation shows up as
// latency and lateness instead of quietly reducing the offered load — the
// coordinated-omission failure mode. The clock is the monotonic
// process.hrtime.bigint(); nothing here reads wall-clock time.
import { seededRandom } from './statistics.mjs';

export const ARRIVAL_MODEL_VERSION = 'sloqual-open-loop-v1';

const SLEEP_SLICE_NS = 2_000_000n; // 2 ms wake-up slice while waiting for a slot.

export function nowNs() {
  return process.hrtime.bigint();
}

function requirePositive(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(`SLOQUAL_ARRIVAL_INVALID: ${label} must be a positive finite number (got ${String(value)})`);
  }
  return value;
}

function requirePositiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(`SLOQUAL_ARRIVAL_INVALID: ${label} must be a positive integer (got ${String(value)})`);
  }
  return value;
}

// Planned arrival offsets in milliseconds relative to the run start.
//
// mode 'open_loop': exponential inter-arrivals with mean 1/rate, so the
//   arrival process is a Poisson-like open-loop stream, not a fixed cadence.
// mode 'burst': the first `burstSize` requests are planned inside one
//   `burstWindowMs` window (spacing = window/size), the remainder follows
//   open-loop arrivals at the scenario rate.
// mode 'closed_loop': no waiting at all (used by the security family, where
//   the trial sequence, not arrival pacing, is the subject).
export function buildArrivalSchedule({
  mode = 'open_loop',
  requests,
  ratePerSecond,
  burstSize = 0,
  burstWindowMs = 0,
  seed,
  jitter = true,
} = {}) {
  requirePositiveInteger(requests, 'requests');
  const offsets = new Array(requests);
  if (mode === 'closed_loop') {
    for (let index = 0; index < requests; index += 1) offsets[index] = 0;
    return {mode, requests, offsetsMs: offsets};
  }
  if (mode !== 'open_loop' && mode !== 'burst') {
    throw new TypeError(`SLOQUAL_ARRIVAL_INVALID: unsupported mode ${String(mode)}`);
  }
  requirePositive(ratePerSecond, 'ratePerSecond');
  if (!Number.isInteger(seed) || seed < 0) throw new TypeError('SLOQUAL_ARRIVAL_INVALID: seed must be a non-negative integer');
  const random = seededRandom(seed);
  const meanInterArrivalMs = 1000 / ratePerSecond;
  let cursorMs = 0;
  for (let index = 0; index < requests; index += 1) {
    if (mode === 'burst' && index < burstSize) {
      const spacing = burstWindowMs > 0 ? burstWindowMs / burstSize : 0;
      offsets[index] = index * spacing;
      cursorMs = offsets[index];
      continue;
    }
    // Inverse-transform sampling of an exponential inter-arrival time.
    const u = jitter ? Math.max(random(), Number.MIN_VALUE) : 0.5;
    cursorMs += -Math.log(u) * meanInterArrivalMs;
    offsets[index] = cursorMs;
  }
  return {
    mode,
    requests,
    ratePerSecond,
    meanInterArrivalMs,
    burstSize: mode === 'burst' ? burstSize : 0,
    burstWindowMs: mode === 'burst' ? burstWindowMs : 0,
    offsetsMs: offsets,
  };
}

// Blocks until the planned instant of the next request, then dispatches it.
// Returns the monotonic instants around the dispatch so the caller can
// separate waiting (lateness) from service time.
export function dispatchAt(scheduledOffsetMs, epochNs, dispatch) {
  const targetNs = epochNs + BigInt(Math.round(scheduledOffsetMs * 1e6));
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    const current = nowNs();
    if (current >= targetNs) break;
    const remainingMs = Number(targetNs - current) / 1e6;
    Atomics.wait(waiter, 0, 0, Math.max(0, Math.min(remainingMs, Number(SLEEP_SLICE_NS) / 1e6)));
  }
  const dispatchStartNs = nowNs();
  const result = dispatch();
  const completeNs = nowNs();
  return {
    result,
    latencyMs: Number(completeNs - targetNs) / 1e6,
    latenessMs: Number(dispatchStartNs - targetNs) / 1e6,
    serviceMs: Number(completeNs - dispatchStartNs) / 1e6,
  };
}
