// S2-006 canonical JSON (canonical-json-v1).
// The single serialization convention for every verifier digest and
// idempotency key: sorted object keys (UTF-16 code-unit order, the default
// Array#sort order for strings), no whitespace, arrays keep their order
// (order is significant and never normalized), and every value must survive
// a fail-closed safety check. Node stdlib only — no dependencies.
//
// The safety check rejects anything JSON.stringify would silently mangle:
// undefined array members or roots (they cannot be represented), functions,
// symbols, BigInts, non-finite numbers (NaN/Infinity serialize to null),
// non-plain objects (Date, Map, class instances) and circular structures.
// Undefined-valued object keys are stripped deterministically (deep) — the
// canonical form is identical to the JSON that gets stored and hashed.
// Idempotency keys and digests are computed exclusively over this form.
import { createHash } from 'node:crypto';

export const CANONICAL_JSON_VERSION = 'canonical-json-v1';

function nonCanonical(reason, path) {
  const error = new TypeError(`non-canonical value at ${path || 'root'}: ${reason}`);
  error.code = 'NON_CANONICAL_VALUE';
  error.path = path || 'root';
  return error;
}

function isPlainObject(value) {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Deterministic pre-pass over the value tree. Returns true when the value can
// be canonically serialized; throws a TypeError with code NON_CANONICAL_VALUE
// otherwise. `_seen` holds the ancestor objects only, so shared (non-cyclic)
// references are allowed while true cycles fail closed.
export function assertCanonicalSafety(value, path = '', _seen = new Set()) {
  if (value === undefined) throw nonCanonical('undefined member', path);
  if (value === null) return true;
  switch (typeof value) {
    case 'boolean':
    case 'string':
      return true;
    case 'number':
      if (!Number.isFinite(value)) throw nonCanonical(`non-finite number ${String(value)}`, path);
      return true;
    case 'bigint':
      throw nonCanonical('bigint', path);
    case 'function':
    case 'symbol':
      throw nonCanonical(typeof value, path);
    case 'object':
      break;
    default:
      throw nonCanonical(`unsupported type ${typeof value}`, path);
  }
  if (_seen.has(value)) throw nonCanonical('circular structure', path);
  if (!Array.isArray(value) && !isPlainObject(value)) {
    throw nonCanonical(`non-plain object of prototype ${String(Object.getPrototypeOf(value)?.constructor?.name ?? 'null')}`, path);
  }
  _seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        assertCanonicalSafety(value[i], `${path}[${i}]`, _seen);
      }
    } else {
      for (const key of Object.keys(value)) {
        // undefined-valued object keys are stripped at encode time, so they
        // carry no canonical meaning; only array members and roots must be
        // representable. Everything else is still checked deeply.
        if (value[key] === undefined) continue;
        assertCanonicalSafety(value[key], path ? `${path}.${key}` : key, _seen);
      }
    }
  } finally {
    _seen.delete(value);
  }
  return true;
}

function encode(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      // unreachable: canonicalize() ran assertCanonicalSafety first
      throw nonCanonical(`unsupported type ${typeof value}`, 'root');
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => encode(item)).join(',')}]`;
  }
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  const members = keys.map((key) => `${JSON.stringify(key)}:${encode(value[key])}`);
  return `{${members.join(',')}}`;
}

// Canonical-json-v1 serialization: sorted-key JSON with no whitespace.
// Arrays preserve their element order; undefined-valued object keys are
// stripped (deeply).
export function canonicalize(value) {
  assertCanonicalSafety(value);
  return encode(value);
}

// SHA-256 hex digest over the canonical-json-v1 form. This is the only digest
// convention for verifier request args, idempotency keys and content digests.
export function canonicalDigest(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}
