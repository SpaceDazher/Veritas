// S2-005 synthesis contract validation.
// Fail-closed ajv validation of every retrieval/synthesis contract object;
// the JSON Schemas in contracts/ are the single source of truth and every
// runtime payload crosses this boundary before it is returned or stored.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');

export const SYNTHESIS_CONTRACTS = Object.freeze([
  'retrieval-request',
  'retrieval-hit',
  'retrieval-run',
  'evidence-map',
  'hypothesis-card',
  'synthesis-result',
]);

let validator = null;

export function synthesisValidators(io = {}) {
  if (validator && !io.reload) return validator;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const schemas = {};
  for (const name of SYNTHESIS_CONTRACTS) {
    const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    ajv.addSchema(schema, schema.$id);
    schemas[name] = schema;
  }
  const compiled = new Map();
  for (const name of SYNTHESIS_CONTRACTS) {
    compiled.set(name, ajv.getSchema(`https://veritas.local/contracts/${name}.schema.json`));
  }
  validator = {
    schemas,
    validate(name, object) {
      const fn = compiled.get(name);
      if (!fn) throw new Error(`unknown contract: ${name}`);
      const ok = fn(object);
      return { ok, errors: ok ? [] : fn.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ') };
    },
    requireValid(name, object) {
      const result = this.validate(name, stripUndefined(object));
      if (!result.ok) {
        const error = new Error(`contract ${name} rejected payload: ${result.errors}`);
        error.code = 'CONTRACT_REJECTED';
        error.contract = name;
        error.issues = result.errors;
        throw error;
      }
      return object;
    },
  };
  return validator;
}

function stripUndefined(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(stripUndefined);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = stripUndefined(value[key]);
  }
  return out;
}
