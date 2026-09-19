// S2-006 verifier contract type generator.
// Reads every verifier schema from contracts/, resolves the TRANSITIVE $ref
// closure over the existing contract schemas (e.g. calibration-report links
// calibration-record v1 and v2 — upstream schemas are pulled in
// automatically, never hand-listed), and emits src/lib/verifier/contracts.d.ts.
// The schemas are the single source of truth: this declaration file must
// never be edited by hand — regenerate with
//   node scripts/generate-verifier-types.mjs --write
// Running without --write is the drift check: it exits 1 if the committed
// declaration file differs from what the schemas produce.
// Unlike the earlier generators, internal $defs references are rendered with
// their owning-contract prefix so every emitted interface is self-consistent.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const OUT_FILE = path.join(ROOT, 'src/lib/verifier/contracts.d.ts');
const CONTRACTS_URL_PATTERN = /^https:\/\/veritas\.local\/contracts\/([a-z0-9-]+)\.schema\.json$/;

export const VERIFIER_CONTRACTS = Object.freeze([
  'semantic-verification-request',
  'semantic-verification-item',
  'semantic-verification-result',
  'annotation-set',
  'adjudication-record',
  'verifier-run',
  'calibration-report',
  'verifier-invalidation-event',
  'semantic-provider-grant',
  'corpus-case',
  'annotation-manifest',
  'rubric',
  'calibration-record-v2',
]);

function loadSchema(name) {
  const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
  return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
}

function collectExternalRefs(node, found) {
  if (typeof node === 'string') {
    const match = node.match(CONTRACTS_URL_PATTERN);
    if (match) found.add(match[1]);
    return;
  }
  if (Array.isArray(node)) {
    for (const element of node) collectExternalRefs(element, found);
    return;
  }
  if (node !== null && typeof node === 'object') {
    for (const value of Object.values(node)) collectExternalRefs(value, found);
  }
}

// Breadth-first closure: the 13 verifier contracts first (in declared order),
// then every transitively referenced contract in deterministic sorted order.
// A $ref to a missing schema file fails closed with ENOENT.
export function resolveContractClosure() {
  const closure = new Map();
  const queue = [...VERIFIER_CONTRACTS];
  while (queue.length > 0) {
    const name = queue.shift();
    if (closure.has(name)) continue;
    const schema = loadSchema(name);
    closure.set(name, schema);
    const refs = new Set();
    collectExternalRefs(schema, refs);
    queue.push(...[...refs].filter((ref) => !closure.has(ref)).sort());
  }
  return closure;
}

const TS_KEYWORD_SAFE = (name) => (name === 'function' || name === 'return' ? `${name}_` : name);

function pascal(name) {
  return name.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

function toType(schema, defsPrefix = '') {
  if (schema === undefined || schema === true) return 'unknown';
  if (schema.$ref) {
    if (schema.$ref.startsWith('#/$defs/')) {
      return `${defsPrefix}${pascal(schema.$ref.replace('#/$defs/', ''))}`;
    }
    const external = schema.$ref.match(CONTRACTS_URL_PATTERN);
    if (external) return pascal(external[1]);
    return 'unknown';
  }
  if (schema.const !== undefined) return JSON.stringify(schema.const);
  if (Array.isArray(schema.enum)) return schema.enum.map((v) => JSON.stringify(v ?? null)).join(' | ');
  if (Array.isArray(schema.oneOf)) return schema.oneOf.map((s) => toType(s, defsPrefix)).join(' | ');
  if (Array.isArray(schema.anyOf)) return schema.anyOf.map((s) => toType(s, defsPrefix)).join(' | ');
  if (Array.isArray(schema.allOf)) return schema.allOf.map((s) => toType(s, defsPrefix)).join(' & ');
  switch (schema.type) {
    case 'string':
      return 'string';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'null':
      return 'null';
    case 'array':
      return `Array<${toType(schema.items ?? {}, defsPrefix)}>`;
    case 'object':
      return schema.properties ? renderInterfaceBody(schema, '  ', defsPrefix) : 'Record<string, unknown>';
    default:
      return schema.properties ? renderInterfaceBody(schema, '', defsPrefix) : 'unknown';
  }
}

function renderInterfaceBody(schema, indent = '', defsPrefix = '') {
  const lines = ['{'];
  for (const [propName, propSchema] of Object.entries(schema.properties ?? {})) {
    const required = (schema.required ?? []).includes(propName);
    const optional = required ? '' : '?';
    let type;
    if (propSchema && propSchema.type === 'object' && propSchema.properties) {
      type = renderInterfaceBody(propSchema, `${indent}  `, defsPrefix);
    } else {
      type = toType(propSchema, defsPrefix);
    }
    const safeName = /^[A-Za-z0-9_$]+$/.test(propName) ? propName : JSON.stringify(propName);
    lines.push(`${indent}  ${TS_KEYWORD_SAFE(safeName)}${optional}: ${type};`);
  }
  if ((schema.additionalProperties ?? true) === true) {
    lines.push(`${indent}  [key: string]: unknown;`);
  }
  lines.push(`${indent}}`);
  return lines.join('\n');
}

export function generateTypes() {
  const header = [
    '// S2-006 verifier contract TypeScript types.',
    '// GENERATED from contracts/*.schema.json by scripts/generate-verifier-types.mjs',
    '// (including the transitive $ref closure over upstream contract schemas).',
    '// Do not edit by hand: the JSON Schemas are the single source of truth and',
    '// tests/verifier/contracts.test.mjs fails if this file drifts.',
    '',
  ];

  const closure = resolveContractClosure();
  const chunks = [...header];
  for (const [name, schema] of closure) {
    const typeName = pascal(name);
    chunks.push(`// ${name}.schema.json (contractVersion ${schema.properties?.contractVersion?.const ?? 'n/a'})`);
    chunks.push(`export interface ${typeName} ${renderInterfaceBody(schema, '', typeName)}`);
    for (const [defName, defSchema] of Object.entries(schema.$defs ?? {})) {
      chunks.push(`export type ${typeName}${pascal(defName)} = ${toType(defSchema, typeName)};`);
    }
    chunks.push('');
  }
  return chunks.join('\n');
}

function main() {
  const output = `${generateTypes().replace(/\s+$/, '\n')}`;
  if (process.argv.includes('--write')) {
    fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
    fs.writeFileSync(OUT_FILE, output);
    console.log(`written: ${path.relative(ROOT, OUT_FILE)} (${output.length} bytes, ${resolveContractClosure().size} contracts incl. transitive closure)`);
    process.exit(0);
  }
  const current = fs.existsSync(OUT_FILE) ? fs.readFileSync(OUT_FILE, 'utf8') : '';
  if (current !== output) {
    console.error('DRIFT: src/lib/verifier/contracts.d.ts does not match contracts/*.schema.json');
    console.error('regenerate with: node scripts/generate-verifier-types.mjs --write');
    process.exit(1);
  }
  console.log(JSON.stringify({ ok: true, bytes: output.length, contracts: resolveContractClosure().size }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
