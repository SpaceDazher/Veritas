// S2-005 TypeScript contract type generator.
// Reads the canonical synthesis/retrieval schemas from contracts/ and emits
// src/lib/synthesis/contracts.d.ts. The schemas are the single source of
// truth: this file must never be edited by hand — regenerate with
//   node scripts/generate-synthesis-types.mjs --write
// tests/synthesis/contracts.types.test.mjs fails closed if the committed
// declaration file drifts from the schemas.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const OUT_FILE = path.join(ROOT, 'src/lib/synthesis/contracts.d.ts');

export const SYNTHESIS_CONTRACTS = Object.freeze([
  'retrieval-request',
  'retrieval-hit',
  'retrieval-run',
  'evidence-map',
  'hypothesis-card',
  'synthesis-result',
]);

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
    // cross-contract reference: retrieval-hit / evidence-map / hypothesis-card
    const external = schema.$ref.match(/https:\/\/veritas\.local\/contracts\/([a-z-]+)\.schema\.json$/);
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
      return schema.properties ? renderInterfaceBody(schema, '  ') : 'Record<string, unknown>';
    default:
      return schema.properties ? renderInterfaceBody(schema, '') : 'unknown';
  }
}

function renderInterfaceBody(schema, indent = '') {
  const lines = ['{'];
  for (const [propName, propSchema] of Object.entries(schema.properties ?? {})) {
    const required = (schema.required ?? []).includes(propName);
    const optional = required ? '' : '?';
    let type;
    if (propSchema && propSchema.type === 'object' && propSchema.properties) {
      type = renderInterfaceBody(propSchema, `${indent}  `);
    } else {
      type = toType(propSchema);
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
    '// S2-005 retrieval/synthesis contract TypeScript types.',
    '// GENERATED from contracts/*.schema.json by scripts/generate-synthesis-types.mjs.',
    '// Do not edit by hand: the JSON Schemas are the single source of truth and',
    '// tests/synthesis/contracts.types.test.mjs fails if this file drifts.',
    '',
  ];

  const chunks = [...header];
  for (const name of SYNTHESIS_CONTRACTS) {
    const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
    if (!fs.existsSync(schemaPath)) {
      console.warn(`Warning: ${schemaPath} not found, skipping`);
      continue;
    }
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    const typeName = pascal(name);
    chunks.push(`// ${name}.schema.json (contractVersion ${schema.properties?.contractVersion?.const ?? '1.0.0'})`);
    chunks.push(`export interface ${typeName} ${renderInterfaceBody(schema)}`);
    for (const [defName, defSchema] of Object.entries(schema.$defs ?? {})) {
      chunks.push(`export type ${typeName}${pascal(defName)} = ${toType(defSchema)};`);
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
    console.log(`written: ${path.relative(ROOT, OUT_FILE)} (${output.length} bytes)`);
    process.exit(0);
  }
  const current = fs.existsSync(OUT_FILE) ? fs.readFileSync(OUT_FILE, 'utf8') : '';
  if (current !== output) {
    console.error('DRIFT: src/lib/synthesis/contracts.d.ts does not match contracts/*.schema.json');
    console.error('regenerate with: node scripts/generate-synthesis-types.mjs --write');
    process.exit(1);
  }
  console.log(JSON.stringify({ ok: true, bytes: output.length, contracts: SYNTHESIS_CONTRACTS.length }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
