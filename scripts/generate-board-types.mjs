// S2-007 Agent Board contract type generator.
// Reads every board schema from contracts/, resolves the TRANSITIVE $ref
// closure over the existing contract schemas (execution-request links
// board-task's $defs/workspaceRef and execution-result links board-error —
// upstream schemas are pulled in automatically, never hand-listed), and emits
// src/lib/agentboard/contracts.d.ts. The schemas are the single source of
// truth (issue #7 §2: one authoritative contract, validated only through
// src/lib/agentboard/contracts.mjs); this declaration file must never be
// edited by hand — regenerate with
//   node scripts/generate-board-types.mjs --write
// Running without --write is the drift check: it exits 1 if the committed
// declaration file differs from what the schemas produce.
// Like the verifier generator, internal $defs references are rendered with
// their owning-contract prefix so every emitted interface is self-consistent:
// board-task's workspaceRef becomes BoardTaskWorkspaceRef, and the same
// cross-document ref in execution-request resolves to that same type instead
// of collapsing to `unknown`. A $ref to a schema file that does not exist
// fails closed with ENOENT rather than degrading to best-effort output.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACTS_DIR = path.join(ROOT, 'contracts');
const OUT_FILE = path.join(ROOT, 'src/lib/agentboard/contracts.d.ts');
// A reference to another contract, optionally into that contract's $defs.
// The optional fragment matters for S2-007: execution-request points at
// `board-task.schema.json#/$defs/workspaceRef`, so both the owning contract
// and the definition name are needed to emit one resolvable type name.
const CONTRACTS_URL_PATTERN = /^https:\/\/veritas\.local\/contracts\/([a-z0-9-]+)\.schema\.json(?:#\/\$defs\/([A-Za-z0-9_$]+))?$/;

// The eight authoritative S2-007 documents, in the order of the board
// lifecycle. Every one of them is a root; anything they reference arrives
// through the closure below. This list is deliberately the same set as
// BOARD_CONTRACTS in src/lib/agentboard/contracts.mjs — the runtime
// validation surface and the type surface describe one boundary.
export const BOARD_CONTRACTS = Object.freeze([
  'board-task',
  'board-transition',
  'adapter-registration',
  'dispatch-decision',
  'execution-request',
  'execution-event',
  'execution-result',
  'board-error',
]);

// Fail closed: a missing or unparseable schema file aborts the generation
// instead of silently emitting a declaration file without that contract.
export function loadSchema(name) {
  const schemaPath = path.join(CONTRACTS_DIR, `${name}.schema.json`);
  return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
}

export function collectExternalRefs(node, found = new Set()) {
  if (typeof node === 'string') {
    const match = node.match(CONTRACTS_URL_PATTERN);
    if (match) found.add(match[1]);
    return found;
  }
  if (Array.isArray(node)) {
    for (const element of node) collectExternalRefs(element, found);
    return found;
  }
  if (node !== null && typeof node === 'object') {
    for (const value of Object.values(node)) collectExternalRefs(value, found);
  }
  return found;
}

// Breadth-first closure: the given roots first (in declared order), then every
// transitively referenced contract in deterministic sorted order. The roots are
// a parameter with a frozen default so the closure itself can be exercised on a
// reduced root set: with only execution-request and execution-result as roots,
// board-task and board-error must still arrive through the walker, which is
// what proves the cross-document references are resolved automatically and not
// merely satisfied because the same documents happen to be roots.
// A $ref to a missing schema file fails closed with ENOENT.
export function resolveContractClosure(roots = BOARD_CONTRACTS) {
  const closure = new Map();
  const queue = [...roots];
  while (queue.length > 0) {
    const name = queue.shift();
    if (closure.has(name)) continue;
    const schema = loadSchema(name);
    closure.set(name, schema);
    const refs = collectExternalRefs(schema);
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
    const internal = schema.$ref.startsWith('#/$defs/');
    const external = schema.$ref.match(CONTRACTS_URL_PATTERN);
    if (internal) {
      return `${defsPrefix}${pascal(schema.$ref.replace('#/$defs/', ''))}`;
    }
    if (external) {
      // A cross-document $ref is rendered with the OWNING contract's prefix,
      // fragment or not, so `...board-task.schema.json#/$defs/workspaceRef`
      // and board-task's own `#/$defs/workspaceRef` both resolve to the very
      // same declared type.
      return `${pascal(external[1])}${external[2] ? pascal(external[2]) : ''}`;
    }
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

export function generateTypes(roots = BOARD_CONTRACTS) {
  const header = [
    '// S2-007 Agent Board contract TypeScript types.',
    '// GENERATED from contracts/*.schema.json by scripts/generate-board-types.mjs',
    '// (including the transitive $ref closure over the upstream contract schemas).',
    '// Do not edit by hand: the JSON Schemas are the single source of truth,',
    '// src/lib/agentboard/contracts.mjs is the single validation surface, and',
    '// tests/agentboard/contracts-drift.test.mjs fails if this file drifts.',
    '',
  ];

  const closure = resolveContractClosure(roots);
  const chunks = [...header];
  for (const [name, schema] of closure) {
    const typeName = pascal(name);
    // Board documents spell the version marker `contractVersion`, the
    // veritas.execution/1.0.0 boundary spells it `contract_version`.
    const version = schema.properties?.contractVersion?.const
      ?? schema.properties?.contract_version?.const
      ?? 'n/a';
    chunks.push(`// ${name}.schema.json (contractVersion ${version})`);
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
    console.error('DRIFT: src/lib/agentboard/contracts.d.ts does not match contracts/*.schema.json');
    console.error('regenerate with: node scripts/generate-board-types.mjs --write');
    process.exit(1);
  }
  console.log(JSON.stringify({ ok: true, bytes: output.length, contracts: resolveContractClosure().size }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
