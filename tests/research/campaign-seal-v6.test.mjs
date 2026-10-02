import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalDigest } from '../../src/lib/verifier/canonical-json.mjs';
import { sealV6 } from '../../scripts/s2-008-campaign-seal-v6.mjs';
import { approveV6, createV6Draft } from '../../scripts/s2-008-campaign-v6-approval.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const corpus = path.join(root, 'corpus/s2-008-campaign');
const read = (file) => JSON.parse(fs.readFileSync(path.join(corpus, file), 'utf8'));

function input() {
  const baseBytes = fs.readFileSync(path.join(corpus, 'preregistration.v5.in-force.json'));
  const base = JSON.parse(baseBytes);
  const table = read('frozen-table.v3.json');
  const previousPin = JSON.parse(fs.readFileSync(path.join(root, 'evidence/s2-008-campaign/model-image-pin-v5.json')));
  const sources = {
    ...previousPin.first.sources,
    prereg: createHash('sha256').update(baseBytes).digest('hex'),
    pi_runtime_tree: 'e'.repeat(64),
    timeout_policy: 'd'.repeat(64),
  };
  const covers = Object.keys(sources).filter((name) => name !== 'prereg').sort();
  const commitment = canonicalDigest(Object.fromEntries(covers.map((name) => [name, sources[name]])));
  const first = {
    ...previousPin.first,
    sources,
    source_digest: canonicalDigest(sources),
    content_commitment: commitment,
    content_commitment_covers: covers,
  };
  const pin = {
    ...previousPin,
    schema: 's2-008-model-image-pin/6',
    commitment_excludes_preregistration: true,
    first,
    second: structuredClone(first),
    commitment: { ...previousPin.commitment, covers, excludes: ['prereg'] },
  };
  const draft = createV6Draft({ base, baseBytes, pin });
  const signed = approveV6({
    draft, base, baseBytes, table, pin,
    principal: 'prn-s2007r-owner', label: 'Daniil (repository owner)',
    issuedAt: '2026-09-30T00:00:00.000Z',
  });
  const ledger = read('source-ledger.v3.json');
  const historyEntry = {
    file: 'preregistration-v5-supersession.json',
    supersession_id: 'xpr-s2-008c-05',
    supersession_digest: 'c'.repeat(64),
    reason: 'v5 supersession',
  };
  const manifest = {
    preregistration: {
      file: 'preregistration.v5.in-force.json',
      status: 'IN_FORCE',
      preregistration_digest: base.preregistration_digest,
    },
    frozen_table: { file: 'frozen-table.v3.json', digest: canonicalDigest(table) },
    source_ledger: {
      entry_count: ledger.entries.length,
      last_anchor_digest: ledger.entries.at(-1).anchor_digest,
    },
    supersession_history: [historyEntry],
    supersession: historyEntry,
  };
  return { signed, draft, base, baseBytes, table, pin, manifest, ledger };
}

test('v6 seal activates the signed document and appends a content supersession without changing science or ledger', () => {
  const before = input();
  const result = sealV6(before);
  assert.equal(result.prereg.approval.in_force, true);
  assert.equal(result.manifest.preregistration.file, 'preregistration.v6.in-force.json');
  assert.equal(result.manifest.preregistration.preregistration_digest, before.signed.preregistration_digest);
  assert.equal(result.manifest.superseded_preregistration.preregistration_digest, before.base.preregistration_digest);
  assert.equal(result.manifest.supersession_history.length, 2);
  assert.equal(result.supersession.supersedes, before.base.preregistration_digest);
  assert.equal(canonicalDigest(result.ledger), canonicalDigest(before.ledger));
  assert.equal(canonicalDigest(result.prereg.trial_list), canonicalDigest(before.base.trial_list));
});

test('v6 seal refuses unsigned approval and changed signed content', () => {
  const unsigned = input();
  unsigned.signed.approval.status = null;
  assert.throws(() => sealV6(unsigned), /V6_NOT_APPROVED/);

  const altered = input();
  altered.signed.metric.name = 'altered';
  assert.throws(() => sealV6(altered), /V6_DIGEST_MISMATCH/);
});
