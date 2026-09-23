import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  MODEL,
  buildCandidate,
  buildRequest,
  parseDiagnosis,
  requestDiagnosis,
  runPilot,
  loadPilotCases,
} from '../../scripts/s2-006m-pilot.mjs';

const pair = { archive: 'v05', candidateId: 'vcase-1', episodeId: 'ep-1', semanticTemplate: 'event_date', qualityFlag: null };
const draft = {
  caseId: 'vcase-1', videoId: 'ep-1', semanticTemplate: 'event_date', sourceStatus: 'ACCEPT',
  claim: 'Событие произошло в 2020 году.', speaker: 'Гость',
  evidenceSpans: [{ quote: 'Я говорил, что событие произошло в 2020 году.' }],
};

test('candidate maps only the selected ACCEPT case and source quote', () => {
  assert.deepEqual(buildCandidate(pair, draft), {
    caseId: 'vcase-1', episodeId: 'ep-1', semanticTemplate: 'event_date',
    claim: draft.claim, quote: draft.evidenceSpans[0].quote, speaker: 'Гость',
    qualityFlag: null,
  });
  assert.throws(() => buildCandidate(pair, { ...draft, sourceStatus: 'NEEDS_SOURCE' }), /ACCEPT/);
  assert.throws(() => buildCandidate(pair, { ...draft, videoId: 'other' }), /episode/);
  assert.throws(() => buildCandidate(pair, { ...draft, evidenceSpans: [] }), /quote/);
  assert.throws(() => buildCandidate({ ...pair, archive: 'unknown' }, draft), /archive/);
  assert.throws(() => buildCandidate(pair, { ...draft, semanticTemplate: 'other' }), /template/);
  assert.throws(() => buildCandidate(pair, { ...draft, claim: 'x'.repeat(801) }), /too long/);
});

test('candidate maps package JSONL format and refuses a missing supporting span', () => {
  const packageCase = {
    candidateId: 'pcase-1', source: { episodeId: 'ep-2', speaker: 'Ведущий' },
    semanticTemplate: 'definition', status: 'ACCEPT',
    claim: { statement: 'Термин означает X.' },
    evidenceSpans: [{ kind: 'supporting', quote: 'Под термином я понимаю X.' }],
  };
  const packagePair = { ...pair, archive: 'ah6', candidateId: 'pcase-1', episodeId: 'ep-2', semanticTemplate: 'definition' };
  assert.equal(buildCandidate(packagePair, packageCase).quote, 'Под термином я понимаю X.');
  assert.throws(() => buildCandidate(packagePair, { ...packageCase, evidenceSpans: [{ kind: 'context', quote: 'X' }] }), /quote/);
});

test('request is pinned to the free model, one short quote, and untrusted-input instructions', () => {
  const candidate = buildCandidate(pair, draft);
  const request = buildRequest(candidate);
  assert.equal(request.model, MODEL);
  assert.equal(request.temperature, 0);
  assert.ok(request.max_tokens <= 220);
  assert.equal(request.messages.length, 2);
  assert.match(request.messages[0].content, /untrusted/i);
  assert.match(request.messages[1].content, /2020 году/);
  assert.ok(!('models' in request));
  assert.ok(!('response_format' in request));
  assert.throws(() => buildRequest({ ...candidate, quote: 'x'.repeat(2001) }), /too long/);
});

test('diagnosis parser is fail-closed on prose, unknown values and extra authority fields', () => {
  assert.deepEqual(parseDiagnosis('{"support":"SUPPORTED","externalVerificationRequired":true,"concern":"Источник не проверен"}'), {
    support: 'SUPPORTED', externalVerificationRequired: true, concern: 'Источник не проверен',
  });
  assert.equal(parseDiagnosis('It is supported.'), null);
  assert.equal(parseDiagnosis('{"support":"PASS","externalVerificationRequired":true,"concern":"x"}'), null);
  assert.equal(parseDiagnosis('{"support":"SUPPORTED","externalVerificationRequired":true,"concern":"x","goldLabel":"PASS"}'), null);
  assert.equal(parseDiagnosis('{"support":"SUPPORTED","externalVerificationRequired":false,"concern":"x"}'), null);
  assert.equal(parseDiagnosis('[]'), null);
  assert.equal(parseDiagnosis('x'.repeat(2001)), null);
});

test('provider request sends key only in auth header and rejects wrong model response', async () => {
  const candidate = buildCandidate(pair, draft);
  let calls = 0;
  const fetchImpl = async (url, options) => {
    calls++;
    assert.equal(url, 'https://openrouter.ai/api/v1/chat/completions');
    assert.equal(options.headers.Authorization, 'Bearer private-test-key');
    assert.equal(JSON.parse(options.body).model, MODEL);
    return { ok: true, status: 200, json: async () => ({ model: MODEL, id: 'gen-1', choices: [{ message: { content: '{"support":"PARTIAL","externalVerificationRequired":true,"concern":"Контекст ограничен"}' } }], usage: { prompt_tokens: 20, completion_tokens: 10 } }) };
  };
  const result = await requestDiagnosis(candidate, { apiKey: 'private-test-key', fetchImpl });
  assert.equal(calls, 1);
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.responseId, 'gen-1');
  assert.ok(!JSON.stringify(result).includes('private-test-key'));
  const wrong = await requestDiagnosis(candidate, { apiKey: 'private-test-key', fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ model: 'paid/model', choices: [{ message: { content: '{}' } }] }) }) });
  assert.equal(wrong.status, 'API_ERROR');
  const invalid = await requestDiagnosis(candidate, { apiKey: 'private-test-key', fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ model: MODEL, id: 'gen-2', choices: [{ message: { content: 'not json' } }] }) }) });
  assert.equal(invalid.status, 'INVALID_RESPONSE');
  const transport = await requestDiagnosis(candidate, { apiKey: 'private-test-key', fetchImpl: async () => { throw new Error('private-test-key'); } });
  assert.equal(transport.status, 'API_ERROR');
  assert.ok(!JSON.stringify(transport).includes('private-test-key'));
  const limited = await requestDiagnosis(candidate, { apiKey: 'private-test-key', fetchImpl: async () => ({ ok: false, status: 429 }) });
  assert.equal(limited.httpStatus, 429);
});

test('pilot limits requests, keeps official verdict unchanged and does not retry errors', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return { ok: false, status: 429, json: async () => ({ error: { code: 429 } }) }; };
  const cases = [buildCandidate(pair, draft), { ...buildCandidate(pair, draft), caseId: 'vcase-2', episodeId: 'ep-2' }];
  const snapshots = [];
  await assert.rejects(() => runPilot(cases, { apiKey: 'private-test-key', fetchImpl, maxCases: 1 }), /consent/);
  const report = await runPilot(cases, { apiKey: 'private-test-key', fetchImpl, maxCases: 1, consentTraining: true, onProgress: (x) => snapshots.push(x) });
  assert.equal(calls, 1);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].status, 'API_ERROR');
  assert.equal(report.runStatus, 'PARTIAL_RATE_LIMITED');
  assert.equal(report.officialS2006Verdict, 'NEEDS_INPUT');
  assert.equal(report.independentLabels, 0);
  assert.equal(snapshots.length, 1);
  assert.ok(!JSON.stringify(report).includes('private-test-key'));
  await assert.rejects(() => runPilot(cases, { apiKey: 'private-test-key', fetchImpl, maxCases: 22, consentTraining: true }), /limit/);
  await assert.rejects(() => runPilot([cases[0], cases[0]], { apiKey: 'private-test-key', fetchImpl, consentTraining: true }), /duplicate case/);
  await assert.rejects(() => runPilot(cases, { fetchImpl, consentTraining: true }), /KEY missing/);
});

test('loader checks archive bytes and handles both source shapes without exposing text', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'veritas-model-pilot-'));
  try {
    const archivePaths = {};
    const sourceArchives = {};
    for (const alias of ['v05', 'ah6', 'xuo']) {
      archivePaths[alias] = path.join(temp, `${alias}.zip`);
      writeFileSync(archivePaths[alias], alias);
      sourceArchives[alias] = createHash('sha256').update(readFileSync(archivePaths[alias])).digest('hex');
    }
    const pairs = Array.from({ length: 21 }, (_, index) => ({
      archive: ['v05', 'ah6', 'xuo'][index % 3],
      candidateId: `c-${index}`,
      episodeId: `ep-${index}`,
      semanticTemplate: 'definition',
      qualityFlag: null,
    }));
    const poolPath = path.join(temp, 'pool.json');
    writeFileSync(poolPath, JSON.stringify({ ticket: 'S2-006M', pairs, sourceArchives }));
    const records = Object.fromEntries(pairs.map((item) => [item.candidateId, {
      candidateId: item.candidateId,
      source: { episodeId: item.episodeId, speaker: 'Гость' },
      semanticTemplate: item.semanticTemplate, status: 'ACCEPT',
      claim: { statement: 'Это X.' }, evidenceSpans: [{ kind: 'supporting', quote: 'Это X.' }],
    }]));
    const readEntry = (archive, entry) => {
      const alias = path.basename(archive, '.zip');
      if (alias === 'v05') {
        const id = path.basename(entry, '.json');
        const i = Number(id.split('-')[1]);
        return JSON.stringify({ ...draft, caseId: id, videoId: `ep-${i}`, semanticTemplate: 'definition' });
      }
      return pairs.filter((item) => item.archive === alias).map((item) => JSON.stringify(records[item.candidateId])).join('\n');
    };
    const cases = loadPilotCases(poolPath, archivePaths, readEntry);
    assert.equal(cases.length, 21);
    assert.equal(cases[1].caseId, 'c-1');
    writeFileSync(archivePaths.ah6, 'tampered');
    assert.throws(() => loadPilotCases(poolPath, archivePaths, readEntry), /digest mismatch/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('CLI refuses a report inside the Git tree before reading key or calling provider', () => {
  const script = path.resolve('scripts/s2-006m-pilot.mjs');
  const output = path.resolve('results/s2-006/unsafe-provider-output.json');
  const child = spawnSync(process.execPath, [script, '--allow-training', '--output', output], {
    cwd: path.resolve('.'), encoding: 'utf8', env: { ...process.env, OPENROUTER_API_KEY: 'private-test-key' },
  });
  assert.equal(child.status, 1);
  assert.match(child.stderr, /outside Veritas Git tree/);
  assert.ok(!child.stderr.includes('private-test-key'));
});
