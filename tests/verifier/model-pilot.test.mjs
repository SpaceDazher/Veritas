import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MODEL,
  buildCandidate,
  buildRequest,
  parseDiagnosis,
  requestDiagnosis,
  runPilot,
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
});

test('pilot limits requests, keeps official verdict unchanged and does not retry errors', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return { ok: false, status: 429, json: async () => ({ error: { code: 429 } }) }; };
  const cases = [buildCandidate(pair, draft), { ...buildCandidate(pair, draft), caseId: 'vcase-2', episodeId: 'ep-2' }];
  const snapshots = [];
  const report = await runPilot(cases, { apiKey: 'private-test-key', fetchImpl, maxCases: 1, onProgress: (x) => snapshots.push(x) });
  assert.equal(calls, 1);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].status, 'API_ERROR');
  assert.equal(report.officialS2006Verdict, 'NEEDS_INPUT');
  assert.equal(report.independentLabels, 0);
  assert.equal(snapshots.length, 1);
  assert.ok(!JSON.stringify(report).includes('private-test-key'));
});
