# A-MVP-05: local human review cycle

This additive service prepares a fixed small README change in an isolated Git
repository. The executor is an actual deterministic Node process in Podman, with
network disabled. It is a local wrapper cycle; it does not establish model
quality, acceptance of a paid campaign, or A-MVP-01.

## Human actions

1. Start with: node scripts/a-mvp05-runtime.mjs --init
   Then keep running: node scripts/a-mvp05-runtime.mjs --serve
2. Open the printed loopback URL. Enter the private scoped reviewer credential
   from ~/.local/state/veritas/a-mvp05/reviewer.private.token.
   It is not a provider API key. Never put it into a URL or log.
3. Read the brief and click **Создать задачу и выполнить**.
4. Inspect the README diff and three existing test results. Enter your own
   reason, then choose **Принять** or **Запросить изменения**.

The producer and reviewer have different principals. The server resolves
Daniil's scoped principal from the credential, rejects another task or identity,
and binds the decision to the displayed artifact digest and task revision.
The credential lasts 24 hours and authorizes only this fixed task. Task guards
permit one final review transition, and repeated decisions are refused.

## Evidence and limits

Canonical transitions, result digests, fences and audit records use the existing
Agent Board commands, guards and PostgreSQL store. PostgreSQL data, immutable
tickets, artifact manifests and receipts persist under
~/.local/state/veritas/a-mvp05, outside the repository and /tmp.
A fresh process replays transition payloads, document bindings and history
against the canonical task. The private database password travels through a
0600 env file; provider credentials are unnecessary.

--preflight creates a separate test fixture. Its reviewer is
prn-a05-test-reviewer; it cannot serve as evidence of Daniil's human action.
After finishing that technical fixture, inspect its saved evidence instead of
restarting it as a new trial. --inspect reads the live task without deciding it.

Provider-fee spend is zero because the pinned deterministic runner makes no
provider calls and runs without network. Local electricity and opportunity cost
are NOT_MEASURED. The USD 0.01 task ceiling is a board resource grant, not a
measurement of local costs.

An interrupted or unknown execution is not retried automatically. A-MVP-05
remains NOT_RUN until the human cycle is observed and its receipt and journal
are independently inspected. Historical campaign signatures and dispositions
are not updated by this service.
