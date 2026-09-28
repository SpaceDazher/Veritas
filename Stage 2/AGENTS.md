<!-- bb-project-folders:agents:start -->
# Section rules

User instructions take priority. Read the project AGENTS.md and parent sections first — their rules apply alongside these.

## Think before coding
- Don't assume silently: state assumptions; when unclear, ask.
- If a task has multiple interpretations, present the options and tradeoffs — don't pick silently.
- Prefer the simple path; if the request leads to overengineering, push back with a simpler proposal.

## Minimum and surgical changes
- Minimum code that solves the task: nothing speculative, no single-use abstractions, no error handling for impossible cases.
- Touch only what the task requires: don't "improve" adjacent code, comments or formatting; match the existing style.
- Remove only what your change made unused; mention other suspicious code instead of deleting it.
- Every changed line must trace back to the user request.

## Success criteria and verification
- Before writing, decide how you will verify the result: a test, a command, a scenario.
- "Fix the bug" means a reproducing check first, then the fix and a green result.
- Drive multi-step work as a "step → verify" list; a task is done when the original problem is verified, not when it "should work".
- If the change affects a running service, deploy and restart it so the result goes live, then check the fix on the running instance.

## Files and autonomy
- Keep the section root for real work (code, documents); everything temporary lives in its folder — artifacts/, notes/, tmp/ or a named subfolder.
- Chat files go to .bb/chats/<chat id>/: reports in artifacts/, notes and handoff in notes/, throwaway work in tmp/.
- Never edit thread.json or history/ — BB owns them.
- Inside the task scope decide yourself: don't ask what you can look up in the repository or docs.
<!-- bb-project-folders:agents:end -->
