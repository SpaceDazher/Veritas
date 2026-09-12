# Open decisions · S2-001

Project A is selected. The following are unresolved; no absence grants permission.

Scenario A execution-specific inputs were resolved in the bounded external pilot and
are frozen in `evidence/s2-001-pilot-binding.json`. The entries below are preserved as
the original local-workspace decision record; they still block new executions unless
a new task supplies its own scoped grants. Scenario B entries remain unresolved.

## target_revision
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.checkout, a.benchmark]
reason: Approved target commit and legal repository/tool access are not supplied.
```

## agent_access
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.real-adapters, a.benchmark]
reason: Codex/pi versions, models, authorization methods, host resources and installation availability have not been verified.
```

## repository_permissions
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.agent-write, a.checkout]
reason: Local ticket editing does not authorize future pilot writes, network access or tool execution.
```

## task_cost
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.execute, b.experiment]
reason: Approved numeric per-task amount and currency required, including local opportunity or provider costs.
```

## campaign_cost
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.benchmark, b.experiment]
reason: Approved numeric campaign ceiling and currency required.
```

## daily_cost
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.execute, b.experiment]
reason: Approved numeric daily ceiling and currency required.
```

## max_duration
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.execute, b.experiment]
reason: Approved numeric timeout required.
```

## budget_owner
```yaml
status: NEEDS_INPUT
owner: user
blocks: [budget.approve]
reason: Authenticated accountable budget owner identity not supplied; user is the input owner, not assumed payer.
```

## decision_owner
```yaml
status: NEEDS_INPUT
owner: user
blocks: [solution.approve, research.approve]
reason: Authenticated final decision owner identity not supplied.
```

## source_allowlist
```yaml
status: NEEDS_INPUT
owner: user
blocks: [b.import]
reason: Specific documents, Telegram channels and lawful permissions not supplied.
```

## research_question
```yaml
status: NEEDS_INPUT
owner: user
blocks: [b.freeze, b.analyze]
reason: Pilot topic approved; exact geography, time interval, populations and causal estimand not supplied.
```

## freshness_windows
```yaml
status: NEEDS_INPUT
owner: user
blocks: [b.current-claims]
reason: Numeric maximum age per source category requires approval.
```

## quality_thresholds
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.select, b.accept]
reason: Baseline, quality minimum, coverage floor, non-inferiority delta and statistical decision rule require preregistration.
```

## independent_reviewer
```yaml
status: NEEDS_INPUT
owner: user
blocks: [a.independent-eval, b.independent-eval]
reason: Independent qualified reviewer identity and conflict-of-interest checks not supplied.
```
