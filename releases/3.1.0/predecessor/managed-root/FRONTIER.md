# Frontier Development Kernel

This kernel exists to increase agent autonomy without confusing an agent's claim with evidence.
It is not an orchestration framework.

## Operating law

**Explore freely. Contract late. Delegate broadly. Verify mechanically. Escalate consequential uncertainty.**

## Four modes

### 1. Discovery
Use when the product, architecture, or interaction model is still uncertain.

- Work interactively with one strong frontier model by default.
- Let it inspect the repository, run the product, prototype, discard, and challenge inherited assumptions.
- Bring in independent models when genuine search breadth or disagreement is valuable.
- Do not create an implementation contract merely to make uncertainty look organized.

Exit Discovery when the next outcome can be stated as observable reality rather than aesthetic or architectural aspiration.

### 2. Contracted execution
Use when the outcome is understood and mechanically distinguishable from the base state.

- Freeze the TOML and acceptance evidence on the trusted base before delegation.
- Give one frontier owner the outcome and broad implementation jurisdiction.
- The implementer chooses architecture, files, refactors, tools, and subagents unless a durable invariant says otherwise.
- `verify.py` determines whether the completion claim is supported.

A contract constrains **what must become true**, not the reasoning path used to get there.

### 3. Search
Use when several legitimate product/interface conceptions may exist.

- Create independent working hypotheses, not competing essays.
- Keep initial attempts independent to avoid anchoring.
- Experience the artifacts before synthesizing them.
- Synthesis should recover the strongest underlying conception, not splice components together.

Do not use acceptance contracts to encode taste.

### 4. Audit
Use for consequential architecture, security boundaries, migrations, or suspicious evidence.

- Prefer an independent reviewer/model.
- Ask for counterexamples, unsupported assumptions, and ways the current evidence could pass while the intended behavior is false.
- Convert valid findings into stronger evidence or a revised frozen contract before implementation resumes.

## Escalation boundary

The implementation owner should resolve reversible engineering choices autonomously.
Escalate when a decision materially changes:

- product meaning or user-visible semantics,
- security/privacy boundaries,
- durable data contracts or migrations,
- expensive-to-reverse external commitments,
- a frozen contract or its evidence.

## What belongs in AGENTS.md

Keep repository instructions small and local:

1. what this product is,
2. durable invariants,
3. how to run/inspect it,
4. where authoritative context lives,
5. how contracted completion is verified.

Do not require every agent to preload broad philosophy, historical architecture, or a large orchestration protocol.
