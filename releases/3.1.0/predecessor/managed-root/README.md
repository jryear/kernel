# `_kernel`

A small shared kit for frontier-model software development. It deliberately separates open-ended discovery from frozen, mechanically verifiable execution.

## Contents

- `verify.py` — canonical mechanical completion gate.
- `task.template.toml` — frozen outcome-contract template.
- `review.template.json` — optional independent contract-review metadata.
- `FRONTIER.md` — human operating model for when to discover, contract, search, or audit.
- `AGENTS.template.md` — intentionally small repo-local instruction template.
- `adopt.py` — adds the minimal task/review/AGENTS scaffolding to a repository without creating an orchestration layer.
- `selftest.py` — executable verifier smoke/regression suite.

## First adoption

From `~/code/_kernel`:

```bash
python adopt.py ~/code/saturn --project saturn
```

This creates missing project-local contract/review scaffolding but does not overwrite existing files unless `--force` is supplied.

Recommended repository shape:

```text
repo/
  AGENTS.md
  tasks/
    task.template.toml
  .claims/          # generated claim log; usually gitignored
```

The verifier intentionally stays at `~/code/_kernel/verify.py`, outside implementation repositories. Run final verification from this shared trust anchor; its version and SHA-256 are recorded in every claim log. Implementation agents should not have write access to `_kernel` during contracted work.

## Contract lifecycle

1. Discover the product/architecture until the intended outcome is concrete.
2. Create acceptance/adversarial evidence and a task TOML.
3. Commit the contract + evidence to the trusted base.
4. Confirm the baseline:

   ```bash
   python ~/code/_kernel/verify.py tasks/TASK.toml --repo . --base main --baseline
   ```

5. Branch/delegate implementation.
6. Run normal verification on the candidate.

`base` is intentionally **not** stored in the TOML. Trust selection comes from `--base` (or `VERIFY_BASE`) so a candidate-controlled task file cannot influence which revision is treated as authoritative.
