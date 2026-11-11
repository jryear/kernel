# Kernel: a completion gate for AI coding agents

An agent saying "done" is not proof. `verify.py` decides whether a commit actually
did what its task promised, using a contract the agent can read but cannot change.

It is a mechanical gate, not a judge of quality: it proves a change met its
contract, not that the contract was a good one.

## The problem

Coding agents grade their own homework. They report success, edit the tests that
judge them, add `.skip`, or pass checks that would have passed anyway. Trusting the
agent's report, or a CI run the agent can influence, doesn't hold up once agents
work unattended or in parallel.

## How it works

You freeze a task file (the contract) at a trusted base commit before any work
starts. It declares the goal, which files may change, which evidence is protected,
and the checks:

| Check | Must... | Proves |
| --- | --- | --- |
| **Acceptance** | fail on the base, pass on the candidate | the change did something |
| **Regression** | pass on both | nothing broke |
| **Adversarial** | pass on the candidate, failing where declared on the base | attempts to break the claim fail |

Then, for a candidate commit, the verifier:

- **reads the contract from the trusted base, never from the candidate.** The
  agent can't edit the rules it's judged by, and the base is chosen by the caller
  (`--base`), not by anything the candidate controls;
- runs base and candidate in **separate fixed snapshots**;
- **rejects meaningless failures.** A plain exit 1, a missing import, a setup
  error, a timeout or exit 99 never counts as a real "red" on the base;
- checks tracked bytes, modes, index and HEAD **before and after every check**, so
  protected evidence, the task file and the verifier must be unchanged;
- flags changes outside the declared scope and added test bypasses;
- treats the implementer's own evidence as a warning, never as proof;
- appends a receipt to a log kept **outside** the repository being judged.

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `SUPPORTED` | 0 | the evidence backs the claim |
| `CONTRADICTED` | 1 | the behaviour or the diff breaks the contract |
| `UNVERIFIABLE` | 2 | the evidence can't settle it |
| `SPEC_ERROR` | 3 | bad contract or bad invocation |

`--baseline` checks that a newly frozen contract is ready to hand out: acceptance
fails on the base, regressions pass, and the harness runs.

## What it does not do

Stated plainly, because a gate that overclaims is worse than none:

- **No sandboxing.** Checks run with the caller's permissions. A macOS sandbox
  was prototyped and deliberately dropped from the 3.2.0 plan; those branches
  remain as history.
- It doesn't prove a result means what it claims. A process can fabricate a
  valid receipt, so a human still reviews the assertions in each check.
- It doesn't attest that a review happened, make external dependencies
  reproducible, or clean up services a check starts.
- It protects only the declared execution chain. Reviewers must identify the
  real helpers, imports and configuration.

## Quick start

Python 3.11+, standard library only.

```bash
python3 adopt.py /path/to/repo --project myproject
python3 verify.py tasks/TASK.toml --repo /path/to/repo --base <frozen-sha> --baseline
python3 verify.py tasks/TASK.toml --repo /path/to/repo --base <frozen-sha> \
  --claim "observable result" --implementer-model "model/runtime" \
  --log /path/outside/the/repo/claims.jsonl
```

`examples/schema2_check.py` is a minimal runnable check to copy from.

## Status

- **3.1.0** is the current sealed release (`releases/`, `MANIFEST.sha256`,
  `selftest.py`).
- **3.2.0** (planned): the verifier refuses to run if its own files don't match an
  external digest, process cleanup after each check, and protected-path integrity.

The full technical reference is [README.md](../README.md), which is part of the
sealed release and is not edited outside a release.
