# Kernel 3.2.0 tranche 1 checkpoint

Owner: sol-1. Authority: Zack, 2026-11-03. Plan instruction_version: 2.
Independent reviewer: the separate Opus session; this document does not attest its
review. Only self-check, cleanup and sandbox-spike were undertaken. Sandbox,
flake, mutants, red-team, default-on and release were not started.

All three branches start at main `d5534ae3b23a2affe01dc99ded5c8783f094c6eb`.
They are independent, not stacked or integrated. No merge or push to main.
The installed 3.1.0 was the external judge for both implementation contracts.

## self-check

- Branch: `kernel/self-check`
- Head SHA: `2da4b773cfb0bf4606d45082e954964671aa0767`
- FROZEN_BASE: `b17e544c823817d886dbafc90c38577049135bdc`
- Contract: `tasks/self-check.toml`; evidence: `tests/self_check.py` plus the
  unchanged `selftest.py` fixture helper, both declared in the frozen chain.
- Baseline log: `/private/tmp/kernel-tranche1-self-check-baseline-v2.jsonl`
- Claim log: `/private/tmp/kernel-tranche1-self-check-claim.jsonl`

Baseline output (exit 0):

```text
BASELINE_READY  self-check  assurance=schema2-evidence-validity
  [accep] base:fail  release integrity refusal
```

The exact baseline failed IDs are ALTERED_MANIFEST, ALTERED_REPORT,
ALTERED_RUNTIME, ALTERED_VERIFIER and MISSING_DIGEST, with harness_error=false.
All five pass on the candidate: exit 3, a release-integrity diagnostic, and no
verdict or baseline-ready output. The intact copied package first establishes a
working fixture. Expected manifest digest is supplied via caller argument
`--release-sha256` or `VERIFY_RELEASE_SHA256`; there is no local-manifest trust
fallback. The digest authenticates the manifest, whose entries authenticate the
release file bytes before runtime/report imports.

Claim output (exit 0):

```text
SUPPORTED  self-check  assurance=schema2-evidence-validity
  [accep] base:fail  release integrity refusal
  [accep] candidate:pass  release integrity refusal
```

Desk prove: exit 0, `PASS python3 tests/self_check.py (467ms)`, `GREEN at 2da4b77`,
dirty=false. Proof file in common Git metadata:
`desk/proof/self-check/2026-11-03T224428563Z-2da4b773cfb0.toml`.
Branch pushed to origin. All six existing self-tests also passed, using a locally
computed development digest of the reviewed package. That is regression evidence,
not authentication of an untrusted candidate and not evidence for the new item.

The first freeze attempt `6598ef17bab5df0ca6c3b8d9f96faf3b1ec49b10` produced
BASELINE_NOT_READY due to a temporary-fixture cwd setup error. Its log is retained
at `/private/tmp/kernel-tranche1-self-check-baseline.jsonl`. No implementation
preceded the corrected contract-only refreeze. That failed attempt is not RED.

Limits: a replaced verifier can remove its own guard. The caller must externally
authenticate the entrypoint and hold the expected release digest outside candidate
control. This is startup integrity, not malicious-code sandboxing or a release.

## cleanup

- Branch: `kernel/cleanup`
- Head SHA: `9de19fcae4e84702dfeec07a3a0299042de8c333`
- FROZEN_BASE: `06df2ef314d67da5d5878d749b75f1c4d77e8af8`
- Contract: `tasks/cleanup.toml`; evidence: `tests/cleanup.py`.
- Baseline log: `/private/tmp/kernel-tranche1-cleanup-baseline.jsonl`
- Claim log: `/private/tmp/kernel-tranche1-cleanup-claim.jsonl`

Baseline output (exit 0):

```text
BASELINE_READY  cleanup  assurance=schema2-evidence-validity
  [accep] base:fail  process cleanup evidence
```

The exact failed IDs are ESCAPE_UNVERIFIABLE, GROUP_KILLED,
KILL_FAILURE_UNVERIFIABLE and TIMEOUT_UNVERIFIABLE, with harness_error=false.
MISSING_UNVERIFIABLE already passes on 3.1.0 and is deliberately not declared RED.
The evidence runs actual nested schema2 CLI verifications against committed
fixture repositories, checks child liveness/receipt identities and final verdicts,
and confines kill-failure injection to the nested candidate's OS killpg boundary.

Claim output (exit 0):

```text
SUPPORTED  cleanup  assurance=schema2-evidence-validity
  [accep] base:fail  process cleanup evidence
  [accep] candidate:pass  process cleanup evidence
```

All five IDs pass on candidate. In-group child is dead before supported; an
escaped setsid child is named by PID, group and start identity in cleanup.survivors
and makes the nested verdict unverifiable. Timeout, kill failure and missing
receipt also produce unverifiable, never finite assertion RED or supported.
Checks use separate POSIX sessions/groups in both schemas; receipts include
observations, errors, timeout and cleanup completeness. Incomplete evidence takes
precedence over certification/contradiction. Escaped processes get best-effort
remediation but their observed escape still invalidates evidence.

Desk prove: exit 0, `PASS python3 tests/cleanup.py (8758ms)`, `GREEN at 9de19fc`,
dirty=false. Common Git proof:
`desk/proof/cleanup/2026-11-03T224804626Z-9de19fcae4e8.toml`.
Branch pushed to origin. All six existing self-tests passed on this change too.

Limits: ps sampling plus an inherited random marker observes descendants; a
hostile process can erase attribution and escape between observations. This does
not prove exhaustive containment. Legacy services, as distinct from individual
checks, retain their lifecycle limitation. Tests are macOS/POSIX evidence, not
Linux acceptance. Protected-path hashing/sandbox implementation is out of scope.

## sandbox-spike

- Branch: `kernel/sandbox-spike`
- Implementation head SHA: `91e3495d2f8051aae2abfc4419e1825d318aca45`.
- The checkpoint is a documentation-only descendant of that implementation.
  Resolve the delivered branch/checkpoint HEAD with `git rev-parse HEAD`; a file
  cannot embed the SHA of the commit containing itself. The final clean-HEAD desk
  proof is kept in common Git metadata and the delivery message names that SHA.
- FROZEN_BASE: not applicable; research item, not a kernel implementation claim.
- Judge baseline output, judge claim verdict and judge log: not applicable.
  No installed-judge SUPPORTED verdict is asserted for this research.
- Acceptance: `python3 spike/sandbox_probe.py`. Exit 0 means every requested
  payload completed and observations were recorded, regardless of whether its
  operations succeeded or were denied. Setup/incomplete payloads cannot return
  completed success; the script does not decide a security pass.
- Dependency installed locally under spike: exact
  `@anthropic-ai/sandbox-runtime@0.0.81`, locked transitive dependencies, no global
  installation. `node_modules` and generated rerun results are ignored.
- Runtime: macOS, Node v24.22.0, Python 3.15.0.

Desk prove at implementation head: exit 0,
`PASS python3 spike/sandbox_probe.py (27597ms)`, `GREEN at 91e3495`,
dirty=false at invocation. The checkpoint/finding wording is documentation added
after that source proof; final checkpoint HEAD is re-proved while clean before
push. The exact final SHA and proof are available from desk status and delivery.
An earlier clean implementation proof also returned GREEN at d4079a0 (27565ms).

Evidence: `spike/evidence/observations.json`, `spike/evidence/cli-collector.log`;
architecture and exact boundaries: `spike/FINDINGS.md`. Current local rerun
results: `spike/results/results.json`, `library.json`, and CLI collector files.
Recorded package/probe hashes match the corresponding source bytes; observations
are not inferred from a process exit alone.

Both CLI and embedded paths separately exercised prestarted collection, a denied
canary, 150 denied writes, delayed denials after leader exit, temporary-directory
writes, SSH/.env open denial and loopback-only application traffic. Protected
fixture hashes stayed unchanged. The committed library sample has 150 EPERM
writes but only 148 matching emitted denial events. Its subscription received
221 total events while the store retained just 100. The synthetic store-only
150-event exercise independently demonstrates the 100-event tail and preattached
subscription. CLI's first canary returned EPERM without a matching log event.
Neither collector supplies an acknowledged ready protocol.

Recommendation: embedded trusted supervisor, opt-in log monitor, subscription
before execution, unique invocation IDs, and a bounded post-exit drain. CLI is a
usable confinement wrapper but initializes without its own log monitor. Neither
path provides a complete authoritative log ledger. Hash protected paths before
and after each check for tamper evidence; logs explain attempted operations and
never establish intent. Do not install product srt inside a candidate write root.
This recommendation was not built.

Not proved: external egress refusal (only loopback was exercised, honoring the
no-network constraint), complete log delivery or attribution, a guaranteed final
event boundary, hostile descendant containment, Linux behavior or production
readiness. Non-allowlisted loopback proxy request got HTTP 403 without risking an
external connection. Missing evidence has not been promoted to a verdict.

## Desk loop findings and boundary incident

Claims, heartbeats and prove ran from this worktree with `--root .`, agent sol-1,
plan v2. No heartbeat returned 3. No planner files were edited. The loop worked;
these are friction/findings, not changes to desk:

1. Claim records the intended branch but neither creates nor switches it. I
   explicitly switched from main for each independent item. All lease worktree
   paths refer to this same checkout; rerunning an earlier item's proof requires
   first switching to its branch (or an explicit correct worktree).
2. Prove records SHA, cleanliness **before** acceptance, result code, tail and
   output hash. It does not freeze a schema2 contract, verify assertion receipts,
   bind an instruction version in the proof or check post-command cleanliness.
   I separately inspected cleanliness and retained the external judge JSONL.
3. State is under shared Git metadata
   `/Users/jryear/code/_kernel/.git/desk/`, written by the required desk commands,
   not under the planner-owned `.desk/`. Required Git branch/snapshot operations
   likewise use the repository's common metadata; no installed source checkout
   or installation was performed.
4. After these items, desk may suggest flake as its next open item. That does not
   extend this tranche's scope; work stops at this checkpoint.
5. **Read-only boundary incident:** the initial Python 3.15 judge invocations
   generated `~/code/_kernel/__pycache__/kernel_runtime.cpython-315.pyc` (31983
   bytes) and `kernel_report.cpython-315.pyc` (6540 bytes), both timestamped
   2026-11-03 14:43:27 Pacific. This violates the instruction to write nothing
   there. They were not deleted or modified again. Further judge invocations
   must set `PYTHONDONTWRITEBYTECODE=1` or use `python3 -B`. Installed source and
   main checkout remain unchanged; this is not a claim of zero filesystem writes.

Read-only final source hashes of the installed judge:

```text
0f638fc9b7a7682ab814c7923557ecbb0871f35140f1aa6838efde17855d4ca5  verify.py
d185f76b12c30a0758fee453c8806508919fa0df2a457c8fb55fd124b7d1ac93  kernel_runtime.py
6c8c21d2f8bbcd81a5a6b0f2abb69166dc7603d7bf5df76e84d803fc5997bd0d  kernel_report.py
```

## Review boundary

The independent branches intentionally overlap MANIFEST.sha256, README/FRONTIER
and some verifier changes. They have **not** been combined or validated together.
The reviewer/Zack owns integration and landing. This checkpoint provides narrow
contract support and research evidence, not independent-review approval or
production release acceptance. No future-tranche work or release was started.

## Integration — integrate-1, plan v3

This section supersedes the earlier "not combined" status for self-check and
cleanup. It does not change the historical tranche-1 evidence or merge the spike.

- Branch: `kernel/integrate-1`, from main
  `a29e8e5fdcc5db10665acfb98ffc757854819db2`.
- Combined implementation head SHA: `e5c76a5c8cc61fb8f10c9082380a961fbd3101ff`.
  The checkpoint is a documentation-only child; the final delivered HEAD is bound
  by the external receipt's `sha` and the final desk proof. A document cannot
  contain the SHA of its own commit.
- Merged `kernel/self-check` and `kernel/cleanup`; their frozen tasks/evidence are
  unchanged. No main merge/push, sandbox, flake, mutants or BidZizi work.
- All three tranche-1 leases released; integrate-1 claimed by sol-1 under v3.
- Conflict resolution — README.md: retained both startup digest requirements and
  observed process-cleanup guarantees/limits.
- Conflict resolution — FRONTIER.md: retained both changes' substance, including
  external trust and hostile-descendant limitations.
- Conflict resolution — MANIFEST.sha256: regenerated every digest from final
  combined file bytes using the union of the two release file lists; no digest
  lines were hand-merged. Includes kernel_process.py and the combined verify.py.
- verify.py auto-merged; both the startup integrity guard and process-group
  execution/verdict changes are present.

External receipt: `/Users/jryear/.local/state/kernel/integrate-1-receipt.json`.
Fields: sha, manifest_digest, time (UTC), method. Manifest digest:
`de2058e5a0bef8bb24d48502373ec514190a826589c7db29a6c8430c62b2d22c`.
The integration owner computed it after regeneration and recorded it outside the
repo. Check invocations load VERIFY_RELEASE_SHA256 **only from that external
receipt**, not from files in the checked tree. Final delivery updates the receipt
SHA to the documentation commit; the release file bytes and digest stay unchanged.
Hashes establish lasting integrity only, not absence of attempted/undone writes
or proof of blocked reads. All judge invocations use `python3 -B`, with
PYTHONDONTWRITEBYTECODE=1 also inherited by subprocesses. No further judge cache
writes are intended or required.

Prescribed installed-3.1.0 judge outputs on the combined implementation head:

```text
CONTRADICTED  self-check  assurance=schema2-evidence-validity
  [accep] base:fail  release integrity refusal
  [accep] candidate:pass  release integrity refusal
  - protected evidence/path changed: tests/cleanup.py
  - out-of-scope changes: .desk/plan.toml, kernel_process.py, kernel_report.py, kernel_runtime.py, tasks/cleanup.toml
```

- Base: `b17e544c823817d886dbafc90c38577049135bdc`.
- Log: `/Users/jryear/.local/state/kernel/integrate-1-self-check.jsonl`.
- Exit 1. Candidate failed_assertions=[], harness_error=false; baseline has the
  exact five intended failed IDs. All checks ran on the combined tree.

```text
CONTRADICTED  cleanup  assurance=schema2-evidence-validity
  [accep] base:fail  process cleanup evidence
  [accep] candidate:pass  process cleanup evidence
  - protected evidence/path changed: tests/self_check.py
  - out-of-scope changes: .desk/plan.toml, tasks/self-check.toml
```

- Base: `06df2ef314d67da5d5878d749b75f1c4d77e8af8`.
- Log: `/Users/jryear/.local/state/kernel/integrate-1-cleanup.jsonl`.
- Exit 1. Candidate failed_assertions=[], harness_error=false; baseline has the
  exact four intended failed IDs. No missing execution evidence was promoted.

The original frozen scopes cannot support this combined diff: both protect
`tests/*`, so each rejects the other suite's addition; the self-check scope also
excludes cleanup implementation modules. Both exclude the v3 plan change and
this subsequently added checkpoint. Original branch SUPPORTED verdicts have not
been substituted for these results. The requested pair of integrated SUPPORTED
verdicts is **not achieved**. No contract or judge was weakened to obtain one.
A decision was requested: authorize versioned integration contracts with a new
trusted freeze and fresh RED-to-GREEN evidence, or retain exact bases and accept
that their scopes contradict the integration. No new contracts were created
without that decision.

`python3 -B selftest.py`: all six existing regression tests passed with the
externally supplied digest.

Desk v3 prove on e5c76a5: all three acceptance commands exited 0 (828 ms, 8202 ms,
6246 ms respectively); dirty_before=false, dirty_after=false, head_after unchanged,
instruction_version=3. Result captured at
`/Users/jryear/.local/state/kernel/integrate-1-desk-initial.json`.
The updated desk correctly records before/after cleanliness and HEAD plus plan
version. Its GREEN result does not override the external judge's scope verdicts.

Final clean checkpoint HEAD is rechecked before push. Its exact final judge
outputs/logs are retained at
`/Users/jryear/.local/state/kernel/integrate-1-self-check-final.jsonl` and
`/Users/jryear/.local/state/kernel/integrate-1-cleanup-final.jsonl`; final desk
result at `/Users/jryear/.local/state/kernel/integrate-1-desk-final.json`.
These final logs also include the checkpoint as an out-of-scope addition.

Previous ignored spike installation/results were preserved outside this checkout
at `/Users/jryear/.local/state/kernel/tranche-1-spike-local-1793748479` so the
integration tree stays clean without deleting or bringing research into scope.


## Integration 1b — fresh contract, plan v4

Supersedes the integration acceptance blocker above without changing its history:
the original branches' SUPPORTED verdicts and original contracts' combined-tree
CONTRADICTED verdicts remain on record. Branch: `kernel/integrate-1b`, based on
`origin/main` `4198029cdc9f9c0aa9355638456d454f1a58d800`.

- FROZEN_BASE: `69028ac26ba6f6a1ccf368549abdcd0f2d747051`; exactly three
  additions: `tasks/integrate-1.toml`, `tests/self_check.py`, `tests/cleanup.py`.
  The suites are byte-identical to b17e544 and 06df2ef respectively. Existing
  `selftest.py`, used as a fixture helper, is also byte-identical. No adapter.
- The schema-2 contract contains only the two unchanged acceptance checks, with
  all original assertion IDs. Nine IDs are intended RED; missing-receipt handling
  already passes on base. Scope is the implementation union plus the checkpoint;
  tests/* and tasks/* are protected. No old frozen contracts were edited/imported.
- Baseline (exit 0): `BASELINE_READY  integrate-1-v1  assurance=schema2-evidence-validity`;
  both acceptance checks base:fail, exactly nine intended failed IDs, no harness
  errors. Log: `/Users/jryear/.local/state/kernel/integrate-1b-baseline.jsonl`.
- Source claim (exit 0) on `297b8df95a5898884d9949576de042de172f822d`:
  `SUPPORTED  integrate-1-v1  assurance=schema2-evidence-validity`;
  both checks base:fail → candidate:pass. Log:
  `/Users/jryear/.local/state/kernel/integrate-1b-claim-source.jsonl`.
- Imported only the seven implementation/release files from e5c76a5; retained
  plan v4, the new contract and frozen tests. Regenerated every manifest digest
  from the final file contents. External receipt:
  `/Users/jryear/.local/state/kernel/integrate-1b-receipt.json`, recording sha,
  frozen_base, manifest_digest, UTC time and method. Expected digest is loaded
  from this external receipt for candidate/judge/desk calls:
  `de2058e5a0bef8bb24d48502373ec514190a826589c7db29a6c8430c62b2d22c`.
- Regression placement is intentional, per the reviewer's correction:
  selftest.py emits no schema-2 terminal receipt, so it is not a judge check.
  `python3 -B selftest.py` passed all six tests separately (log:
  `/Users/jryear/.local/state/kernel/integrate-1b-selftest.txt`); desk's integrate-1
  acceptance runs and records it as well, and release reruns it.
- Desk v4 source proof: GREEN; all three plan commands exit 0, clean before and
  after, HEAD unchanged. Record:
  `/Users/jryear/.local/state/kernel/integrate-1b-desk-source.json`.

This checkpoint is a documentation-only child of the source claim above. Its own
SHA is recorded in the external receipt and final judge/desk records rather than
embedded in its own commit. Final verification artifacts:
`/Users/jryear/.local/state/kernel/integrate-1b-claim-final.jsonl` and
`/Users/jryear/.local/state/kernel/integrate-1b-desk-final.json`.
Judge calls use python3 -B with PYTHONDONTWRITEBYTECODE=1 inherited. Judge
package/cache/directory inventories are retained at
`/Users/jryear/.local/state/kernel/integrate-1b-judge-before.json` and
`/Users/jryear/.local/state/kernel/integrate-1b-judge-after.json` (shared .git
metadata for required branch/desk/snapshot operations is explicitly excluded).
Hashes establish observed lasting integrity only. No sandbox, flake, mutants,
BidZizi work, main merge/push, or release was undertaken.


## Sandbox v5 — DEV incomplete

Authority: Zack 2026-11-09 and Claude independent prefreeze approval. Sol-6
claimed the sandbox lease after sol-5 expired, under binding plan v7. Terra and
Luna performed bounded read-only verification of the freeze bytes, runtime
recipe, inventories and guards. No Desk prove was performed.

### Immutable source and baseline

FROZEN_BASE: `222f3385543f6da6b4bbcd932cc4a260193021c1`. Its parent is exactly
`f14a12270641723c81dba13ebb2df9f484d151d3`. The freeze commits only the 12
approved files, with all SHA-256 values and modes verified before committing.
External freeze receipt: `/Users/jryear/.local/state/kernel/sol6-setup/freeze-receipt.json`.
The reviewed implementation was ported from `d472fb4fb53968e123275294a826ee2843156145`.
The exact clean committed qualification HEAD is `a1532a527f705df87eefdd7343a96250d05d1609`. This delivery
checkpoint is documentation added after qualification; runtime/package bytes,
manifest and all frozen inputs remain identical to that qualified HEAD.

Installed 3.1.0 baseline: **BASELINE_READY**, four genuine behavioral REDs.
Each named boundary assertion independently observed a forbidden protected write
succeed, lasting protected change, a complete nested supported result and clean
execution evidence. No schema/setup error counted as RED. Evidence:
`/Users/jryear/.local/state/kernel/sol6-setup/baseline/judge.jsonl` and
`/Users/jryear/.local/state/kernel/sol6-setup/baseline/behavioral-red-receipt.json`. Before/after judge inventories
are unchanged. Tests/tasks and all other protected inputs remain immutable.
Some approved frozen descriptions retain their prefreeze draft label; the bytes
were intentionally preserved rather than edited after freeze.

### Full direct sweep on the committed candidate

| Group | Cases | Variants | Completed | Mismatch | Unavailable |
|---|---:|---:|---:|---:|---:|
| effect-classifier | 137 | 247 | 247 | 0 | 0 |
| isolation | 7 | 14 | 14 | 0 | 0 |
| policy-dependency | 57 | 114 | 114 | 0 | 0 |
| protocol | 13 | 26 | 26 | 0 | 0 |
| Total | 214 | 401 | 401 | 0 | 0 |

Exact coverage, unique job IDs, clean source/fixture identity, unchanged installed
judge and suspension/lease/caffeinate cleanup all validated. No unavailable case
was credited as a pass. Raw case roots, command streams and teardown-safe nested
archives remain under `/Users/jryear/.local/state/kernel/sweep/sol6-v5-frozen-20261109`. Summary: `summary.json`; per-variant command
hashes and artifact roots: `per-variant-index.json`; guard: `guard-validation.json`.

### Regressions and installed-judge claim

The manifest was regenerated from the final package contents before qualification.
Caller-held external receipt: `/Users/jryear/.local/state/kernel/sol6-setup/candidate-release.json`.
Manifest SHA-256: `2a488340de2054009bf25d5534bef3aded29ff4176cfbbbe9c0ae0c0907e80cd`.
Manifest verification, all six self-tests, self_check and cleanup passed with
that digest supplied. Logs and commands: `/Users/jryear/.local/state/kernel/sol6-setup/regressions`.

Single four-check installed-judge result: **CONTRADICTED**, DEV-ONLY.
Effect-classifier failed: `LATE_RELEVANT_DENIAL` / `enabled` expected
`unverifiable` but returned `supported`. Its other 246 variants completed;
protocol 26/26, policy-dependency 114/114 and isolation 14/14 passed. The
effect-classifier check exited 1 with `harness_error=false`. This failed
observation is preserved and was not retried. Root cause is not established;
neither an implementation defect nor a frozen-fixture defect is assumed.
Exact failure receipt: `/Users/jryear/.local/state/kernel/sol6-setup/claim/failure-receipt.json`.
Raw failure: `/Users/jryear/.local/state/kernel/sol6-setup/claim/retained/LATE_RELEVANT_DENIAL-enabled-dedcc5ec5a8d4d4a9d871d254a2205fa/invocation.json`.
Exact claim: DEV-ONLY sandbox-v5: all four frozen checks and 214 cases / 401 variants pass on the committed candidate and authenticated development bundle; no production, egress or default-on qualification
Implementer model: `gpt-6.1-sol medium (+terra/luna)`.
New external log: `/Users/jryear/.local/state/kernel/sol6-setup/claim/judge.jsonl`.
Console: `/Users/jryear/.local/state/kernel/sol6-setup/claim/console-0.txt`; command/environment receipt:
`/Users/jryear/.local/state/kernel/sol6-setup/claim/command-0.json`; before/after judge inventories and guard
validation: `/Users/jryear/.local/state/kernel/sol6-setup/claim/summary.json`. No unchanged failure was retried.
The claim runs on the clean committed qualification HEAD named above.

Authenticated DEV bundle receipt: `/Users/jryear/.local/state/kernel/dev-bundle-v5-integrated-r1.receipt.json`,
SHA-256 `79c6d22e99e317efcfdda3db9f858622d45d9919538b85a447e191966489398c`. Bundle digest
`b17f5ec019f336b73816712b815667817015cfa49c90b269cdfa6a37e7e1bc40`;
912 inventoried files. Supervisor/validator bytes match the reviewed source.
Node v24.22.0 retains `UNQUALIFIED_LOCAL_EXECUTABLE` artifact provenance.
No new installation, dependency fetch, patch application or provisioning was run.

### Zack-only provisioning command and prerequisites

Patch SHA-256: `9116e04677a6a058947b7e24d2b71372d86dfd6c756f25f126f512a73ac7beb2` (`kernel-srt-0.0.81-exact-tcp-v1`).
Run from this reviewed branch only after authenticating the source and an official
Node v24.22.0 archive. The exact command below requires Zack to supply the actual
absolute archive path and independently authenticated official archive digest;
this session has neither input and does not substitute a local executable hash.
The receipt parent must already exist, be root-owned/non-writable and symlink-free
through its ancestry. The receipt path must not already exist.

```sh
sudo /Users/jryear/orca/workspaces/_kernel/kernel-sandbox-v2/sandbox_runtime/provision.sh \
  --node-archive "${KERNEL_NODE_ARCHIVE:?set absolute official node-v24.22.0-darwin-arm64.tar.gz path}" \
  --node-archive-sha256 "${KERNEL_NODE_ARCHIVE_SHA256:?set authenticated official archive SHA-256}" \
  --receipt "/Library/Application Support/KernelRuntime/receipts/sandbox-v5-bundle.json"
```

This host is macOS arm64; Intel requires the darwin-x64 archive and renewed exact
runtime qualification. `lo0` must have the `127.0.0.2` alias for the controlled
alternate-loopback listener. It was present before the freeze and full sweep.
No sudo, alias configuration or provisioning was performed by Sol-6. Authenticate
the new operator receipt digest externally before its qualifying run. DEV evidence
does not qualify Zack's new bundle; no Desk prove before that separate run.

### Known gaps and named residual risks

- `NONNETWORK_GENERATOR_COMMON_MODE`: matching generated non-network templates
  are not an independent semantic policy oracle. Separate red-team shared-generator
  mutation/effect evidence and release-owner disposition remain required.
- `ENTRYPOINT_EXTERNAL_AUTHENTICATION`: caller authentication of the entrypoint
  and its launch/import environment is a prerequisite; self-check cannot establish it.
- Swallowed denials whose events are never delivered may still be supported when
  all required observable evidence passes. Logs are diagnostic; absence proves nothing.
  The approved fixed 1ms timestamp uncertainty is unchanged and is never widened.
- Hashes establish lasting boundary changes, not absence of attempts, transient
  writes or reads. Process sampling and reviewed assertion reporters retain their limits.
- Declared TCP ports grant address-wildcard bind/inbound authority; localhost alias
  matching, allowed-service identity and relay exposure remain published limits.
- Official operator bundle, per-host/runtime qualification, off-machine egress,
  repetition/mutants/red-team, default-on, real-caller and release gates remain open.
  V4 freeze and its UNVERIFIABLE claim are preserved. No main/next push or release.

Stop for independent review after pushing `kernel/sandbox-v5` and setting in-review.
