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


## Sandbox freeze — plan v5, FREEZE ONLY

Branch `kernel/sandbox` starts at reviewed landing branch `origin/next`
`4a4ad64` (full ancestor is recorded in Git). Main remains the installed 3.1.0
judge; neither main nor next is merged into or pushed by this worker.

- **FROZEN_BASE:** `c6f519b584c9d611601a0bc998472c5743d71df2`.
  The freeze adds only tasks/sandbox.toml, tests/tamper_suite.py and the complete
  tests/sandbox_fixtures helper/catalogue/documentation chain. No product source,
  installed dependency, existing test/contract, .desk file or decision was edited.
- **Contract:** schema 2 `sandbox-v1`, acceptance `sandbox evidence matrix`,
  assertion `SANDBOX_MATRIX_BOUNDARY`, intended baseline failure of that ID.
  It is a conjunction over the full case registry and logging variants, not a
  false claim that every individual case is newly RED. Tests/tasks/decision/spike
  and planner files remain protected. Explicit implementation scope allows the
  Python verifier/runtime/cleanup, new kernel_sandbox module/package, trusted
  Node supervisor/bundle-source staging, runtime docs, manifest and checkpoint.
  Source-edit scope never grants runtime writes.
- **Baseline:** exit 0,
  `BASELINE_READY  sandbox-v1  assurance=schema2-evidence-validity`,
  `[accep] base:fail  sandbox evidence matrix`.
  Log: `/Users/jryear/.local/state/kernel/sandbox-freeze-baseline.jsonl`.
  The nested legacy subject executed a real synthetic protected write, returned
  SUPPORTED with complete assertion/cleanup evidence, and independent inventories
  measured the lasting byte change. That is the decisive counterexample. No
  unknown CLI, missing dependency/API, missing receipt or setup failure is RED.
  Later cases short-circuit after that witness and are explicitly unqualified,
  not individually credited as RED or GREEN. An enforcing future subject cannot
  pass on the gate alone: every matrix row/variant must then pass; unavailable
  evidence propagates without an assertion result.
- Final documentation-only HEAD is re-baselined against the same immutable freeze
  with the literal FROZEN_BASE argument. Its log is
  `/Users/jryear/.local/state/kernel/sandbox-freeze-baseline-final.jsonl`.
  No claim-mode SUPPORTED, sandbox implementation acceptance, or security
  qualification is asserted by this freeze. Desk prove is not used to disguise
  the deliberately RED acceptance; workspace is in-review for freeze approval.
- Syntax/catalogue validation and disposable unsandboxed positive controls were
  exercised before freeze. File operations, synthetic reads, IPv4/IPv6 nonce ACK,
  fixed-target HTTP/CONNECT and environment-report fixture protocols were checked.
  These validate fixture wiring only, not enforcement. Pre-freeze setup mistakes
  (hardlink-read digest and directory-vs-worktree .git control shape) were corrected
  before commit and never counted as RED. Terra authored bounded synthetic payload
  fixtures; Luna drafted the case catalogue; sol-1 reviewed/adapted the full result.

### Bundle proposal — NOT PROVISIONED

Operator/admin-owned, non-replaceable macOS prefix:
`/Library/Application Support/KernelRuntime/kernel-sandbox/0.0.81/<bundle-sha256>/`.
ACLs/ownership must exclude the candidate and implementation-agent identity from
writes to the bundle, resolved targets and ancestors; same-owner chmod alone is
insufficient. Provisioning requires separate operator authorization. This phase
installed nothing, ran no npm/npx/download, and installed nothing in the judge.

Pin embedded srt **0.0.81**, exact transitive lock bytes from spike/package-lock.json
SHA-256 `53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9`,
and qualified **Node v24.22.0** per OS/build/architecture. A later operator receipt
must pin both the Node distribution artifact and extracted executable SHA-256;
no artifact hash or qualification is invented in this freeze. Hash sorted
canonical bundle rows `{path,type,mode,sha256/target}` covering supervisor, srt,
all transitives/lock and Node. Caller-held release receipt binds bundle manifest,
Node artifact/executable and lock digests outside candidate authority; kernel
release manifest binds that receipt. Reject unsafe aliases, writable ancestry,
authentication mismatch, missing dependency or unavailable exact policy; no
unconstrained fallback or install during verification.

Concrete future operator request, receipt schema and classifier/capability seams
are part of the reviewable freeze in tests/sandbox_fixtures/README.md. They are
fixture interfaces for future code, not implementations. Pure injected classifier
cases remain distinct from actual operation probes, and source review must verify
that production uses the same classifier; JSON cannot attest semantic execution.

### Qualification gaps and claims deliberately not frozen

- All matrix probe/classifier code and helper inputs are frozen, but the **full
  matrix is not executed/qualified**: the product and authenticated bundle do not
  exist yet. This baseline proves a real counterexample, not the future backend.
- **External egress:** probe code and required evidence are frozen, but no endpoint,
  privileged isolated network or human authorization is provisioned/frozen here.
  Future operator must separately authorize and qualify an isolated private
  endpoint, nonce echo and independent journal. Receipt and caller-held receipt
  digest are required; unsandboxed reachable control plus observed EPERM/EACCES
  AND journal evidence are mandatory. Missing qualification is outer unavailable,
  never a pass borrowed from loopback. It remains an explicit acceptance gap.
- No finite fixture claims detection of swallowed invisible attempts, write/restore
  from equal endpoint hashes, semantic honesty of a valid-looking forged result,
  exhaustive hostile descendants or complete OS log delivery. Those guarantees
  cannot be frozen honestly under this decision. Dedicated bounded-limitation
  cases require supported only for identical complete observed evidence, or
  unverifiable where execution evidence is explicitly missing/ambiguous.
- Case aliases, exact ports, IPv6, immutable-bundle ownership, deterministic fault
  seams and live backend diagnostics require later platform qualification. Enabled
  collector loss/failure remains unverifiable; disabled logging is a distinct
  declared mode. No live OS loss percentage or quiet-drain completeness is assumed.

Judge calls use python3 -B with PYTHONDONTWRITEBYTECODE=1 inherited. Inventories:
`/Users/jryear/.local/state/kernel/sandbox-freeze-judge-before.json` and
`/Users/jryear/.local/state/kernel/sandbox-freeze-judge-after.json`. Required shared
.git desk/branch/snapshot metadata is explicitly excluded; package directories,
files, modes, links, bytes, caches and mtimes are compared. Old leases were
released; sandbox was claimed/heartbeated by sol-1 under v5. No implementation,
flake, mutants, BidZizi work, release, main push or next push was performed.

### Frozen matrix case list and expected nested verdicts

182 named cases, 350 declared logging variants. The exact evidence for each
row is in tests/sandbox_fixtures/matrix.json and the linked helper chain.

| Case | Expected nested result | Logging |
| --- | --- | --- |
| `DENY_JUDGE_WRITE` | unverifiable | disabled, enabled |
| `DENY_JUDGE_CREATE` | unverifiable | disabled, enabled |
| `DENY_JUDGE_UNLINK` | unverifiable | disabled, enabled |
| `DENY_JUDGE_RENAME` | unverifiable | disabled, enabled |
| `DENY_JUDGE_CHMOD` | unverifiable | disabled, enabled |
| `DENY_JUDGE_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_WRITE` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_CREATE` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_UNLINK` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_RENAME` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_CHMOD` | unverifiable | disabled, enabled |
| `DENY_CLAIM_LOG_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_WRITE` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_CREATE` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_UNLINK` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_RENAME` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_CHMOD` | unverifiable | disabled, enabled |
| `DENY_RUNTIME_MODULE_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_WRITE` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_CREATE` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_UNLINK` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_RENAME` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_CHMOD` | unverifiable | disabled, enabled |
| `DENY_MANIFEST_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_WRITE` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_CREATE` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_UNLINK` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_RENAME` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_CHMOD` | unverifiable | disabled, enabled |
| `DENY_CONTRACT_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_CHAIN_WRITE` | unverifiable | disabled, enabled |
| `DENY_CHAIN_CREATE` | unverifiable | disabled, enabled |
| `DENY_CHAIN_UNLINK` | unverifiable | disabled, enabled |
| `DENY_CHAIN_RENAME` | unverifiable | disabled, enabled |
| `DENY_CHAIN_CHMOD` | unverifiable | disabled, enabled |
| `DENY_CHAIN_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_WRITE` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_CREATE` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_UNLINK` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_RENAME` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_CHMOD` | unverifiable | disabled, enabled |
| `DENY_FIXTURE_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_WRITE` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_CREATE` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_UNLINK` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_RENAME` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_CHMOD` | unverifiable | disabled, enabled |
| `DENY_GIT_WORKTREE_METADATA_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_WRITE` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_CREATE` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_UNLINK` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_RENAME` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_CHMOD` | unverifiable | disabled, enabled |
| `DENY_GIT_COMMON_DIRECTORY_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_WRITE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_CREATE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_UNLINK` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_RENAME` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_CHMOD` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SRT_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_WRITE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_CREATE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_UNLINK` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_RENAME` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_CHMOD` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_SUPERVISOR_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_WRITE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_CREATE` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_UNLINK` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_RENAME` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_CHMOD` | unverifiable | disabled, enabled |
| `DENY_BUNDLE_NODE_REPLACE_PARENT` | unverifiable | disabled, enabled |
| `RESTORE_OR_ALIAS_WRITE_RESTORE` | unverifiable | disabled, enabled |
| `RESTORE_OR_ALIAS_DELETE_RECREATE` | unverifiable | disabled, enabled |
| `RESTORE_OR_ALIAS_SYMLINK_WRITE` | unverifiable | disabled, enabled |
| `RESTORE_OR_ALIAS_HARDLINK_WRITE` | unverifiable | disabled, enabled |
| `RESTORE_OR_ALIAS_ANCESTOR_ALIAS_WRITE` | unverifiable | disabled, enabled |
| `MEASURED_LASTING_BYTE_CHANGE` | contradicted | disabled, enabled |
| `MEASURED_LASTING_CHANGE_WITH_LOGGING` | contradicted | disabled, enabled |
| `MEASURED_ADDITION` | contradicted | disabled, enabled |
| `MEASURED_REMOVAL` | contradicted | disabled, enabled |
| `MEASURED_REPLACEMENT` | contradicted | disabled, enabled |
| `MEASURED_MODE_CHANGE` | contradicted | disabled, enabled |
| `CHANGE_PLUS_SURVIVOR` | unverifiable | disabled, enabled |
| `CHANGE_PLUS_TIMEOUT` | unverifiable | disabled, enabled |
| `CHANGE_PLUS_MISSING_RESULT` | unverifiable | disabled, enabled |
| `CHANGE_PLUS_COLLECTOR_LOSS` | unverifiable | enabled |
| `CHANGE_PLUS_HASH_UNAVAILABLE` | unverifiable | disabled, enabled |
| `HASH_READ_FAILURE_NO_CHANGE_FACT` | unverifiable | disabled |
| `PRECEDENCE_UNVERIFIABLE_OVER_CONTRADICTED` | unverifiable | disabled, enabled |
| `PRECEDENCE_CONTRADICTED_OVER_SUPPORTED` | contradicted | disabled, enabled |
| `DENY_READ_SYNTHETIC_SSH_KEY_ABSOLUTE_FIXTURE_PATH` | unverifiable | disabled, enabled |
| `DENY_READ_SYNTHETIC_SSH_KEY_SYMLINK_ALIAS` | unverifiable | disabled, enabled |
| `DENY_READ_SYNTHETIC_SSH_KEY_ANCESTOR_ALIAS` | unverifiable | disabled, enabled |
| `DENY_READ_SYNTHETIC_ENV_SECRET_ABSOLUTE_FIXTURE_PATH` | unverifiable | disabled, enabled |
| `DENY_READ_SYNTHETIC_ENV_SECRET_SYMLINK_ALIAS` | unverifiable | disabled, enabled |
| `DENY_READ_SYNTHETIC_ENV_SECRET_ANCESTOR_ALIAS` | unverifiable | disabled, enabled |
| `NETWORK_DIRECT_V4_DEFAULT` | unverifiable | disabled, enabled |
| `NETWORK_DIRECT_V6_DEFAULT` | unverifiable | disabled, enabled |
| `NETWORK_WRONG_PORT` | unverifiable | disabled, enabled |
| `NETWORK_DECLARED_PORT_V4` | supported | disabled, enabled |
| `NETWORK_DECLARED_PORT_V6` | supported | disabled, enabled |
| `NETWORK_ALTERNATE_LOOPBACK_V4` | unverifiable | disabled, enabled |
| `NETWORK_NONLOOPBACK_BIND_V4` | unverifiable | disabled, enabled |
| `NETWORK_NONLOOPBACK_BIND_V6` | unverifiable | disabled, enabled |
| `NETWORK_UDP_DEFAULT` | unverifiable | disabled, enabled |
| `NETWORK_PROXY_HTTP_UNDECLARED` | unverifiable | disabled, enabled |
| `NETWORK_PROXY_CONNECT_UNDECLARED` | unverifiable | disabled, enabled |
| `EXTERNAL_EGRESS_NO_AUTHORIZED_FIXTURE` | unverifiable | disabled, enabled |
| `CACHE_WRITE_REDIRECTED_SCRATCH` | supported | disabled, enabled |
| `CACHE_WRITE_PROTECTED_SOURCE` | unverifiable | disabled, enabled |
| `CLEAN_CONTROL` | supported | disabled, enabled |
| `DECLARED_SCRATCH_WRITE` | supported | disabled, enabled |
| `GROUP_CHILD_CLEAN` | supported | disabled, enabled |
| `ESCAPE_CHILD_SURVIVOR` | unverifiable | disabled, enabled |
| `CHECK_TIMEOUT` | unverifiable | disabled, enabled |
| `SUPERVISOR_DEATH` | unverifiable | disabled, enabled |
| `CANARY_MISSING` | unverifiable | enabled |
| `BURST_OVER_100_PERSISTED` | supported | enabled |
| `SUBSCRIPTION_DROP` | unverifiable | enabled |
| `SPOOL_OVERFLOW` | unverifiable | enabled |
| `COLLECTOR_DEATH` | unverifiable | enabled |
| `AMBIGUOUS_EVENT_ID` | unverifiable | enabled |
| `DELAYED_AFTER_LEADER_EXIT` | supported | enabled |
| `CROSS_INVOCATION_EVENT` | unverifiable | enabled |
| `LOGGING_DISABLED_EXPLICIT` | supported | disabled |
| `MISSING_NODE` | unverifiable | disabled, enabled |
| `NODE_DIGEST_MISMATCH` | exit 3, no verdict | disabled, enabled |
| `MISSING_SANDBOX_FACILITY` | unverifiable | disabled, enabled |
| `WRITABLE_BUNDLE` | unverifiable | disabled, enabled |
| `BUNDLE_DIGEST_MISMATCH` | exit 3, no verdict | disabled, enabled |
| `INVALID_POLICY_GRANT` | exit 3, no verdict | disabled, enabled |
| `UNSUPPORTED_EXACT_PORT_POLICY` | unverifiable | disabled, enabled |
| `MALFORMED_RESULT` | unverifiable | disabled, enabled |
| `STALE_RESULT` | unverifiable | disabled, enabled |
| `MISSING_RESULT` | unverifiable | disabled, enabled |
| `DUPLICATE_ASSERTIONS` | unverifiable | disabled, enabled |
| `INCONSISTENT_EXIT` | unverifiable | disabled, enabled |
| `FINAL_RECEIPT_FORGERY` | unverifiable | disabled, enabled |
| `SEQUENTIAL_RUN_ISOLATION` | supported | disabled, enabled |
| `DRAIN_TIMEOUT` | unverifiable | enabled |
| `LATE_RELEVANT_DENIAL` | unverifiable | enabled |
| `SWALLOWED_INVISIBLE_DENIAL_DISABLED` | supported | disabled |
| `COMPARATOR_RESTORE_WITH_MISSING_EVIDENCE` | unverifiable | disabled, enabled |
| `KILL_FAILURE` | unverifiable | disabled, enabled |
| `PROCESS_OBSERVATION_FAILURE` | unverifiable | disabled, enabled |
| `TMP_PRIVATE_TMP_ALIAS` | unverifiable | disabled, enabled |
| `CASE_ALIAS` | unverifiable | disabled, enabled |
| `HARDLINK_READ_ALIAS` | unverifiable | disabled, enabled |
| `ABSOLUTE_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `PARENT_TRAVERSAL_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `WILDCARD_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `TRACKED_FILE_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `DEPENDENCY_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `PROTECTED_ANCESTOR_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `SYMLINK_WRITE_ROOT` | exit 3, no verdict | disabled, enabled |
| `DUPLICATE_PORT` | exit 3, no verdict | disabled, enabled |
| `PORT_ZERO` | exit 3, no verdict | disabled, enabled |
| `PORT_TOO_LARGE` | exit 3, no verdict | disabled, enabled |
| `PORT_STRING` | exit 3, no verdict | disabled, enabled |
| `PORT_WILDCARD` | exit 3, no verdict | disabled, enabled |
| `RAW_NETWORK_FLAGS` | exit 3, no verdict | disabled, enabled |
| `DECLARED_PORT_BIND_V4` | supported | disabled, enabled |
| `DECLARED_PORT_BIND_V6` | supported | disabled, enabled |
| `DECLARED_PROXY_HTTP` | supported | disabled, enabled |
| `DECLARED_PROXY_CONNECT` | supported | disabled, enabled |
| `UDP_DENIED_WITH_DECLARED_TCP_PORT` | unverifiable | disabled, enabled |
| `WRONG_NODE_VERSION` | unverifiable | disabled, enabled |
| `WRONG_PHASE_RESULT` | unverifiable | disabled, enabled |
| `WRONG_CHECK_RESULT` | unverifiable | disabled, enabled |
| `MISSING_ASSERTION_ID` | unverifiable | disabled, enabled |
| `MALFORMED_JSON_RESULT` | unverifiable | disabled, enabled |
| `CONFLICTING_STATUS_RESULT` | unverifiable | disabled, enabled |
| `NO_RESULT_JSON` | unverifiable | disabled, enabled |
| `VALID_LOOKING_FABRICATED_RESULT_LIMIT` | supported | disabled, enabled |
| `DENY_SNAPSHOT_GIT_INDIRECTION` | unverifiable | disabled, enabled |
| `CACHE_WRITE_EXTERNAL_DEPENDENCY` | unverifiable | disabled, enabled |
| `CACHE_WRITE_JUDGE_FIXTURE` | unverifiable | disabled, enabled |
| `JUDGE_SIDE_CACHE_FAILURE` | unverifiable | disabled, enabled |
| `CLEAN_DEFAULT_POLICY` | supported | disabled, enabled |
| `REDIRECT_HOME_TMP_CACHE` | supported | disabled, enabled |
| `EXPECTED_DENIAL_BEHAVIORAL_ASSERTION` | supported | disabled, enabled |
