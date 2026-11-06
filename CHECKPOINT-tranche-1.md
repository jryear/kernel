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


## Sandbox v2 freeze — plan v6, FREEZE ONLY

Authority: Zack, 2026-11-06. Owner `sol-2`; independent reviewer lands reviewed
work on `next`. Branch `kernel/sandbox-v2` starts from `origin/next` at
`bf9ed3d` (plan v6 merge). Binding plan read from `origin/main` at `426e43a`,
instruction_version 6; docs/SANDBOX_DECISION.md remains the acceptance boundary.
The decision's historical plan-version prose does not override current v6 rules.

**FROZEN_BASE: `4fa15c4b0afeb9adb5afe5caea31e864775b8580`.**
This single commit adds only tasks/sandbox.toml and the full test/fixture chain:
tests/tamper_suite.py and tests/sandbox_fixtures/{harness.py,subject_driver.py,
payload.py,matrix.json,README.md,measure_cost.py}. Product sources and the installed
3.1.0 judge are unchanged. This checkpoint is a separate documentation commit.

### Changes from sandbox-v1, case by case

The comparison is against `origin/kernel/sandbox`: freeze
`c6f519b584c9d611601a0bc998472c5743d71df2`, checkpoint `a34d2a7`.

- Move only `EXTERNAL_EGRESS_NO_AUTHORIZED_FIXTURE` (disabled and enabled logging)
  to plan item `egress`. Remove its network dispatch, `egress_case` and
  tests/sandbox_fixtures/egress_probe.py from this freeze and executable chain.
  No new egress test is authored here; tests/egress_qualification.py freezes later.
  Sandbox-v2 has no off-machine endpoint or external-egress receipt dependency.
- Retain default IPv4/IPv6 direct connections, wrong port, declared IPv4/IPv6
  ports, alternate loopback, IPv4/IPv6 non-loopback binds, UDP default,
  undeclared HTTP/CONNECT proxies, declared IPv4/IPv6 binds, declared HTTP/CONNECT
  proxies and UDP denied despite a declared TCP port. These 16 network rows are
  unchanged, including their logging variants, positive controls and evidence.
- All other 165 rows are unchanged. The exact 181 retained JSON case objects are
  byte-equivalent after JSON parsing to v1 with the one moved row removed;
  subject_driver.py and payload.py are byte-identical to v1. Totals change from
  182 cases / 350 variants to **181 cases / 348 variants**. No other case is
  removed, relaxed, renamed or individually credited as a novel baseline RED.
- Replace the single 1200-second conjunction with four separately budgeted
  acceptance checks. Each has a fresh real-effect boundary witness followed by
  all assigned rows; it cannot pass by satisfying only the witness. With no
  explicit group, the Desk command still runs all groups.
- Classifier is folded into effect; dependency into policy. Installed 3.1.0
  kernel_runtime.validate_spec explicitly rejects an empty acceptance
  baseline_failures set. A missing classifier API/dependency is not RED. Each
  named assertion instead conjoins its entire assigned layer set with the same
  reviewed confinement boundary, independently exercised in its own disposable
  fixture. A real successful forbidden write plus complete nested SUPPORTED
  disproves that conjunction. Later rows are explicitly unqualified on that
  short-circuit. Unavailable continues to escape without an assertion receipt.

### Check split, measured costs and budgets

Measured on macOS 27.0 arm64, Python 3.15.0, using the unsandboxed subject package
from origin/next. Two actual nested base+candidate witness invocations per group;
separate direct operation controls. File control samples: 0.2290, 0.2320, 0.2307 s.
Network control samples including listener shutdown: 0.7375, 0.7361 s.

| Check / named assertion | Cases / variants | Measured witness seconds | Full cost projection seconds | Timeout seconds |
| --- | ---: | --- | ---: | ---: |
| effect-classifier / `SANDBOX_EFFECT_CLASSIFIER_BOUNDARY` | 124 / 234 | 2.2988, 2.2628 | 586.62 | 3660 |
| protocol / `SANDBOX_PROTOCOL_BOUNDARY` | 13 / 26 | 2.2431, 2.3116 | 62.41 | 600 |
| policy-dependency / `SANDBOX_POLICY_DEPENDENCY_BOUNDARY` | 37 / 74 | 2.2699, 2.2400 | 196.97 | 1320 |
| isolation / `SANDBOX_ISOLATION_BOUNDARY` | 7 / 14 | 2.2421, 2.2811 | 75.30 | 600 |

The full-cost column is a calibrated projection, **not a measured sandbox run**.
Every variant is conservatively charged the slowest measured nested invocation
(2.311628 s), even classifier and prelaunch rows that do not execute that pipeline.
Add one gate per check, extra sequential invocations (16 isolation invocations
for 14 variants), 187 file controls, 32 network controls and six seconds per
timeout variant (36 s total). Use the slowest measured control of each type.
Timeout = max(600, round_up_to_60(120 + 4 * projection + 5 * variants)).
This leaves generous startup/collector/backend headroom without certifying a
future backend's cost. Inner fixture-command timeout remains 45 s; each nested
payload check retains its intentional 3 s limit. Correct backend qualification
and any unanticipated timing problem remain for implementation review; no
post-GREEN timeout adjustment or retry is authorized by this checkpoint.

Reproduction: `PYTHONDONTWRITEBYTECODE=1 python3 -B
 tests/sandbox_fixtures/measure_cost.py` (one shell line). Measurement code is
frozen, manual and outside acceptance; it neither implements nor mocks the
sandbox. Raw external samples/model:
`/Users/jryear/.local/state/kernel/sandbox-v2-costs.json` and
`/Users/jryear/.local/state/kernel/sandbox-v2-costs.txt`.

### Scope and protection audit

Protected patterns remain exactly `tests/*`, `tasks/*`,
`docs/SANDBOX_DECISION.md`, `spike/*`, `.desk/*`; no protection is loosened.
Every executed entry/helper/catalogue is in each check's chain and protected.
Evidence includes all fixture files, the decision and pinned spike lock bytes.

Implementation scope covers verify.py; root kernel_*.py runtime/report/process/
sandbox modules; kernel_sandbox/* package; sandbox_supervisor.mjs;
sandbox_runtime/* bundle-source staging; sandbox.package.json/lock; VERSION;
MANIFEST.sha256; README.md; FRONTIER.md; AGENTS.template.md installation/agent
instructions; docs/SANDBOX_RUNTIME.md; and this checkpoint. The kernel_*.py
pattern preserves v1's named modules while permitting additional runtime helpers;
VERSION and AGENTS.template.md cover packaging/instruction updates. No scope
entry overlaps the required protected paths. No installed bundle path or runtime
write grant follows from source-edit scope. A later unexpected build output
outside this scope requires review/refreeze, not a weakened frozen protection.
This anticipates the integrate-1 scope collision without editing its old contract.

### Installed-judge baseline and evidence

Initial baseline: exit 0, `BASELINE_READY sandbox-v2
assurance=schema2-evidence-validity`. All four checks emit exactly their named
failure ID, `harness_error=false`. Each detail records a successful synthetic
protected write, independently inventoried lasting byte change, nested exit 0
and nested SUPPORTED with complete assertion/cleanup evidence. Missing API,
CLI error, setup failure, unavailable dependency or missing receipt is never RED.
Rows beyond each decisive witness are not individually qualified by this result.

Initial output/log:
`/Users/jryear/.local/state/kernel/sandbox-v2-baseline.txt`,
`/Users/jryear/.local/state/kernel/sandbox-v2-baseline.jsonl`.
The initial invocation used --base HEAD while HEAD was exactly FROZEN_BASE.
The final checkpoint HEAD is re-baselined with the literal immutable SHA:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B ~/code/_kernel/verify.py tasks/sandbox.toml --repo . --base 4fa15c4b0afeb9adb5afe5caea31e864775b8580 --baseline --log ~/.local/state/kernel/sandbox-v2-baseline-final.jsonl
```

Final output: `/Users/jryear/.local/state/kernel/sandbox-v2-baseline-final.txt`.
Judge inventories before/after:
`/Users/jryear/.local/state/kernel/sandbox-v2-judge-before.json`,
`/Users/jryear/.local/state/kernel/sandbox-v2-judge-after.json`.
Inventory includes directory/file/link types, modes, mtimes, bytes, sizes and
caches; only shared .git metadata used by required branch/Desk/snapshot operations
is excluded. Comparison receipt:
`/Users/jryear/.local/state/kernel/sandbox-v2-judge-comparison.json`.

### Review stop and remaining boundary

Desk claimed sandbox as `sol-2`, branch kernel/sandbox-v2, instruction_version 6,
and heartbeats were maintained. No Desk prove is used to recast deliberate RED
as GREEN. Branch is pushed and workspace set in-review for **freeze review**.
No implementation, bundle provisioning, egress qualification, flake, mutants,
BidZizi work, installation, merge or push to main/next occurs in this run.

The v1 bundle proposal remains a proposal: operator-owned immutable external
prefix, pinned srt 0.0.81 and spike transitive lock, qualified Node v24.22.0 with
artifact/executable digests and caller-held receipt. No bundle or enforcement is
qualified here. Full matrix execution and GREEN require that later authorized
implementation/environment. Off-machine egress remains a separate default-on
and release gate under plan v6. Logs remain diagnostic/incomplete; no invisible
attempt, restored-write, semantic-attestation or exhaustive-cleanup claim is added.
