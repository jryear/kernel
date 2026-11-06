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


## Sandbox v3 freeze — amendment 2026-11-06, FREEZE ONLY

Branch `kernel/sandbox-v3` starts exactly at `origin/next`
`f9a0c82ebef62184208a3493be84df365f5c83a5`, the reviewed amendment landing.
Binding source is docs/SANDBOX_DECISION.md, section "Amendment 2026-11-06: exact
loopback ports via pinned srt patch", read in full; plan remains v6. The earlier
unmodified-backend restriction and loopback-only binding claims are superseded
at declared ports as specified there. This phase does not port implementation.

**FROZEN_BASE: `f86aadec2564160d062b7c4ab3da8d2f7cd4938e`.**
The one freeze commit adds only tasks/sandbox.toml and the full fixture chain:
tests/tamper_suite.py and tests/sandbox_fixtures/{README.md,harness.py,matrix.json,
measure_cost.py,payload.py,profile_faults.py,subject_driver.py}. No product source,
patch, supervisor, provisioning source, installed dependency, decision or plan is
edited. Scope/protection is byte-equivalent to v2; sandbox_runtime/* already
covers the future patch/validator/bundle sources. No protection is loosened.

V2 remains history on `kernel/sandbox-v2` at
`39a419c97b1271ab1ba08b9dfab948e7665456da`, with immutable v2 freeze
`4fa15c4b0afeb9adb5afe5caea31e864775b8580`. The v3 fixtures were copied from that
freeze, not from partial implementation. No v2 frozen file was edited on its
branch and no v2 implementation was cherry-picked into v3.

### Exact v2 to v3 evidence changes and reasons

The complete line-for-line unified diff, including every README/harness/matrix
change, is retained externally as
`~/.local/state/kernel/sandbox-v3-v2-interface.diff`, SHA-256
`98478887c3a21971330a6d724c70e289d0466a9414a7d7bd6618c046453c2094`.
It is reproducible with `git diff --binary 4fa15c4b0afeb9adb5afe5caea31e864775b8580
f86aadec2564160d062b7c4ab3da8d2f7cd4938e -- tasks/sandbox.toml tests` on one line.
`~/.local/state/kernel/sandbox-v3-evidence-diff.json` separately records exact
before/after evidence arrays per changed case, every new case, and this diff
hash. The following is the exhaustive semantic change map for review.

**Matrix:** All 181 prior case IDs, layers/groups, operations, expected verdicts,
logging variants, params and evidence_source fields remain identical. All
operation controls remain unchanged in payload.py and the existing harness case
handlers. Payload.py and tests/tamper_suite.py are byte-identical to v2. Exactly
11 prior evidence lines change; no other existing matrix field changes.

Old line in each of these 11 rows:
`policy contains only declared exact loopback tuples`

New line, verbatim in each:
`declared destinations are exact canonical TCP tuples; effective bind/inbound/outbound and internal-proxy grants match the versioned profile specification, with residual limits explicitly receipted`

Changed rows:
- `NETWORK_DIRECT_V4_DEFAULT`
- `NETWORK_DIRECT_V6_DEFAULT`
- `NETWORK_WRONG_PORT`
- `NETWORK_DECLARED_PORT_V4`
- `NETWORK_DECLARED_PORT_V6`
- `NETWORK_ALTERNATE_LOOPBACK_V4`
- `NETWORK_NONLOOPBACK_BIND_V4`
- `NETWORK_NONLOOPBACK_BIND_V6`
- `NETWORK_UDP_DEFAULT`
- `NETWORK_PROXY_HTTP_UNDECLARED`
- `NETWORK_PROXY_CONNECT_UNDECLARED`

Reason for every replacement: the old line described canonical loopback tuples
as exhaustive authority and could conceal wildcard binding. The amendment
requires canonical declarations AND the actual versioned effective grants plus
explicit residual limits. The rows' other evidence lines are unchanged. The
remaining five network rows (DECLARED_PORT_BIND_V4/V6, DECLARED_PROXY_HTTP/CONNECT,
UDP_DENIED_WITH_DECLARED_TCP_PORT) retain their original evidence arrays. The
shared receipt predicate for all 16 now enforces the amended meaning; native
successful bind observations still must match the requested native address/port.

**Harness receipt evidence:**

- Parent sandbox_receipt.schema changes 1 to 2. Operator request schema remains 1.
  Required policy fields add network_semantics, effective_network_rules,
  profile_sha256 and profile_validation; this versions the authority correction.
- localhost_endpoints is explicitly the declared application list, still exactly
  two canonical TCP tuples per integer. A multiplicity-preserving list comparison
  replaces the previous set comparison, so duplicate declared tuples cannot hide.
- network_semantics must equal srt-0.0.81-exact-tcp-v1. Expected effective IP rules
  are exactly local TCP bind/inbound at host * and remote TCP outbound at host
  localhost per declared port, plus one remote TCP localhost outbound rule per
  distinct actual proxy port. Complete-list/multiplicity comparison rejects
  omissions, extras, duplicates, UDP/ip, local outbound or broad host/port rules.
  Empty declarations require an empty application bind/inbound set.
- internal_ipc now explicitly separates proxies and non_ip_rules. Each proxy
  carries role, canonical host, integer port, tcp transport, positive PID/start
  identity, ready=true and ownership_verified=true; http/socks roles are unique,
  can share a mux port, and may not overlap declarations. The only fixed reviewed
  non-IP rule is system-socket, AF_SYSTEM, protocol 2. This prevents proxy and
  Unix-socket authority from being omitted or confused with declarations.
- profile_validation binds validator_id=kernel-srt-profile-validator-v1,
  exact_match, the complete retained UTF-8 inspected_profile string, and errors.
  Its SHA-256 must equal policy.profile_sha256. Successful launched/enforced
  receipts must match complete declarations and grants, not just a network
  marker section. Failed inspection requires exact_match=false, nonempty errors
  and retained mismatching profile identity. Unparsed effective rules may be
  unavailable on rejection; the fixture does not demand fictitious repaired rules.
- policy.exceptions explicitly discloses address_wildcard_declared_tcp_binding
  (sorted ports, nonloopback_inbound_exposure and accepted_connection_data_exchange
  true iff declarations are nonempty), localhost_address_class_aliases
  (literal_spelling_enforced=false), and mapped_outbound_qualification
  (supported/unavailable, universal_compatibility=false, this platform, exact
  OS build and matching Node version/artifact). Each has a nonempty detail.
- assurance adds required false loopback_only_binding and literal_address_only;
  all five preexisting false assurance limits remain. This prevents obsolete
  loopback-only or literal-spelling claims while retaining other evidence bounds.
- bundle must bind patch_id=kernel-srt-0.0.81-exact-tcp-v1, patch_sha256,
  patch_preimages, patch_postimages and bundle_digest exactly to the external
  operator receipt. Both patch manifests are nonempty unique relative
  {path,sha256} lists with identical changed-file sets and valid SHA-256 values.
  Existing pinned srt/Node/lock and release digest checks remain.
- Probe.invoke additionally retains the declared ports, external expected bundle
  metadata, whether any final verdict was written, and a bounded bundle-executable
  launch audit. The real-effect witness and its short-circuit/Unavailable
  behavior are unchanged; its detail protocol changes sandbox-freeze-2 to -3.

**New fault evidence and adapter:** profile_faults.py only alters test input.
subject_driver.py wraps the future production
`kernel_sandbox.validate_generated_profile(profile, context)` seam, passes the
altered complete bytes to that real validator, and records before/inspected
hashes. It raises actual RuntimeError/OSError for failed/unavailable inspection.
It does not implement a profile parser, fabricate a validator result or rewrite
an actual launch profile. Missing API is Unavailable, never RED. The production
prelaunch call and identical-byte launch binding remain independent source-review
requirements. profile_faults.py is added to every check's declared chain.

Each profile rejection must return exit 2/unverifiable, enforced=false,
launched=false, no candidate operation, no protected change, exact_match=false,
a precise error list and the inspected hash/bytes matching the injected witness.
For PATCH_AUTHENTICATION_FAILURE, dependency_case appends bytes only to the
inventoried patch_file in a disposable bundle copy with original expected hashes.
It requires exit 3, no final verdict and no observed bundle-executable launch.
The adapter audits Popen for executables under that disposable bundle root; this
is bounded launch evidence, not exhaustive semantic/code-loading attestation.

**README:** The title/counts/table become v3 and 201/388 with the revised policy
budget. The parent receipt schema paragraph becomes schema 2. The old paragraph
calling localhost_endpoints exact effective authority is replaced by the
canonical-destination/effective-rule/internal-IPC/profile/exception definitions
above, with exact machine-readable field shapes. The bundle section adds patch
file/ID/own digest/pre/postimage identities and whole-bundle coverage. A new
read-only validator seam paragraph explains the reviewed fault path and required
production wiring. The assurance paragraph adds both false flags. The old
"16 network rows byte-for-byte" paragraph becomes the exact 11-line evidence
replacement accounting while retaining every operation/outcome/control. New
rejection-case paragraphs specify each verdict, input mutation, retained evidence
and launch audit limit. The explicit residual-limit paragraphs disclose wildcard
bind/inbound and accepted-connection data exchange, OS localhost alias/mapped
matching, no server/process identity, possible relay by allowed services,
occupancy/permission/race unavailability and all unchanged UDP/egress/log/attempt/
hostile-host limits. V3's external-egress exclusion remains; no external endpoint
or egress receipt is introduced. Patch file/hash/authentication are future
implementation outputs, not fabricated by this freeze.

**Contract and cost helper:** ID changes sandbox-v2 to sandbox-v3. Existing four
names, assertion IDs, baseline failure sets, groups, scope and protections remain
identical. The fixture helper chain adds profile_faults.py. Only the policy/
dependency timeout changes, to budget the new cases by the existing formula.
measure_cost.py retains approved v2 cost floors and writes sandbox-v3-costs.json,
preserving old evidence; it never changes the frozen task timeout itself.

### Added cases

Every new case has operation clean and both disabled/enabled logging variants.
The 19 profile faults belong to policy; the patch fault belongs to dependency.
All are in the existing policy-dependency check; no other group changes.

| New case ID | Reviewed fault | Required nested outcome |
| --- | --- | --- |
| `PROFILE_MISSING_RULE` | missing_rule | unverifiable, exit 2, launched=false |
| `PROFILE_ADDITIONAL_RULE` | additional_rule | unverifiable, exit 2, launched=false |
| `PROFILE_DUPLICATE_RULE` | duplicate_rule | unverifiable, exit 2, launched=false |
| `PROFILE_MALFORMED_RULE` | malformed_rule | unverifiable, exit 2, launched=false |
| `PROFILE_BROADENED_HOST` | broadened_host | unverifiable, exit 2, launched=false |
| `PROFILE_IP_TRANSPORT` | ip_transport | unverifiable, exit 2, launched=false |
| `PROFILE_WILDCARD_PORT` | wildcard_port | unverifiable, exit 2, launched=false |
| `PROFILE_LOCAL_OUTBOUND` | local_outbound | unverifiable, exit 2, launched=false |
| `PROFILE_UNACCOUNTED_PROXY` | unaccounted_proxy | unverifiable, exit 2, launched=false |
| `PROFILE_UNIX_SOCKET` | unix_socket | unverifiable, exit 2, launched=false |
| `PROFILE_UNEXPECTED_DEFAULT` | unexpected_default | unverifiable, exit 2, launched=false |
| `PROFILE_INSPECTION_FAILURE` | inspection_failure | unverifiable, exit 2, launched=false |
| `PROFILE_INSPECTION_UNAVAILABLE` | inspection_unavailable | unverifiable, exit 2, launched=false |
| `PROFILE_UNKNOWN_SYNTAX` | unknown_syntax | unverifiable, exit 2, launched=false |
| `PROFILE_INCLUDE` | include | unverifiable, exit 2, launched=false |
| `PROFILE_MACRO` | macro | unverifiable, exit 2, launched=false |
| `PROFILE_OPERATION_WILDCARD` | operation_wildcard | unverifiable, exit 2, launched=false |
| `PROFILE_OUTSIDE_NETWORK_SECTION` | outside_network_section | unverifiable, exit 2, launched=false |
| `PROFILE_NONNETWORK_TEMPLATE` | nonnetwork_template | unverifiable, exit 2, launched=false |
| `PATCH_AUTHENTICATION_FAILURE` | patch file byte tamper | exit 3, no verdict |

No previous case is removed, weakened, renamed or reclassified. The count is
201 cases / 388 variants (181/348 retained plus 20/40 new). A synthetic declared
port 12345 supplies a known application rule for profile mutations. Mutators
cover every listed rejection class, plus an extra grant beyond a marker section
and a changed non-network template to exercise complete-profile inspection.
The patch case targets its own authenticated patch-file digest, not a missing API.
These new paths are frozen for review, not executed/qualified on the absent
patched product. Baseline witnesses do not individually credit their outcome.

### Cost calibration and timeouts

Same formula: max(600, ceil_to_60(120 + 4 * projected_seconds + 5 * variants)).
Charge every variant the slowest calibrated nested invocation, including pure
classifier/prelaunch variants, plus one gate/check, extra isolation invocations,
187 file controls, 32 network controls and six seconds per timeout variant.
Keep approved v2 floors: nested 2.31162816699 s, file 0.23199816700 s, network
0.73749454098 s; fresh faster samples must not shrink existing budgets.

| Check | Cases / variants | Fresh measured witness samples (s) | Projection (s) | Frozen timeout (s) |
| --- | ---: | --- | ---: | ---: |
| effect-classifier | 124 / 234 | 1.3969, 1.3726 | 586.62 | 3660 |
| protocol | 13 / 26 | 1.3841, 1.3843 | 62.41 | 600 |
| policy-dependency | 57 / 114 | 1.4029, 1.3787 | 289.44 | 1860 |
| isolation | 7 / 14 | 1.4114, 1.4096 | 75.30 | 600 |

The 40 added variants add 92.4651 s to the policy projection, which becomes
289.4371 s, yielding 1860 s. Other budgets remain exactly 3660/600/600. Fresh
measurements and full arithmetic are external:
`~/.local/state/kernel/sandbox-v3-costs.txt` and sandbox-v3-costs.json.
These are unsandboxed fixture samples/projections, not a patched-backend timing
or a correct-build GREEN claim. Inner timeouts and all prior controls remain.

### Baseline, inventory and fixture checks

Initial installed-judge baseline: exit 0, BASELINE_READY sandbox-v3,
assurance=schema2-evidence-validity. All four checks fail exactly their existing
named boundary assertion with harness_error=false. Each decisive witness is an
actual synthetic protected write, independent lasting change, nested exit 0 and
SUPPORTED with complete check/cleanup evidence. No API, CLI, dependency or setup
failure is counted as RED. Subsequent rows are explicitly unqualified after the
witness. Unavailable still propagates without an outer assertion result.

Initial output/log:
`~/.local/state/kernel/sandbox-v3-baseline.txt`, sandbox-v3-baseline.jsonl.
The same literal immutable SHA is used for initial and final documentation-head
baselines:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B ~/code/_kernel/verify.py tasks/sandbox.toml --repo . --base f86aadec2564160d062b7c4ab3da8d2f7cd4938e --baseline --log ~/.local/state/kernel/sandbox-v3-baseline-final.jsonl
```

Final output: `~/.local/state/kernel/sandbox-v3-baseline-final.txt`.
Before/after judge inventories: sandbox-v3-judge-before.json and
sandbox-v3-judge-after.json under the same external state directory. They include
all package/cache files, directories, modes, mtimes, sizes, bytes and links;
only shared .git metadata required for branches/Desk/snapshots is excluded.
Comparison: sandbox-v3-judge-comparison.json. The installed judge is read-only.

Syntax, unique/exhaustive grouping, original case-field preservation, exact 11
matrix replacements, unchanged entry/payload, complete protected helper chain
and unchanged scope checks passed. All 19 mutation inputs were exercised on a
synthetic generated-profile string for fixture wiring only. The new receipt
predicate accepted one synthetic control and rejected 14 distinct malformed
metadata controls (missing/duplicate rules, ip, wildcard port, local outbound,
broadened host, proxy bind, wrong declaration, extra IPC, profile hash, validation
failure, missing exception, literal alias overclaim and undisclosed exposure).
Log: `~/.local/state/kernel/sandbox-v3-fixture-validation.txt`. This is fixture
predicate evidence, not product validator/enforcement or patched-bundle proof.

### Review stop

Desk sandbox lease was released from v2 before branching; sol-2 claimed it on
kernel/sandbox-v3 under instruction_version 6 and maintained heartbeats. Branch
is pushed and workspace is in-review for **v3 freeze review**. No desk prove,
implementation port, patch construction/application, supervisor/validator product
code, npm install, provisioning, egress, flake, mutants, BidZizi work, installation,
merge or push to main/next occurred in this phase. Phase 2 needs a separate go
after this freeze is approved. The approved v2 history and evidence are preserved.


## Sandbox v3 implementation — INCOMPLETE context checkpoint

User-authorized Phase 2, Sol implementation manager with Terra and Luna. Stopping
at the requested context boundary with a coherent pushed checkpoint rather than
claiming acceptance. **Source HEAD: `24a54b42be83c346b2f2009f10bf71a1e993153c`**
on kernel/sandbox-v3. This source commit was pushed before this documentation
commit. Approved FROZEN_BASE remains
`f86aadec2564160d062b7c4ab3da8d2f7cd4938e`; tests/tasks/decision/spike/Desk plan
are unchanged and every changed path is inside its frozen implementation scope.

**Done condition is NOT met:** no all-four-check installed-judge claim has run.
The work below is development/component evidence only, not qualification, full
acceptance, production readiness or provisioning authorization.

### Implemented source and ownership

- Terra: versioned dist patch, authenticated pre/postimage manifest and an exact
  hunk applicator; trusted Node supervisor; read-only complete-profile validator
  kernel-srt-profile-validator-v1 in kernel_profile.py.
- Luna: exact sandbox.package.json/lock, fresh external bundle assembler,
  Zack-only provision.sh, runtime docs and README/FRONTIER residual limits.
- Sol: ported classifier/policy validation, new kernel_bundle.py authentication,
  kernel_sandbox_runtime.py trusted-parent session/receipt integration, schema-2
  parser/runtime/report hooks and legacy opt-in refusal, source review, final
  package manifest/external digest and integrated DEV smoke/regressions.

The patch is sandbox_runtime/kernel-srt-0.0.81-exact-tcp-v1.patch, SHA-256
`361badaf1608a8eca139ce3a17fe69722d70e85c31078e90dca2fbb6dfb212ce`.
It changes only the three listed pinned dist files, with exact preimages and
postimages in sandbox_runtime/patch-manifest.json. The custom applicator checks
version, own patch hash, complete changed-file sets, old hunk positions/content
without fuzz, line counts and all postimage hashes before writing any output.
Already-applied or changed preimages are refused. Assembly is fresh; it never
patches an existing bundle in place. The private sorted integer-port input is
validated even when upstream initialize bypasses schema parsing. Broad
allowLocalBinding or unrestricted generation throws. Per-port/proxy rules are
exactly the amendment's TCP grants, with no proxy bind/inbound grants.

The Node supervisor owns separate literal-canonical HTTP/CONNECT and numeric
SOCKS gateways outside the candidate group. It rejects alternate spellings and
undeclared ports rather than relying on upstream hostname canonicalization. It
constructs an independent proxy-only reference profile first from authenticated
code and trusted filesystem configuration, then generates the actual launch
profile once. Python validates the entire actual profile and reference via the
same public validator seam used by the frozen adapter. Actual profile bytes
are never repaired or regenerated after validation. Python executes the returned
wrapped argv in kernel_process.execute; the supervisor stays outside that group
until candidate cleanup. The canary replaces only the trusted final command in
a copy of that argv, retaining the identical profile bytes.

Authentication occurs before loading/launching bundle code. It checks regular
file inventory/hash/mode, no extra files/symlinks, complete bundle digest,
upstream lock, patch own hash, pre/post manifest binding and actual postimages.
Production requires a caller-held KERNEL_SANDBOX_BUNDLE_RECEIPT_SHA256 and
operator ownership/non-writable ancestry. Development requires explicit
KERNEL_SANDBOX_DEV=1 and is always marked dev_only. Missing capability/runtime
returns unavailable; failed authentication exits 3. No npm/patch/fallback occurs
in the verifier. The production per-check and aggregate decisions call the same
classify_sandbox_evidence code exercised by the classifier fixtures.

The parent uses fresh private scratch/home/cache/result state and a reviewed
same-profile protected/scratch write canary before candidate execution. Explicit
secret paths and bounded preexisting hardlink aliases are denied; unaccounted
existing secret hardlinks fail closed. No exhaustive host alias/secret or
transient-read claim follows. Parent receipts use schema 2, disclose wildcard
TCP binding/inbound and accepted-connection exposure, OS localhost alias
semantics, unavailable mapped qualification, patch/bundle binding, complete
inspected bytes/hash and exact effective IP/proxy rules.

### Fresh development bundles and retained failures

The historical ~/.local/state/kernel/dev-bundle was never modified. Fresh v3
assembly used a clean npm ci from the exact frozen lock outside repo/judge.
The first v3 assembly copied the local Homebrew Node executable without libnode
and failed dyld startup; it is retained, not rewritten. The second fresh runtime
bundle includes copied/relocated local dylibs and ad-hoc signatures ONLY for
DEV use. This is not an official authenticated Node distribution artifact.
Production provisioning instead requires the authenticated official archive.

Current fresh checkpoint bundle:
`~/.local/state/kernel/dev-bundle-v3-checkpoint/`

External DEV receipt:
`~/.local/state/kernel/dev-bundle-v3-checkpoint.receipt.json`

Bundle digest: `399ec720ede447bc653f58358559c942dbbb191a761edf785327855bd2d426a0`.
Receipt SHA-256: `6eb80b46a5e84ba1561d7db76529d71aab232c9c1c38fec55ca9061c5a211da7`.
The receipt explicitly records dev_only, development-only qualification,
UNQUALIFIED_LOCAL_EXECUTABLE artifact provenance, actual executable digest,
patch identity, network limits and false assurance claims. Old dev-bundle-v3 and
dev-bundle-v3-runtime2 remain unchanged. Assembly log:
`~/.local/state/kernel/sandbox-v3-checkpoint-assembly.json`.

The first integrated smoke exposed srt overriding TMPDIR to nonexistent
/private/tmp/claude, so the payload failed before its operation. That failure is
retained in sandbox-v3-first-integration-smoke.txt and is not RED. The trusted
supervisor environment now supplies CLAUDE_CODE_TMPDIR to fresh child scratch;
shared /tmp/claude and state-level convenience cache paths are explicitly denied.
The successful retry is sandbox-v3-integration-smoke-r2.txt. A final smoke on
source HEAD against the checkpoint bundle is retained as
sandbox-v3-integration-smoke-final.txt/json. It requires the frozen receipt_check
and denied_probe predicates on a real protected-write operation: EPERM, nested
unverifiable, no protected changes, exact schema-2 patch/profile/rule evidence.
This is one DEV-ONLY disabled-logging smoke, not the full effect group.

### Per-check acceptance status and other validation

| Frozen check | Installed-judge DEV claim status | Available bounded evidence |
| --- | --- | --- |
| effect-classifier | NOT RUN | Real boundary smoke; 41/41 classifier variants |
| protocol | NOT RUN | Existing regression handshake tests only |
| policy-dependency | NOT RUN | Actual profile smoke; synthetic validator controls; worker proxy controls |
| isolation | NOT RUN | Existing cleanup regression suite only |

No sandbox-v3 claim log or all-four GREEN exists at this checkpoint. These
statuses must not be converted to passing acceptance by a later reader.

- selftest.py: 6/6 pass, external expected package digest supplied;
  sandbox-v3-selftest-checkpoint.txt.
- tests/self_check.py: all five assertions pass;
  sandbox-v3-self-check-checkpoint.txt.
- tests/cleanup.py: all five assertions pass;
  sandbox-v3-cleanup-checkpoint.txt.
- Combined regression exits/log paths:
  ~/.local/state/kernel/sandbox-v3-regressions-checkpoint.json.
- Parent component controls: 41 classifier/logging variants, a synthetic valid
  full profile and 17 directly mutated profile inputs pass/reject as expected;
  sandbox-v3-component-controls-checkpoint.txt. The two injected inspection
  exceptions still need full frozen-harness exercise.
- Terra reported exact patch first-apply success/replay refusal, JS syntax,
  actual generated-profile acceptance, local CONNECT/SOCKS positive nonce echo
  and CONNECT 127.1 refusal. Those worker checks are component leads, not the
  independent full claim. The original local Node was used before copied Node
  closure was fixed; do not treat them as final-bundle qualification.
- Parent source syntax, bash -n provision.sh, node --check supervisor, whitespace,
  unchanged protected paths and frozen-scope checks passed.
- Installed judge package/cache remains byte/mode/mtime identical across 206
  entries to the v3-freeze inventory (shared .git metadata excluded):
  sandbox-v3-implementation-judge-comparison.json. No installed-judge invocation
  occurred during this implementation checkpoint.

All log names above are under ~/.local/state/kernel/. Package MANIFEST.sha256
was regenerated from final retained sources. External expected-digest receipt:
`~/.local/state/kernel/sandbox-v3-implementation-release.json`, manifest SHA-256
`97f13b01418b0bf04262cba8a43f68b140638fa2937cd575d990ab6132a228b7`.
The checkpoint is not a package-manifest member, so this documentation commit
does not change that expected package digest.

### Zack's future provisioning command — DO NOT RUN YET

The single operator script is sandbox_runtime/provision.sh. It authenticates an
operator-supplied official Node archive digest, calls the same assembler into
fresh staging, refuses existing digest directories/receipts, sets root ownership
and non-writable ancestry/deny-write ACLs, writes the external protected operator
receipt and prints its SHA-256. Administrative ownership/ACL behavior is not
executed or qualified here. Receipt parent must already be root-owned,
non-writable and symlink-free. Future arm64 command, after full implementation
acceptance/review and authenticated archive acquisition:

```sh
sudo ./sandbox_runtime/provision.sh --node-archive "$HOME/Downloads/node-v24.22.0-darwin-arm64.tar.gz" --node-archive-sha256 "$KERNEL_NODE_ARTIFACT_SHA256" --receipt "/Library/Application Support/KernelRuntime/receipts/kernel-sandbox-v3.json"
```

KERNEL_NODE_ARTIFACT_SHA256 must be independently authenticated for that exact
archive, not inferred from an untrusted local download. No sudo or provisioning
was run. This checkpoint is not a request for Zack to provision incomplete work.

### Exact continuation and known gaps

1. Review the integrated parent/session/authentication/proxy/validator source on
   HEAD. In particular, verify independent reference-template construction,
   same-byte execution, allow/deny path overlaps, bounded hardlink handling,
   failed inspection receipts and protected inventory attribution.
2. Run the full installed-judge claim on clean committed HEAD against the current
   DEV receipt, with KERNEL_SANDBOX_DEV=1 and KERNEL_SANDBOX_BUNDLE_RECEIPT set.
   Do NOT set VERIFY_SANDBOX=1 on the outer judge; the frozen nested harness owns
   that opt-in. Use the user-authorized command/model label, literal FROZEN_BASE
   and a new external JSONL log, for example:

```sh
PYTHONDONTWRITEBYTECODE=1 KERNEL_SANDBOX_DEV=1 KERNEL_SANDBOX_BUNDLE_RECEIPT="$HOME/.local/state/kernel/dev-bundle-v3-checkpoint.receipt.json" python3 -B ~/code/_kernel/verify.py tasks/sandbox.toml --repo . --base f86aadec2564160d062b7c4ab3da8d2f7cd4938e --claim "DEV-ONLY sandbox-v3 integration" --implementer-model "gpt-6.1-sol medium (+terra/luna)" --log "$HOME/.local/state/kernel/sandbox-v3-dev-claim.jsonl"
```

3. Resolve real full-matrix failures in implementation only. Do not edit tests
   or tasks or loosen protections/timeouts. Retain failed logs. Likely required
   review areas include enabled collector readiness/loss/drain behavior, proxy
   socket teardown, actual lifecycle failure injection, read/alias and default
   policy cases, malformed/stale result handling and exact prelaunch refusal.
   Enabled diagnostic collection and full lifecycle evidence remain unqualified;
   absence of errors/events must never stand in for that evidence.
4. Rebuild a fresh external bundle whenever bundled sources change; never mutate
   existing development bundles. Re-run required regressions after fixes,
   regenerate final manifest/expected digest, and get all four checks GREEN in
   one complete installed-judge claim before stating the requested done condition.
5. Append final per-check logs/known gaps to this checkpoint, push v3, set
   in-review and stop. Qualification still waits for Zack's separately provisioned
   immutable bundle. No desk prove before that qualifying run.


Desk sandbox remains sol-2 on kernel/sandbox-v3 with heartbeat. Both bounded
workers have completed and own no pending writes. Workspace is set in-review;
this run stops for context recovery with acceptance incomplete. No egress,
flake, mutants, BidZizi work, installation, merge or main/next push occurred.


## Sandbox v3 implementation — DEV blocked at immutable fixture

Continuation authorized 2026-11-06. Sol-3 acquired the expired sol-2 lease at
20:41:43 UTC under instruction_version 6 and maintained heartbeats. Source HEAD:
`f15f7d9a4edc66fcb6ea6f201e4afd13a8b9e0d2` on kernel/sandbox-v3. This checkpoint
is incomplete: **no all-four GREEN and no DEV-complete claim**. The documentation
commit containing this section is recorded in the external delivery receipt.

### Stop boundary and exact blockers

The user's immutable-path stop rule applies. No tests/tasks/spike/.desk/decision
files were changed. Two independently reproduced blockers prevent the requested
complete DEV claim:

1. `NETWORK_ALTERNATE_LOOPBACK_V4` (policy layer) needs an unsandboxed reachable
   listener at 127.0.0.2. Both a plain bind and the unchanged frozen network_case
   fail with errno 49, Can't assign requested address. The actual frozen error
   is `harness.Unavailable: controlled listener unavailable: [Errno 49] Can't
   assign requested address`. No host network provisioning or sudo was used.
   Logs: `sandbox-v3-sol3-r1-policy-dependency-diagnostic.txt` and
   `sandbox-v3-sol3-r1-network-alternate-v4.txt` under ~/.local/state/kernel/.
2. Frozen `matrix.json` lines 2759–2771 supply `INVALID_POLICY_GRANT` with
   `params.policy = "unsafe_grant"`. Frozen `harness.py:682` instead reads
   `params.invalid_declaration`, defaults to the case ID, and at line 692 raises
   `Unavailable: unmapped invalid-policy fixture INVALID_POLICY_GRANT`.
   This happens before preparing/invoking the product, so implementation changes
   cannot repair it. The existing unsafe_grant mapping is present at line 686.
   Do not change frozen inputs in place or add a product test backdoor. Reviewer
   disposition/new freeze is required. Exact evidence and 20 preceding tail
   variant observations: `sandbox-v3-sol3-r1-policy-tail.jsonl`,
   `sandbox-v3-sol3-r1-policy-tail-summary.json`, and
   `sandbox-v3-sol3-r1-policy-tail-run.txt` under the external state directory.

These are unavailable evidence, not meaningful feature RED or product denial.
No positive control was emulated, skipped into success, or reclassified.

### Source review and retained implementation

Terra repaired proxy socket tracking/teardown, immediate diagnostic JSONL
spooling, observation of the embedded srt collector process and detectable
same-chunk loss, and bounded diagnostic drain/shutdown. Sol integrated parent
consumption and authentication of those spool bytes/counts; sanitized the Node
version-query environment; bound inspected profile bytes to the precise
sandbox-exec -p argv slot; included resolved Git metadata and bundle paths in
protected inventories; retained provisional result bytes/hash and an additional
final integrity observation; and separated the reviewed no-descendant canary
from arbitrary-check process cleanup so lifecycle faults exercise the check.
Luna assembled a fresh DEV bundle and ran the mechanical diagnostics/regressions.

The reviewed reference is generated separately with empty application ports;
the validator compares the entire non-network template plus exact rule
multiplicity, and the retained inspected bytes are launched without regeneration.
Path overlap, bounded hardlink fail-closed handling, inspection exception
receipts and typed classifier wiring were reviewed. This is source review and
bounded DEV evidence, not independent product acceptance or production proof.

Further read-only review found two pending source corrections. Implementation
stopped at the immutable-fixture boundary before applying them:

- Keep the diagnostic subscription active until collector close is observed;
  currently it unsubscribes before reset/close, leaving a known omission window.
  Account conservatively for deliveries after the drain deadline.
- Anchor benign late-denial matching to recognized operations/exact trusted
  canary identity. Current substring exemptions are too broad, and routine
  `system-info vfs.disk-space` is not exempted as the decision requires.

No claim about complete logs, invisible attempts, exhaustive cleanup, external
egress, mapped-address universality or production qualification follows.

### Exact DEV evidence status

The installed-judge command used the literal FROZEN_BASE and requested model
label, with PYTHONDONTWRITEBYTECODE=1, KERNEL_SANDBOX_DEV=1 and the fresh r1
KERNEL_SANDBOX_BUNDLE_RECEIPT. Outer VERIFY_SANDBOX was unset. Source stayed
clean/committed during execution. The full run was stopped at the user's scope
boundary; no complete four-check JSONL was published and no acceptance is credited.

| Frozen check | Installed-judge verdict line | Separate direct diagnostic |
| --- | --- | --- |
| effect-classifier | NONE — interrupted during candidate matrix | incomplete; no GREEN |
| protocol | NONE — not reached before stop | exit 0, 26/26 variants, no mismatches |
| policy-dependency | NONE — not reached before stop | unavailable at alternate-loopback control; later partial diagnostic unavailable at INVALID_POLICY_GRANT |
| isolation | NONE — not reached before stop | exit 0, 14/14 variants, no mismatches |

Full command console: ~/.local/state/kernel/sandbox-v3-sol3-dev-claim-r1.txt.
Requested JSONL path: sandbox-v3-sol3-dev-claim-r1.jsonl (NOT emitted).
Interruption/cleanup receipt: sandbox-v3-sol3-r1-interruption.json. Exit 130 is
an intentional interrupted run, not a test verdict. The harness was paused,
its current nested descendants were observed to finish, then the dedicated
judge group was interrupted. Judge/harness PIDs were absent afterwards and no
verification worktrees remained. This is observed cleanup, not exhaustive proof.

Direct group logs: sandbox-v3-sol3-r1-protocol-diagnostic.txt and
sandbox-v3-sol3-r1-isolation-diagnostic.txt; summary
sandbox-v3-sol3-r1-diagnostics.json. They do not replace an installed-judge claim.
The policy-tail diagnostic completed 20 variants with zero Mismatches and
stopped at its first Unavailable; later rows are not qualified.

All three regressions exited 0 with the external expected package digest:
selftest.py (6/6), tests/self_check.py (5/5), tests/cleanup.py (5/5).
Logs: sandbox-v3-sol3-r1-selftest.py.txt, sandbox-v3-sol3-r1-self_check.txt,
sandbox-v3-sol3-r1-cleanup.txt; summary sandbox-v3-sol3-r1-regressions.json.
Installed judge inventory remains exactly equal across 206 entries, excluding
only shared .git metadata: sandbox-v3-sol3-judge-before.json,
sandbox-v3-sol3-judge-after.json and sandbox-v3-sol3-judge-comparison.json.
All evidence names in this section are under ~/.local/state/kernel/.

### Final retained package and DEV bundle identities

MANIFEST.sha256 was regenerated from retained final package contents and checked
again at stop. Its external expected digest is
`aa773d8a0ab07e5f2fbe48da1bd3c1a562b53d90ad18c35b7ed04c077511c5b2`.
External receipt: ~/.local/state/kernel/sandbox-v3-sol3-blocked-release.json.
This checkpoint is not a manifest member and does not change the package digest.

Fresh bundle: ~/.local/state/kernel/dev-bundle-v3-sol3-r1/.
Receipt: ~/.local/state/kernel/dev-bundle-v3-sol3-r1.receipt.json.
Bundle digest: `0fb60c9613adaafb1254f9b82df465a0ec2d9184c55bdf0d828655f2ea1c05e5`.
Receipt SHA-256: `96d11fa4acca57b6a9c0d7b9c2969c9e75bbf1c7502e07c886cfa4784c484ad8`.
Patch file SHA-256:
`361badaf1608a8eca139ce3a17fe69722d70e85c31078e90dca2fbb6dfb212ce`.
Assembly log: sandbox-v3-sol3-r1-assembly.txt. Assembly itself succeeded; Luna's
initial shell exit-recorder used zsh's reserved status variable and failed after
success. A redundant r2 assembly attempt was interrupted; it is not acceptance
evidence. Existing historical bundles were not overwritten. The retained r1
Node remains an UNQUALIFIED_LOCAL_EXECUTABLE with development-only provenance.

### Exact continuation and Zack-only later provisioning

Reviewer must first resolve the immutable fixture seam and route the missing
alternate-loopback host prerequisite; do not infer authority to edit tests or
configure the host. After explicit continuation, repair the two diagnostic
source gaps above, assemble another fresh external bundle, regenerate the
manifest/external expected digest, and rerun the complete installed-judge claim
with the reviewed frozen base/contract. Do not borrow the direct protocol or
isolation passes as all-four GREEN. Preserve this interrupted run and all
unavailable evidence. Repeat regressions after code changes.

The future operator command remains below for Zack, after implementation and
review gates; it was NOT run and this blocked checkpoint is not a provisioning
request. The archive checksum must be independently authenticated:

```sh
sudo ./sandbox_runtime/provision.sh --node-archive "$HOME/Downloads/node-v24.22.0-darwin-arm64.tar.gz" --node-archive-sha256 "$KERNEL_NODE_ARTIFACT_SHA256" --receipt "/Library/Application Support/KernelRuntime/receipts/kernel-sandbox-v3.json"
```

Branch is delivered for review of this blocked continuation. No push to main or
next, installation, provisioning, sudo, fixture edit or desk prove occurred.
Qualifying acceptance still requires Zack's separately provisioned bundle.


## Full sweep

Reviewer authorized exhaustive direct diagnostics, implementation repairs and a
v4 proposal on 2026-11-06. **Latest source HEAD is
`47aab9a6de4c998d0105086c01f82277befac697`**, kernel/sandbox-v3. Sol-3 retained the
instruction_version 6 lease and heartbeats. Terra implemented collector repairs;
Luna built external runners/bundles and ran sweeps/regressions; Sol integrated,
reviewed source and raw evidence, classified failures and prepared the proposal.

This is complete **DEV diagnostic coverage**, not all-four installed-judge GREEN,
a v4 freeze, production qualification or permission to provision. Every frozen
case and logging variant ran; the runners continued after every failure.
All tests/tasks/spike/.desk/decision files remain byte-identical to FROZEN_BASE
`f86aadec2564160d062b7c4ab3da8d2f7cd4938e`.

### Sweep table and immutable evidence

Counts below are raw pass / Mismatch / Unavailable, never reclassified as passes.
“Pass” means unchanged harness.run_case returned after its predicates passed.

| Group | Cases / variants | Initial af1b42e | R2 7356317 | R3 47aab9a |
| --- | ---: | ---: | ---: | ---: |
| effect-classifier | 124 / 234 | 221 / 11 / 2 | 232 / 0 / 2 | 232 / 0 / 2 |
| protocol | 13 / 26 | 26 / 0 / 0 | 26 / 0 / 0 | 26 / 0 / 0 |
| policy-dependency | 57 / 114 | 110 / 0 / 4 | 112 / 0 / 2 | 110 / 1 / 3 |
| isolation | 7 / 14 | 14 / 0 / 0 | 13 / 1 / 0 | 13 / 1 / 0 |
| Total | 201 / 388 | 371 / 11 / 6 | 383 / 1 / 4 | 381 / 2 / 5 |

External evidence roots (all under ~/.local/state/kernel/sweep/):

- Initial: sol3-full-20261106T2102Z/, source af1b42e, r1 bundle.
- R2: sol3-final-20261106T2225Z/, source 7356317, r2 bundle.
- R3: sol3-final-r3-20261106T2250Z/, source 47aab9a, r3 bundle.

Each has summary.json, input identities, per-variant JSONL, retained system-temp
fixture paths and classified-nonpass-index.json. R2/R3 also retain per-variant
command argv/cwd/stdout/stderr/exit logs (no environment dumps). Each final sweep
has 388 unique variants, unchanged HEAD, clean caller source, unchanged frozen
fixture digest and installed-judge inventory equality across 206 entries.
R2/R3 valid_evidence=true means complete coherent capture, NOT all cases passed.

External runners: sweep/run.py (initial) and sweep/run-balanced.py (R2/R3).
The latter distributes variants over four independent workers and requires an
explicit source HEAD and external expected release digest. Runner hashes and
exact argv are recorded in each run. A failed intermediate runner launch,
sol3-final-20261106T2210Z/, executed zero variants because of a command-capture
import error; it is retained separately and is not a matrix outcome. No failure
was erased by a retry. All later attempts used new run IDs and bundle paths.

### Every non-pass and its classification

(a) FIXTURE defects, both modes in all complete sweeps (four final variants):

- INVALID_POLICY_GRANT: matrix params.policy="unsafe_grant" is not the key read
  by harness.py:682; the unmapped case ID raises Unavailable at line 692 before
  subject invocation. Proposed fix uses invalid_declaration, retaining the unsafe
  dot grant and the refusal expectation.
- CACHE_WRITE_EXTERNAL_DEPENDENCY: Probe.prepare writes /dependency/ to
  .gitignore, but creates dependency as a symlink. Git records mode 120000, while
  the contract also declares that path as an external worktree link. A correct
  verifier must refuse this tracked/link overlap before executing the cache
  operation. The independent disposable reproduction exited 3 with SPEC_ERROR
  external link overlaps tracked source/evidence, no receipt. Proof:
  sweep/external-dependency-fixture-proof.json. Proposed fix removes the trailing
  slash from declared-link ignore entries; controls and denial expectations stay.

(b) HOST prerequisites and availability:

- Initial NETWORK_ALTERNATE_LOOPBACK_V4, both modes: missing lo0 alias, errno49
  at the unsandboxed 127.0.0.2 listener. Zack subsequently added the alias; Sol
  verified ifconfig and bind. Both unchanged post-alias diagnostic variants and
  both variants in R2 and R3 passed. Historical failures remain in initial data;
  this prerequisite is now resolved. Evidence:
  sweep/sandbox-v3-sol3-r1-network-alternate-host-refresh.json/.txt.
- R3 NETWORK_NONLOOPBACK_BIND_V6/enabled: actual unsandboxed :: bind at port54556
  returned errno48/EADDRINUSE. Its command log proves no subject driver launched.
  This is transient positive-control port availability, not sandbox-denial proof
  or an unconditional fixture impossibility; earlier sweeps passed this case.
- R3 DECLARED_PORT_BIND_V6/enabled and GROUP_CHILD_CLEAN/enabled: BASE canary
  operation reports denied write and scratch success, but the marker is absent
  from the authenticated raw log stdout itself. Raw captures are 2268 and 3262
  bytes respectively, received=retained, below 8MiB, hash-verified, with matching
  session predicates, banner-before-prepare, no recorded drop/fault and observed
  healthy close. Candidate phases have their own canary events and are supported.
  Aggregate unverifiable is correct. Sol and Terra independently inspected these
  facts. Class (b) is limited to the observed diagnostic-stream positive-control
  dependency being unavailable in those invocations. Upstream cause remains
  unproved; this is NOT proof that the OS never emitted an event or that no
  upstream/product cause exists. No parser can recover the missing marker from
  these captured bytes. Original two Mismatch rows remain Mismatch, not passes.

(c) IMPLEMENTATION failures found and repaired:

- Initial three RESTORE_OR_ALIAS_{SYMLINK_WRITE,HARDLINK_WRITE,
  ANCESTOR_ALIAS_WRITE} cases, both modes, failed setup with ENOENT rather than
  the required denial. CACHE_WRITE_REDIRECTED_SCRATCH and DECLARED_SCRATCH_WRITE,
  both modes, also failed. These ten Mismatches were treated as implementation
  defects: the parent now materializes only validated ignored/disjoint declared
  output roots before taking its protected inventory. No runtime grant expanded.
  All ten corresponding R2 and R3 variants pass unchanged predicates.
- Initial REDIRECT_HOME_TMP_CACHE/enabled and R2 GROUP_CHILD_CLEAN/enabled failed
  due to absent canary evidence. Their particular upstream causes are unproved,
  and these historical failures remain recorded. Source/component controls
  independently proved receiver defects: split UTF-8 records, multi-record chunks,
  shutdown unsubscribe omission and unsafe late-denial substring filtering.
  The build-time pinned srt patch now frames all complete records incrementally;
  malformed/unpaired/oversized framing is ambiguous, not silently ignored.
  Subscription lasts through collector close; late deliveries/failures invalidate.
  Exact routine-operation/canary matching replaces substring exemptions.
  R3 adds bounded authenticated raw stdout, lifecycle timestamps, startup-banner
  progress observation and a one-shot isolated Python canary without site hooks.
  Missing events still make verification unverifiable; no retry manufactures pass.

The latest seven raw non-passes classify exactly as (a)=4, (b)=3, (c)=0 at the
observed boundary. This is not a claim of universal implementation correctness
or complete OS logs. R3/classified-nonpass-index.json gives every row, evidence
path, original status, category and raw hash; earlier classified indexes remain.
The canary cases remain blocked for qualification, not GREEN.

### Bounded repair validation and retained identities

Mocked collector controls (not OS-delivery qualification) live under
sweep/collector-controls/: before.json, after.json, framing-before.json,
framing-r2-exact.json, patched-after.json and r3 startup/capture/limit controls.
They prove split/batch loss before repair; afterwards all 211 byte boundaries,
including UTF-8, preserve exact contents/order, malformed input is ambiguous,
shutdown events are retained with faults, routine disk-space stays benign and
misleading path substrings stay relevant. Raw overflow and missing-banner controls
fail closed. Script/preload/source/bundle hashes are retained; the intermediate
supervisor source was archived under its matching hash.

sweep/tcp-emission-comparison.json proves the authenticated r1/r3
generateSandboxProfile body is byte-identical. The module postimage changed
because the collector changed; network profile emission was not repaired or
broadened at runtime. Exact patch preimages were preserved, application checked
against clean inputs, replay refused, postimage hashes and generator bindings
updated together. Patch SHA-256:
`9116e04677a6a058947b7e24d2b71372d86dfd6c756f25f126f512a73ac7beb2`.

Fresh retained r3 DEV bundle: ~/.local/state/kernel/dev-bundle-v3-sweep-r3/.
Receipt: ~/.local/state/kernel/dev-bundle-v3-sweep-r3.receipt.json.
Bundle digest: `4b3c5cf4af4cbcf2d4b3d8eaa41114f028340cc851c747f40c931c4c7cca2cef`.
Receipt SHA-256: `1390c998cedbe5d0fbf5eaac0cf32b934adb4156deca728fc60ec90c075a5ed6`.
Expected final MANIFEST.sha256 digest:
`3031d1ae45ea1037a94fed16f6fdc10333a1222539724e6c347057ff36d0651c`, held in
~/.local/state/kernel/sweep/release-r3.json. It was regenerated from retained
package contents; this checkpoint is not a manifest member.

Required regressions on r3 all exit0 with that external digest: selftest.py
(6/6), tests/self_check.py (5/5), tests/cleanup.py (5/5). Logs and consolidated
JSON use prefix sweep/sol3-final-r3-20261106T2250Z-{selftest,self_check,cleanup}.txt
and -regressions.json. Earlier regression/assembly logs are retained as well.
No operator bundle or official Node artifact was qualified: development Node
provenance remains UNQUALIFIED_LOCAL_EXECUTABLE.

### Proposed v4 diff — review before any freeze

Proposal: ~/.local/state/kernel/sandbox-v4-proposal.diff.
Rationale: ~/.local/state/kernel/sandbox-v4-proposal-rationale.txt.
Input/proposal hashes: ~/.local/state/kernel/sandbox-v4-proposal-receipt.json.
Proposal SHA-256:
`919e37c6d6e0e92ec7a06723a68ace1d4ecb3e79ae67ca29f74276bd2c17c66d`.

The proposal fixes both strict (a) seams, documents explicit host prerequisites,
propagates the narrow missing diagnostic positive-control condition as
Unavailable (never a pass), updates v4 metadata and makes the cost helper write
a fresh v4 report exclusively. It preserves all 201 cases/388 modes, operations,
expected verdicts, assertion IDs, scope, timeouts and baseline witness logic.
The helper uses receipt claims for unavailability propagation before full
identity validation, never to certify a pass. Host/implementation classification
still requires the human/source/raw evidence described above.
Read-only git apply --check and independent Terra review passed. It was NOT
applied, frozen or used for any of the sweep results above.

Three passing-case coverage observations are separately documented in the
rationale for reviewer disposition before the single v4 freeze: the actual temp
alias differs from literal /tmp on the current temp root; supervisor death is
currently prelaunch; and two lifecycle faults substitute group_child for the
matrix timeout operation. These are not hidden as unconditional (a) failures or
claimed covered by existing passes. Amend the same proposal before freezing if
stronger controls are selected; no additional freeze was created here.

Next owner action is reviewer disposition of this proposal and remaining host
availability evidence. Only after explicit approval: freeze v4 on the reviewed
old-subject lineage, obtain meaningful baseline RED, then port implementation and
run full qualifying evidence. No v4 freeze, main/next push, sudo, network
configuration by Sol, operator provisioning, installation or desk prove occurred.
Branch is pushed in-review and this run stops for proposal review.
