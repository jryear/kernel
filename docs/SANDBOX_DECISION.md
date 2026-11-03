# Kernel 3.2.0 sandbox decision

Decision date: 2026-11-03. Authority: Zack's visiting-architect run of that date.
Status: architectural decision for implementation and review; no implementation,
new security experiment, integration approval, or release approval in this run.

## Decision and evidence boundary

Use **srt 0.0.81 as an embedded library in a trusted Node supervisor**, launched
by the external Python verifier. Start with opt-in sandboxing on macOS. Treat
confinement, protected-path integrity, assertion evidence, process cleanup, and
diagnostic denial logs as separate observations. No complete attempted-operation
ledger is available. Do not promise one or make absence of log events a pass.

The binding source is `origin/main:.desk/plan.toml`, instruction_version 3, at
`a29e8e5fdcc5db10665acfb98ffc757854819db2`. Its release and verdict rules supersede
the checkpoint's instruction_version 2. Remote heads were checked against these
local references during this decision:

| Evidence | Revision / location | Consequence for this decision |
| --- | --- | --- |
| Sandbox spike and checkpoint | `ce934f91cd39a8c83cf01f7c5769b88b4cffa71d`; [checkpoint](../CHECKPOINT-tranche-1.md), [findings](../spike/FINDINGS.md), [probe](../spike/sandbox_probe.py), [library driver](../spike/library_probe.mjs), [payload](../spike/payload.py) | Research completion is not a security verdict. Both wrappers confined the exercised operations; neither collector had a ready acknowledgement. |
| Raw observations | [observations.json](../spike/evidence/observations.json), SHA-256 `0bd040fd58c482acd123601e5fdb3b59614115f30f7736f0d6268421b94e019e` | Embedded burst: 150 EPERM outcomes, 148 matching events. Subscription saw 221 events overall; store retained 100. Synthetic store test separately retained 100 of 150. |
| CLI collector | [cli-collector.log](../spike/evidence/cli-collector.log), SHA-256 `fd28eeea37fc4153a77eeb5947196c55da75dbeca97f75ee95569efc4e36bfbb` | First CLI canary returned EPERM without a matching event. Later burst and delayed-child events do not repair that gap. |
| Proven self-check diff from `d5534ae3b23a2affe01dc99ded5c8783f094c6eb` | `origin/kernel/self-check` at `2da4b773cfb0bf4606d45082e954964671aa0767` | Authenticate the manifest with an external expected digest before helper imports; refusal is exit 3 with no verdict. The entrypoint still requires external authentication. |
| Proven cleanup diff from the same base | `origin/kernel/cleanup` at `9de19fcae4e84702dfeec07a3a0299042de8c333` | Preserve per-check process groups, survivor identities and incomplete-evidence precedence. Detection is sampled observation, not exhaustive containment. |
| Existing execution and protocol | [verify.py](../verify.py), [kernel_runtime.py](../kernel_runtime.py), [kernel_report.py](../kernel_report.py), [FRONTIER.md](../FRONTIER.md), at spike HEAD | Schema 2 uses committed snapshots and complete terminal assertion sets. Current snapshot integrity errors are undifferentiated strings; current result files are child-writable. Neither is already a trusted sandbox receipt. |

The spike's 700 ms startup delay and two-second drain are observation windows,
not readiness or completeness proofs. Its network result is a loopback success
and a non-allowlisted loopback proxy 403. It is not external-egress acceptance or
proof of restriction to individual localhost ports. The late embedded case grew
from 11 to 17 events after leader exit. These facts are accepted, not rerun here.
The independently proven branches remain prerequisites to the combined tree;
this decision does not certify the integration currently in progress.

## Mechanism, dependencies, and trust ownership

The Python verifier remains standard-library Python code, but **sandboxed kernel
execution is no longer a Python-only installation**. Its trusted computing base
includes the Node runtime, supervisor, srt and its transitive packages, OS sandbox
facilities, and the existing Python/Git/process-observation tools. Document that
dependency explicitly in installation instructions and receipts.

Pin srt to exactly `0.0.81` and the complete transitive lockfile, initially the
versions in [spike/package-lock.json](../spike/package-lock.json). Pin the qualified
Node executable and its release artifact digest; Node `v24.22.0` is the initial
qualification target reported in the checkpoint, not an assertion that every
Node version allowed by srt's `>=22.12.0` engine range is qualified. Record the OS
build/architecture and Python version. An upgrade to any enforcement component
requires renewed sandbox qualification. Do not resolve `latest`, run `npx`,
install packages, or fetch a dependency during verification.

Place the supervisor, locked srt installation and Node runtime in an
operator-managed versioned bundle outside the caller repository, snapshots,
linked dependencies and every candidate-writable root. An installation layout
such as `<trusted-runtime-root>/kernel-sandbox/0.0.81/<bundle-digest>/` is suitable;
`spike/node_modules`, project `node_modules`, and an ordinary writable global npm
installation are not product locations. Authenticate bundle contents from a
caller-held release receipt before loading them. Cover the supervisor and bundle
digest binding in the kernel release manifest. Resolve absolute executables and
imports from this bundle, with no candidate-controlled module search or loader
options. Do not inherit `NODE_OPTIONS`, `NODE_PATH`, Python import injection,
proxy overrides, credentials, or arbitrary executable search paths into the
trusted supervisor. The candidate environment is a separate, explicit input.

Candidate sandbox policy must deny writes to the bundle, its ancestors and
resolved targets. Provisioning must also place it outside the implementation
agent's write authority before execution; a read-only chmod owned by that same
agent is not sufficient. This is an operator trust prerequisite, not something
startup self-check can manufacture. An arbitrary unsandboxed process with the
same host authority, or a compromised OS, remains outside this assurance.

The trusted Python parent owns policy validation, release authentication,
snapshot/protected inventories, final verdict and final receipt. The Node
supervisor owns srt initialization, wrapping and diagnostics. Only the check
process and its descendants enter the sandbox. Both trusted processes remain
outside it; neither loads candidate modules or executes candidate setup hooks.
Use a distinct supervisor/session per check and repeat, with separate run IDs,
scratch, diagnostics and result channels. No persistent candidate-writable state
may carry into the next check or repetition.

Preserve the cleanup branch's process-group boundary around the **actual wrapped
check**, not merely around the trusted supervisor. The parent must be able to
time out and clean up a check if the supervisor dies. Supervisor/proxy/collector
termination is also required before finalization. Surviving or unobservable
processes make the run unverifiable even if later remediation kills them.

Subscribe before initialization, enable the library monitor when diagnostic
logging is requested, and persist received events outside the sandbox instead
of polling the 100-event tail. Bound the spool and drain; record limits and loss.
A preflight probe under the same effective policy must demonstrate a denied
synthetic protected write and a successful scratch write through a reviewed
probe's operation results, independently of denial logs. It must not touch the
installed judge. A canary log, if received, proves only that one event arrived.
No handshake, sleep, subscription count or quiet drain proves all events arrived.

Diagnostic logging defaults to disabled; the trusted caller may request it before
the run. This never disables sandbox enforcement. Disabled logging is a supported,
explicitly recorded mode. Do not silently switch to it after collector failure.
With logging enabled, detected failure, delivery gaps, ambiguous relevant attribution or
spool loss invalidate that invocation conservatively; logging remains incapable
of establishing contradiction or certification by itself. Routine srt system
denials seen in the spike (for example `sysctl-read` and disk-space queries) are
diagnostics, not automatically failed contract assertions.

Reject srt CLI as the product interface: it has no built-in monitor in this
version and would require a second collector/lifecycle protocol. It buys no
stronger evidence. Do not build a standalone Seatbelt backend for 3.2.0: that
would transfer profile and compatibility ownership to the kernel without
closing the demonstrated log gap. srt remains the selected macOS enforcement
backend. If the required policy cannot be expressed and proven with this pinned
backend, fail closed and return to architecture review; do not silently broaden
policy, fall back to CLI, or run unconstrained. Linux and a VM backend are not
qualified by this evidence.

Run every external judge invocation with `python3 -B`, and propagate
`PYTHONDONTWRITEBYTECODE=1` to nested Python processes. The checkpoint's bytecode
writes are actual judge-side writes. Do not misattribute them to the candidate,
delete their evidence, or call a package unchanged because its tracked files
alone match. Disable or redirect judge caches into supervisor-owned scratch and
inventory the installed judge directory before and after acceptance runs.

## Verdict rules

The following table describes the event's classification when reliably observed.
It does not assume the verifier can observe every event. A refusal before judging
is distinct from a verdict: invalid contracts and release-authentication failures
remain exit 3 with no verdict; an authenticated judge unable to establish the
requested sandbox execution returns unverifiable (exit 2).

| Event class | Available evidence and meaning | Classification |
| --- | --- | --- |
| Protected-path hash change | Trusted before/after inventory establishes a lasting forbidden change to the same protected object set. Include bytes, types, modes, symlink targets, existence and added/deleted entries. | **Contradicted** (exit 1) when the measurement is reliable and no independent evidence failure overrides it. Record the effect, not an accusation of intent. An unreadable/incomplete inventory, an expected supervisor write mistakenly included, or ambiguous path identity is **unverifiable**. |
| Denied protected write with a log event | A denial reports an attempted operation. srt attribution and completeness are not execution attestation; unchanged hashes establish only no lasting difference at boundaries. | **Unverifiable** for an affected check whose observed operation was denied. Do not infer tampering intent or turn this into a deterministic protected-change contradiction. The event explains the failure. |
| Denied protected write without a log event | A reviewed harness can report EPERM or fail to produce its complete assertion result. Hashes may remain unchanged. There is no guaranteed independent attempt signal. | **Unverifiable** if the denial/failure is observed through that execution evidence. Do not infer a protected write from generic exit 1, nor a successful run from unchanged hashes. If the operation is caught and hidden and all other evidence is identical to a clean run, the verifier cannot classify the unseen attempt; see the limitation below. |
| Denied undeclared network | A policy/proxy refusal or trusted harness operation failure establishes an unavailable environmental dependency. | **Unverifiable**, even with a diagnostic event. An undeclared destination is not evidence of malicious intent. A fixture intentionally testing denial is assessed by its own declared assertion, as explained below. |
| Denied cache write | A failed cache operation is an environmental mismatch, including a cache under a read-only dependency or source tree. | **Unverifiable** when it affects the check or is observed as a relevant unexpected denial; never call it tampering merely because its path is protected. Disable/redirect caches. A permitted cache write to declared scratch is not a violation. |
| Survivor process | Cleanup names an observed escaped descendant or a process still alive after group cleanup. | **Unverifiable**, including when subsequent remediation succeeds. Preserve PID, PGID, start identity and reason. No survivor observed is not proof of exhaustive containment. |
| Collector failure or overflow | Enabled collector exits unexpectedly, expected canary event is missing, observed delivery gap, subscription loses events, spool fills, or relevant event attribution is ambiguous. | **Unverifiable**; retain the evidence and reason, never retry into supported. The normal 100-event store rollover is not itself a failure if every emitted event was persisted by the subscription. Upstream completeness remains unknown regardless. Intentionally disabled logging is a different declared state, not a collector failure. |

Preserve the proven cleanup branch's aggregation order: **unverifiable precedes
contradicted, which precedes supported**. A deterministic protected change is
still recorded as a contradiction fact when a survivor, missing receipt or other
evidence failure forces the overall verdict to unverifiable. Do not discard it.
This avoids reverting the cleanup branch while giving the plan's protected-change
rule an explicit typed observation. Replace the current catch-all integrity-error
string with a distinction between measured forbidden change and unavailable
measurement when sandbox is implemented. On a baseline run, unavailable evidence
means BASELINE_NOT_READY, never useful RED.

An ordinary complete, trustworthy failed behavioral assertion remains
contradicted under the existing schema-2 contract. An operation denied during
setup, a missing import, timeout, invalid receipt or unavailable environment is
not such an assertion. The frozen harness must preserve that distinction; the
verifier cannot recover it reliably from arbitrary output text.

**Expected-denial tests have two levels.** A tamper-suite assertion can pass by
observing that its nested candidate was denied and returned unverifiable. That
supports the outer sandbox contract; it does not make the nested candidate
supported or contradicted. A reviewed check whose explicit subject is a denied
operation can likewise pass its declared denial assertion. No blanket rule may
convert every OS denial, including expected canaries, into a failing outer suite.

**Unobserved attempts remain unobserved.** With logs disabled, a payload may catch
EPERM and return a valid result indistinguishable from one with no attempt. Even
enabled logs can miss that attempt. The kernel cannot promise that such payloads
always receive unverifiable without making all executions unverifiable. A
supported verdict is possible only for the bounded frozen behavioral claim and
observed integrity/cleanup checks; it says nothing about absence of attempted
writes or reads. If a contract requires proof of no attempts or no transient
tampering, that claim is unverifiable with this architecture. Do not advertise
3.2.0 as a complete tamper-attempt detector.

## Receipts and protected evidence

Retain schema-2 source bindings, frozen contract hash, exact assertion IDs,
baseline failures and observed results. Add a versioned sandbox receipt owned by
the trusted parent, with these fields/semantics (names may be implemented as a
documented versioned schema):

| Record | Required content |
| --- | --- |
| Identity and provenance | Run/check/repetition/phase IDs, base and candidate commits and manifests, kernel release digest and its caller-supplied source, supervisor/bundle/lockfile digests, absolute runtime identities, versions, OS build and architecture. |
| Effective policy | Frozen declaration, normalized resolved writable roots and localhost endpoint tuples, immutable protected inventory, secret-read denials, effective backend policy digest and exceptions required by the runtime. Record sandbox requested/enforced/failed separately from diagnostics enabled/disabled/failed. |
| Lifecycle | Preflight operation results, initialize/start/exit/cleanup/drain timestamps, check PID/PGID/start identity, exit/signal/timeout, startup and supervisor errors, exact observation boundary. No `collector_ready=true` invented from a delay. |
| Integrity | Before/after manifest digests plus a retained per-path inventory and differences; missing/unreadable entries and observation errors; judge directory before/after; active receipt prefix and trusted writes accounted separately. |
| Assertions and cleanup | Full validated provisional assertion result, its hash, complete IDs, exit consistency, cleanup.complete/timed_out/observed/survivors/errors from the proven implementation, including remediation outcomes. |
| Diagnostic quality | Logging mode, subscription/collector start, canary operation and event outcomes separately, received/retained/persisted/dropped counts where measurable, unknown upstream loss explicitly unknown, spool capacity, drain deadline, raw-event artifact hash and attribution confidence. |
| Decision | Typed facts and their sources, unavailable reasons, deterministic contradictions, final aggregate verdict and precedence, and explicit assurance limitations. |

The final claim log, diagnostic spool, contracts, fixtures, judge, bundle, source
snapshots, caller tree and both worktree and common Git metadata are outside the
candidate's write authority. Protect `.git` indirection targets, not just the
worktree's `.git` file. Keep trusted artifacts under non-replaceable protected
ancestors; resolve aliases and reject writable overlaps before launch.

The existing `VERIFY_RESULT_JSON` file is **provisional child output**, not the
protected final claim log. Give the check an exact per-invocation result slot in
its own disposable output area, then capture/validate it after process cleanup
and copy its bytes/hash into the parent-owned receipt. Do not grant write access
to the final log or its parent merely to preserve this protocol. Candidate stdout
is also untrusted data captured by a parent-owned stream. A valid result remains
a reviewed-harness assumption, not semantic execution attestation; importing
candidate code in that harness does not magically authenticate its assertions.

Hash stable protected files before launch and after cleanup/drain, with an
additional final observation before receipt publication. For append-only logs,
freeze and hash the prior prefix; account for the supervisor's own append
separately. Do not classify an expected trusted append as a candidate change.
Inventory errors or failure to persist the final receipt cannot yield supported.
Do not retain raw environment dumps, proxy credentials or secret contents.

Explicitly do not claim: no write attempt; no write followed by restoration; no
secret read from matching hashes; complete or correctly attributed OS logs;
absence of hostile escaped processes from sampling; semantic honesty of an
assertion reporter; hermetic external runtimes; universal macOS/Linux coverage;
production readiness, independent review, or authorization to deploy. A
successful preflight and matching endpoint hashes do not discharge these limits.

## Contract policy surface and defaults

Add a narrow optional `[sandbox]` table to newly frozen schema-2 contract versions.
The absence of that table means these defaults when sandbox execution is selected:

```toml
[sandbox]
writable_paths = []
localhost_ports = []
```

These are proposed contract fields, not fields the current parser already accepts.
`scope.include` remains source-edit scope; it must never imply runtime write
permission. The kernel's release/operator selects sandbox enforcement and
diagnostic logging. A contract cannot disable confinement, permit protected writes,
request arbitrary raw srt/Seatbelt settings, or weaken kernel evidence rules.

`writable_paths` declares literal relative **output directory roots** in each
disposable snapshot, such as `build-output` or `.cache`. Default grants are only
the kernel-created per-check scratch/home/temp/cache directories and provisional
result slot; the caller tree, tracked source and external dependency links stay
read-only. Additional paths must be untracked output roots with committed ignore
rules, disjoint from protected/tracked files and dependencies. Reject absolute
paths, `..`, wildcards, symlinks/aliases to protected objects, and grants to a
protected path's ancestor. Resolve `/tmp` versus `/private/tmp`, existing ancestor
links and case aliases before launch. Confinement must still block links created
after validation; a string-prefix check is not an enforcement boundary.

Set HOME, TMPDIR and supported cache variables to fresh per-check locations; set
Python's no-bytecode environment. Do not grant all of `/tmp`, the real home,
repository, or shared package caches for convenience. Missing preinstalled
dependencies are unverifiable, not permission to install them during a check.
The trusted bundle and ordinary external tool installations are never contract
writable paths. Explicitly deny reads of real `~/.ssh`, credential stores and
secret `.env` inputs resolved by the operator's fixed policy; use synthetic
fixtures in tests. HOME redirection alone does not deny an absolute secret path.
This is not a claim to enumerate every possible host secret.

`localhost_ports` is a unique list of integers 1..65535, default empty. In 3.2.0,
each port grants TCP connection and loopback binding only at `127.0.0.1` and `::1`
for that port; `localhost` must resolve only to those identities. No wildcard
binding, alternate 127/8 addresses, UDP, external DNS/egress, arbitrary domain
allowlists or Unix sockets are granted by this field. Runtime-required internal
IPC must be separately enumerated by trusted policy, not inherited as a general
host-service escape. A declared port also permits contact with a service on that
port: use isolated fixtures or an explicitly reviewed caller-owned service; it
is not proof of server identity or an authorization to use production services.

**Exact ports are a sandbox acceptance gate.** The spike configured hostname
allowlisting and `allowLocalBinding=true`, not these semantics. The selected
backend must prove both direct-socket and proxy paths cannot reach undeclared
ports/destinations or bind non-loopback interfaces. Do not translate a finite
port list into unrestricted localhost access. If srt 0.0.81 cannot implement the
restriction, a valid requested policy is unavailable and returns unverifiable
without executing the check; the sandbox item cannot be accepted until that
capability is resolved or a new architectural decision changes the surface.

Malformed or impermissible declarations are SPEC_ERROR (exit 3) before execution.
Unsupported platforms/backends or missing execution dependencies are unverifiable
after release authentication, never an automatic unsandboxed fallback. Keep
legacy schema-1 behavior visibly legacy during opt-in development; do not certify
its unconstrained setup/service commands as sandboxed. A request to sandbox such
unsupported lifecycle commands fails closed. Real contracts needing migration
must be versioned and frozen anew, not edited in place or silently downgraded.

## Required sandbox acceptance suite

Freeze the reviewed `tests/tamper_suite.py`, complete helper chain, fixtures and
schema-2 acceptance contract **before implementation**. Use the installed 3.1.0
as the external judge with `python3 -B`; all copies of the judge under attack are
disposable fixtures. The real judge, frozen inputs and result logs remain outside
candidate authority. Obtain meaningful named RED against 3.1.0 and GREEN against
the integrated candidate. An unknown CLI option, missing Node, harness crash or
missing result is not new-feature RED. Tests that already pass in 3.1.0 are
regressions; declare the exact new failing assertion IDs rather than pretending
every negative case is novel.

Run the relevant matrix with diagnostic logging enabled **and deliberately
disabled**, keeping enforcement identical. Use deterministic collector fault
injection for classifier tests; do not require a naturally lossy OS stream to
reproduce an exact 148/150 count. All verdicts below refer to nested verification;
the outer suite passes only when it observes the specified result and effects.

| Cases | Required evidence and expected result |
| --- | --- |
| Clean control; declared scratch/cache/output | Complete real assertion set, expected base RED, successful allowed writes, matching protected inventories, complete cleanup: **supported**, including logging disabled. Also prove installed judge directory unchanged with `-B`. |
| Rewrite final claim log; edit disposable verifier/runtime/manifest; edit frozen contract, chain or fixture; write snapshot `.git` and resolved common Git directory; replace pinned srt/supervisor/Node | Each operation denied by enforcement. An observable denied-operation/setup failure yields **unverifiable**, with and without diagnostic events; protected artifacts unchanged. Test existing file writes, creation, deletion, rename, chmod and parent replacement. Attack a disposable bundle, never the installed judge. |
| Lasting protected change under controlled boundary-failure injection | Reliable independent before/after inventory and otherwise complete execution evidence: **contradicted** in both logging modes. Remove/replace/add a file as well as change bytes. This tests effect classification, not proof that the sandbox allowed a real escape. |
| Same protected change plus survivor, timeout, missing result, collector loss or unavailable hash | **Unverifiable** overall; retain the deterministic change fact when measurable. Hash-read failure alone must not be mislabeled a change. |
| Write then restore; delete then recreate; symlink/hardlink/ancestor alias from allowed output to protected target | Under real confinement, independent synthetic operation results must show denial. Observed unexpected denials: **unverifiable**. A comparator-only write/restore fixture ends with equal hashes and must not be labeled detected tampering; with explicit missing/ambiguous execution evidence it is **unverifiable**. A swallowed unobserved denial can be indistinguishable from the clean control: the suite must verify the limited receipt claim, not demand imaginary attempt detection. |
| Read synthetic SSH key and synthetic secret `.env`, including absolute and alias paths | Reviewed operation result establishes denial; affected ordinary nested check **unverifiable**. Equal hashes are never read-denial evidence. Include logging disabled and an expected-denial outer assertion. Do not read real secret contents. |
| Undeclared network, no-network default, wrong localhost port, alternate loopback address, IPv6, direct sockets, proxy requests/CONNECT, non-loopback bind | Independent controlled listener/operation evidence, with reachable positive controls, proves prohibited connections/binds denied; affected nested check **unverifiable**. Exact declared ports succeed and permit **supported** controls. If exact policy cannot be enforced, **unverifiable before check launch** and sandbox acceptance remains failed. |
| External egress refusal | A separately authorized controlled endpoint or isolated network fixture with a reachable unsandboxed positive control must establish denial without relying solely on missing traffic or logs. Refusal gives nested **unverifiable**; an unauthorized/untested external route is missing acceptance proof, not a pass borrowed from the loopback spike. |
| Cache beside source/dependency or judge; allowed redirected cache | Unexpected denied cache write: **unverifiable**, not tampering. Redirected cache succeeds; clean nested run **supported**. Judge-side cache creation is a judge/environment failure; retain attribution rather than blaming the candidate. |
| Child in group, setsid escape, timeout, kill/ps failure, supervisor death | Preserve the proven cleanup cases: group child dead with complete evidence permits **supported**; named escape, timeout, kill/observation failure or supervisor death is **unverifiable** even if assertions passed. Repeat with logging disabled. |
| First canary without event; >100 events; known dropped subscription events; spool overflow; collector death; ambiguous ID; delayed event after leader exit | Enabled logging with known gaps/failure/ambiguous relevant attribution: **unverifiable**. Persisted subscription events exceeding the store tail alone do not fail. Exercise drain timeout and ensure finalization follows cleanup. A late event must not contaminate another invocation. No test may equate a quiet drain with complete logs. |
| Disabled logging control | Record `disabled`, no collector readiness/completeness claim. All non-log evidence classifications above remain intact; a protected change is still **contradicted** with complete evidence, observed failed denied operations remain **unverifiable**, clean bounded claims can still be **supported**. |
| Missing/wrong Node, missing sandbox facility, altered bundle, writable bundle path, path-policy conflict | Missing execution dependency/facility or unavailable capability: **unverifiable**, no unconstrained execution. Authenticated release/bundle mismatch: startup refusal exit 3, no verdict. Unsafe/invalid contract grant: exit 3. No download or fallback. |
| Result/log forgery and stale replay | Attempts to modify the protected final receipt path are denied. Wrong run/phase/check ID, missing/duplicate assertions, inconsistent exit or malformed provisional result: **unverifiable**. Valid-looking fabricated results remain the documented reviewed-harness limitation, not a newly proven attestation mechanism. |
| Sequential checks/repeats | Unique identities and fresh scratch; no prior result replay, late-log reassignment, persistent proxy or candidate file carrying authority into the next run. Missing isolation/cleanup evidence: **unverifiable**. |

The effect probes, classifier injections and positive controls are all necessary:
unverifiable alone does not prove confinement. The outer suite must fail if a
forbidden operation succeeds even when the nested verifier returns unverifiable.
Do not claim exhaustive descendant containment or complete log delivery from any
finite matrix. No implementation tests or spike reruns are performed by this
decision-only run.

## Consequences for remaining work

`sandbox` stays opt-in, after the integrated self-check/cleanup proof and spike.
Its definition of done becomes the matrix above, exact policy enforcement and
external dependency packaging. The slogan “agents can't edit the rules” means
enforced write authority under the stated trust assumptions; it does not mean
all attempts are detected. The existing logging-disabled requirement is retained
with achievable, explicitly bounded verdict expectations.

`flake` must repeat the entire sandbox/check/cleanup protocol with fresh state
under a schedule frozen before observing results. Record every seed, repetition
and outcome. Any unavailable repetition or quarantine makes the aggregate
unverifiable. Mixed pass/fail results are unstable and unverifiable; consistently
failed named assertions with complete evidence remain contradicted. Supported
requires every required repetition to pass. A later green cannot erase any prior
failure or relax a timeout, policy, repetition count or quarantine decision.

`mutants` must use that same effective sandbox and frozen repeat policy. Only the
specified assertion failure under complete execution evidence kills a mutant.
Denied cache/network access, missing dependencies, timeout, crash, survivor or
invalid result cannot count as a kill, even if its process exited nonzero. Bind
mutant identity, source, expected assertion, observed set and each repetition.
Mutants passing instead of failing are survivors of the mutation test; they are
distinct from OS process survivors. Neither a kill score nor a red-team run proves
contract completeness. Keep `red-team` and its new-version freeze requirement.

`default-on` requires the sandbox suite and repeat policy on the exact combined
candidate, plus genuine supported receipts for BidZizi `preview-001` and
`photos-001` with narrow declared outputs/ports. Do not weaken assertions or grant
the entire repository/home to get green. If migration is necessary, retain the
original contracts and freeze reviewed successors with new baseline evidence.
Until then sandbox remains opt-in; an unavailable backend never falls back.

`bidzizi-gate` exercises the actual caller entrypoint against the staged,
authenticated final 3.2.0 package and caller-held digest before switching the
installed judge. Verify missing/wrong digest refusal and missing dependency
failure as well as the successful real invocation. Computing an expected digest
from whatever package happens to be present is not caller authentication.

`release` reruns combined frozen-contract evidence under installed 3.1.0 and the
existing regression baseline; publishes the kernel manifest, external bundle
binding, tag digest, installation receipt and accurate limits. Recheck real
invocations if final package bytes change after their proof. The default-on
implementation is not permission to switch the installation early. Keep the
SWE-bench comparison scoped to what was measured. Update the Python-only claim,
legacy-service limitation, macOS qualification and log/attempt limits. Never
describe the six old self-tests or a checksum command alone as evidence of the
new guarantee. The architect stops after this document and branch delivery.

## Proposed plan changes — exact TOML for the planner

The planner should replace the `[project]` header and the six matching `[[item]]`
blocks below, not append duplicate IDs. Leave `self-check`, `cleanup`,
`sandbox-spike`, `integrate-1`, and `red-team` intact. The new dependencies mean
merged completion under Desk semantics; `integrate-1` keeps its deliberately
empty dependency list. The instruction-version bump makes the new acceptance
boundary explicit. This is a proposal; this run does not edit `.desk/`.

```toml
[project]
name = "kernel"
outcome = "verify.py becomes a production gate: checks run sandboxed, the verifier refuses to run when tampered with, flaky checks can lower confidence but never certify, and a contract must reject known-wrong implementations before it can be frozen."
main = "main"
instruction_version = 4
# Release rule: the installed release judges the next one.
# - 3.2.0 is built in a separate worktree. ~/code/_kernel stays on installed 3.1.0, read-only until release gates pass.
# - Freeze each item's complete tests/fixtures first; named new assertions must FAIL against 3.1.0 and PASS on the candidate.
# - The six existing self-tests are regressions, not evidence for new guarantees. Setup/CLI errors are not RED.
# - Judge, frozen contracts/fixtures, final logs, expected digest and pinned sandbox bundle stay outside candidate write authority.
# - Judge invocations use python3 -B and nested Python uses PYTHONDONTWRITEBYTECODE=1; inventory the judge directory before/after.
# Verdict rule: docs/SANDBOX_DECISION.md is the sandbox acceptance boundary.
# - contradicted: reliably measured deterministic forbidden effect or complete failed behavioral assertion; denial is not intent.
# - unverifiable: environment failures, survivors, incomplete execution/cleanup, enabled collector failure/loss, ambiguous/missing evidence.
# - Aggregate precedence is unverifiable, then contradicted, then supported; retain deterministic change facts even when overridden.
# - Hashes prove lasting differences at observed boundaries only, never no attempts, no restored writes, or read denial.
# - Logs are diagnostic and incomplete. Intentional logging-disabled mode is distinct from collector failure; no silent fallback.
# - Supported is bounded contract evidence, not proof of no attempts or hostile-process containment.

[[item]]
id = "sandbox"
title = "Opt-in sandbox: pinned embedded srt under a trusted supervisor; exact write/localhost policy, external receipts and typed integrity evidence"
mandate = "Zack, 2026-11-03; architecture in docs/SANDBOX_DECISION.md. Freeze the full tamper matrix before implementation. Pin srt 0.0.81, transitive lock and qualified Node artifact outside candidate authority. Preserve integrated self-check/cleanup. Prove exact ports and path confinement; unsupported policy fails closed. Logs cannot prove intent or completeness."
depends = ["integrate-1", "sandbox-spike"]
acceptance = [["python3", "-B", "tests/tamper_suite.py"]]
# Test observed denials -> unverifiable; reliable lasting protected changes -> contradicted unless independent evidence is unavailable.
# Repeat with logging disabled; clean bounded controls may be supported. Never claim detection of swallowed invisible attempts.
# Prove effects independently of nested verdicts, including reads, direct/proxy network, aliases, cache, receipts, bundle and judge integrity.
# Enabled collector loss/failure and all incomplete cleanup remain unverifiable. No unconstrained fallback or runtime installation.

[[item]]
id = "flake"
title = "Frozen repetition schedule over fresh sandbox invocations; all required repetitions must pass to certify"
mandate = "Zack, 2026-11-03. Freeze seeds, count and timeout handling before measurement. Record every repetition and fresh-state/cleanup evidence. Unavailable or quarantined repetitions and mixed pass/fail outcomes are unverifiable; a later green never erases prior evidence."
depends = ["sandbox"]
acceptance = [["python3", "-B", "tests/flake_policy.py"]]

[[item]]
id = "mutants"
title = "Known-wrong implementations run under the same sandbox and repeat policy; only the named assertion failure counts as a kill"
mandate = "Zack, 2026-11-03. Bind mutant source/identity, expected and observed failed assertions, policy and every repetition. Cache/network denial, setup failure, crash, timeout, missing receipt, collector failure and process survivors never count as kills. Kills do not prove contract completeness."
depends = ["sandbox", "flake"]
acceptance = [["python3", "-B", "tests/mutants.py"]]

[[item]]
id = "default-on"
title = "Enable sandbox by default only after preview-001 and photos-001 are supported on the exact combined candidate with declared outputs/ports"
mandate = "Zack, 2026-11-03. Preserve real assertions and narrow authority. Version and refreeze any required contract migration; no in-place edits. Require complete repetitions and cleanup, record backend/policy/bundle identity, and leave opt-in until both real contracts pass. Unsupported backends never run unsandboxed implicitly."
depends = ["sandbox", "flake"]
acceptance = [["python3", "-B", "tests/tamper_suite.py"], ["python3", "-B", "tests/flake_policy.py"], ["python3", "-B", "tests/real_contracts_sandboxed.py"]]

[[item]]
id = "bidzizi-gate"
title = "Exercise BidZizi's actual invocation against authenticated final 3.2.0 package and caller-held digest before installation switches"
mandate = "Zack, 2026-11-03. Prove actual successful calls plus missing/wrong digest refusal and missing sandbox dependency failure. Use python3 -B; bind exact package/bundle/policy/contract identities. No locally derived untrusted expected digest or implicit fallback. Any later package change invalidates this proof until rerun."
depends = ["default-on"]
acceptance = [["python3", "-B", "tests/bidzizi_invocation.py"]]

[[item]]
id = "release"
title = "Release 3.2.0 only from final combined evidence: external judge, real caller proof, manifest/bundle digest, tag and install receipt"
mandate = "Zack, 2026-11-03. Rejudge all frozen new-feature contracts with installed 3.1.0 using python3 -B; retain exact RED/GREEN and regression evidence. Recheck real caller proof against final bytes. Publish external dependency and platform qualification, accurate log/hash/cleanup limits, release digest and SWE-bench comparison before the authorized installation switch."
depends = ["bidzizi-gate", "red-team"]
acceptance = [["shasum", "-a", "256", "-c", "MANIFEST.sha256"], ["python3", "-B", "tests/self_check.py"], ["python3", "-B", "tests/cleanup.py"], ["python3", "-B", "tests/tamper_suite.py"], ["python3", "-B", "tests/flake_policy.py"], ["python3", "-B", "tests/mutants.py"], ["python3", "-B", "tests/red_team_freeze.py"], ["python3", "-B", "tests/real_contracts_sandboxed.py"], ["python3", "-B", "tests/bidzizi_invocation.py"], ["python3", "-B", "selftest.py"]]
# Acceptance commands supplement, never replace, the external 3.1.0 frozen-contract receipts.
# Release/bundle authentication uses caller-held trusted digests; regenerate manifest from final contents before final proof.
```
