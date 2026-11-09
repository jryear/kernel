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

## Amendment 2026-11-06: exact loopback ports via pinned srt patch

Authority: Zack, 2026-11-06, **"patch srt"**. Decision: retain embedded srt
0.0.81 under the trusted Node supervisor, with a reviewed, versioned distribution
patch for exact TCP ports. Patch the installed **dist JS during bundle assembly**;
do not rewrite generated profiles in the supervisor. This amendment authorizes
that design, not an implementation, provisioned bundle, qualification or release.
Earlier sections remain as historical decisions. Where they conflict, this
amendment supersedes their loopback-only binding claim and unmodified-backend
restriction. Plan v6 at `origin/next`
`bf9ed3d66a7dd74a08d103269e412da76bb3a073` is the current plan, including its
separate off-machine egress gate; the earlier plan-v3/v4 references are historical.

### Evidence and scope of the decision

Read the "Sandbox v2 implementation" checkpoint at
`origin/kernel/sandbox-v2`, `39a419c97b1271ab1ba08b9dfab948e7665456da`
(partial implementation source `8ac441052002709f25d17504ced5fbc979cf9a85`).
Both remote heads above were checked on this date. The checkpoint correctly
stopped: the unmodified backend probe's `allowLocalBinding=false` denied declared
and undeclared direct TCP and wildcard bind; `true` allowed all three. Its
`allowedDomains` setting did not restrict direct sockets.

The local evidence is under `~/.local/state/kernel/`:

| Artifact | SHA-256 |
| --- | --- |
| `sandbox-v2-backend-policy-probe.json` | `5002c74962a202e38170eed7195b9162827efadab36cfe0732e01fa1a39238db` |
| `sandbox-v2-backend-policy-probe.mjs` | `25b8bf6d571ef1030f2dcd9f60fc061b405740f4388ca8ed7c4de052298cca84` |
| `sandbox-v2-backend-policy-probe.txt` | `db428c8022c43b82d548330c43a10ec39b04ff0e667e8efbc0c08a5f592c3ded` |
| `dev-bundle/node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js` | `7f297d6acb08a44adc9198876a38ce49ffa59e3a7aa09692933b3e008b446a32` |

In that source, lines 951–954 emit wildcard bind/inbound and all-port localhost
outbound; lines 982–992 demonstrate exact-port profile generation for proxies.
The comment beginning at line 931 explains the mapped-address compatibility
problem and why a local-address filter must not authorize outbound connections.
These are source facts, not proof of identical behavior on every OS build.

### Patch specification and smaller trusted surface

Name the first patch revision `kernel-srt-0.0.81-exact-tcp-v1`. Add a private,
validated `kernelLocalhostPorts` array to the embedded configuration path and
thread it to the existing macOS profile generator. Only the trusted supervisor
constructs that input from the validated contract's `localhost_ports`: unique
integers 1..65535, sorted, default empty. No candidate-supplied srt flags, profile
text, environment variables or imports may provide it. Reject the legacy
`allowLocalBinding=true` path in the kernel bundle; it must never coexist with,
override or serve as fallback for the finite-port path. Always require network
restriction, including for an empty list. Other platforms remain unqualified.

For **each declared port P**, emit exactly these three grants, substituting only
the validated decimal integer for `P`:

```scheme
(allow network-bind (local tcp "*:P"))
(allow network-inbound (local tcp "*:P"))
(allow network-outbound (remote tcp "localhost:P"))
```

Use **`tcp`, not `ip`**, in all three rules. The latter also grants UDP at that
port, demonstrated below, and would violate `UDP_DENIED_WITH_DECLARED_TCP_PORT`.
Keep srt's default-deny profile. There is no `*:*`, `localhost:*`, outbound
`remote tcp "*:P"`, or outbound rule using a **local** address predicate.
An empty declaration emits none of these three grants.

The wildcard host on bind/inbound admits native IPv4, IPv6 and IPv4-mapped
bindings at the declared port, without depending on `localhost` matching the
mapped local address. Outbound retains the remote `localhost:P` predicate.
Native AF_INET `127.0.0.1` and AF_INET6 `::1` must work. On this host, AF_INET6
`::ffff:127.0.0.1` also worked with this outbound predicate; the source comment
warns that it may not on other systems. Do not broaden outbound to `*` to repair
a mapped-address failure. Qualification must record that result for the exact
OS/runtime: applications may use native AF_INET for IPv4, while a contract
requiring a mapped connection on a host that cannot enforce it is unavailable
and must be refused before launch. No universal mapped-outbound claim is made.

Runtime proxies are separate trusted IPC, never fake declarations. Let `R` be
the distinct actual HTTP/SOCKS listener ports owned by this check's trusted
supervisor. For each `R`, the candidate needs only:

```scheme
(allow network-outbound (remote tcp "localhost:R"))
```

As part of the same patch, replace srt's proxy `ip` grants with this TCP-only
outbound grant; remove candidate bind/inbound grants for those proxy ports.
The proxy listeners run outside the candidate sandbox. Allocate proxy ports
disjoint from the declared ports, verify ownership/readiness, and hold them
through candidate cleanup. Record them separately. No other candidate IP
network grants or Unix-socket escape is permitted; any required non-IP IPC must
be explicitly enumerated and reviewed, including the existing fixed AF_SYSTEM
protocol-2 allowance. The authenticated supervisor's HTTP/CONNECT/SOCKS policy
must allow only declared canonical loopback destination/port pairs, validate
resolved addresses, and deny undeclared destinations, alternate addresses,
arbitrary DNS forwarding and UDP. Merely checking an HTTP hostname string is
insufficient. A proxy path that cannot enforce this is unavailable, not a reason
to enlarge the Seatbelt grants. Full direct and proxy qualification remains due.

A bounded dist patch keeps emission in srt's existing generator. Its review
covers the configuration validation/plumbing, three per-port rules, proxy rules,
and removal/refusal of broad paths. Runtime profile post-processing would add a
second policy-changing stage, replacement-order assumptions and another possible
bypass after generation. Choose the smaller **policy-changing** trusted surface:
build-time patch plus a read-only runtime validator. The supervisor validates
and either launches the exact generated bytes or refuses; it does not repair them.

### Application, pinning and authentication

Apply the reviewed patch once to a clean installation of exactly srt 0.0.81 and
the frozen transitive lock during operator-controlled bundle assembly. Retain the
upstream lock (SHA-256
`53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9`),
upstream package integrity, patch revision and patch bytes. Require authenticated
preimage hashes for **every** changed file, exact hunk matches with no fuzz or
offset, and reviewed postimage hashes. Refuse wrong version, changed preimage,
partial/already-applied patch, unexpected changed files or wrong postimage.
Do not mutate the existing scratch dev-bundle or a live installed bundle in place.
Publish a newly assembled immutable bundle outside candidate authority.

The complete bundle digest covers patched distribution bytes, patch file,
pre/postimage manifest, lock, supervisor/validator and qualified runtime under
the existing bundle rules. The caller-held operator receipt must additionally
name `srt_version=0.0.81`, `patch_id=kernel-srt-0.0.81-exact-tcp-v1`, the patch
file's **own `patch_sha256`**, pre/postimage identities, and bundle digest.
Authenticate the release binding and receipt from the external trusted expected
digest before importing or launching any bundle code; recomputing a hash from
untrusted local bytes does not authenticate it. Bind patch and bundle identities
into each check receipt. No fetch, npm install, patch application or profile
repair occurs during verification. No patch file or patch SHA-256 is manufactured
in this decision-only run; those concrete bytes and hashes are required outputs
of the later implementation review before any patched bundle can be accepted.

### Exact-profile check and failure classification

Before every candidate launch, independently derive the expected rule set from
the authenticated policy and actual trusted proxy identities: three rules per
sorted declared port, one outbound rule per distinct proxy port, and only the
fixed reviewed non-IP socket rules. Inspect the **complete** generated profile,
not just a marker-delimited network section or substring count. The restricted
validator must recognize all rule expressions affecting networking and default
policy, reject unknown syntax, includes/macros or broad operation wildcards,
and compare rule structure, predicates, ports and multiplicity exactly. It must
verify default deny and absence of any other grant that can reopen networking.
Approved non-network rules remain bound to the pinned generator/template; an
unrecognized profile fails rather than being treated as harmless text.

Reject missing, additional, duplicate, malformed or broadened network rules;
`ip` instead of `tcp`; a wildcard port; a local outbound predicate; unaccounted
proxy/Unix-socket authority; unexpected defaults; or a failed/unavailable profile
inspection. Do not merely verify that the expected clauses are present.
Retain the inspected bytes and their SHA-256 outside candidate write authority,
launch those same bytes without a writable-file or regeneration race, and record
the effective rules plus validator version/result in the parent receipt.

- Invalid contract or failed release/bundle/patch authentication: **exit 3,
  no verdict**, before loading untrusted code or launching the candidate.
- Authenticated backend generates an unexpected profile, cannot validate it,
  fails required preflight, or cannot enforce a valid policy: **unverifiable,
  exit 2, `lifecycle.launched=false`**. Preserve the precise mismatch and profile
  identity. An unavailable baseline is BASELINE_NOT_READY, not RED.
- Neither class permits a broad-switch retry, profile rewrite, alternate backend
  or unsandboxed execution. Existing verdict precedence remains unchanged.

### Limits required in README and operator/check receipts

The implementation must publish these limits in README and both receipt types,
with machine-readable effective rules and explicit exception/assurance fields:

1. **Declared-port binding is address-wildcard TCP binding.** A candidate can
   bind `0.0.0.0`, `::` or an available non-loopback/alternate local address at a
   declared port. A listener there may accept non-loopback inbound connections
   and exchange data on accepted connections. The rules do not distinguish the
   remote peer, ownership or purpose of that listener. This is a real inbound
   exposure and possible communication route; restricted outbound `connect()`
   is not a claim of complete network isolation. Empty declarations confer no
   such bind/inbound authority. Other ports remain denied.
2. Seatbelt's `localhost` predicate is an OS address class, not a literal-address
   spelling check. On this host, `0.0.0.0:P` connected to the local service, and
   mapped IPv4 worked. The raw-socket policy cannot claim to distinguish every
   spelling/alias of the same endpoint. Record the tested native/mapped behavior
   and alias limitation. The proxy still validates canonical destinations.
3. Exact ports do not identify services or processes and do not authenticate a
   server. Any reachable service on an allowed port can receive candidate TCP;
   such a service may itself relay traffic. Isolated fixtures/caller-reviewed
   services remain required. OS permissions, port occupancy and races can make
   an allowed operation unavailable; allowance does not guarantee availability.
4. TCP-only per-port authority, denied undeclared direct connections, and bounded
   proxy routing are the claims to qualify. No UDP grant, all-port localhost
   access, universal mapped-address compatibility, external-egress qualification,
   complete denial log, invisible-attempt detection or hostile-host containment
   follows from this amendment. Existing integrity/log/cleanup limits remain.

Accordingly, the earlier paragraphs saying "loopback binding only", "No wildcard
binding", and all non-loopback binds are forbidden are superseded **at declared
ports only**. Do not continue printing those claims in receipts or README.

### Frozen matrix: operations stand; receipt semantics require a new version

The reviewer's reading is correct about **operation outcomes**: none of the 16
network rows requires a different allowed/denied result. Native IPv4/IPv6 declared
connect and bind succeed; wrong port, empty-policy alternate loopback,
empty-policy non-loopback bind, UDP with or without a declaration, and undeclared
proxy traffic remain denied. No frozen case requires denial of non-loopback bind
**at a declared port**, or requires mapped outbound success on every OS.

However, the reading that **no frozen evidence specification changes** is too
strong. At `39a419c`, `tests/sandbox_fixtures/harness.py:582–588` describes
`localhost_endpoints` as effective authority and asserts exact equality to only
`127.0.0.1`/`::1` TCP tuples, with a comment forbidding wildcard/alternate binding
authority. The matrix repeats "policy contains only declared exact loopback
tuples", and its README lines 110–114 reinforces that ceiling. Reporting only
those tuples while actually granting `*:P` would pass the equality check by
omission. Calling the field a declaration after the fact silently changes the
frozen evidence meaning. Do not do that.

Specify the following **sandbox-v3** refreeze, not an in-place edit to sandbox-v2:

- Preserve sandbox-v2 and its immutable base/evidence. Create a new contract ID
  `sandbox-v3` with an explicitly recorded immutable base and new fixture hashes.
  Retain all case IDs, groups, operations, expected verdicts, logging variants,
  effect controls, protections and timeouts. The refreezer must obtain fresh
  genuine baseline RED; this decision does not supply one or change `.desk`.
- Version the parent sandbox receipt from `schema=1` to **`schema=2`**. Define
  `policy.localhost_endpoints` explicitly as canonical **declared application
  destinations**, still exactly the two native loopback TCP tuples per declared
  integer. It is no longer an exhaustive effective-authority field.
- Add required `policy.network_semantics="srt-0.0.81-exact-tcp-v1"`,
  `policy.effective_network_rules`, `policy.profile_sha256`, and
  `policy.profile_validation` (validator identity and exact-match result).
  `effective_network_rules` enumerates operation, local/remote selector,
  transport, host token and port for every IP grant. Trusted proxy ports/rules
  remain separately identified in `internal_ipc`, and the exact rule comparison
  includes them. Require patch identity/digest in `bundle`.
- Replace the shared network receipt predicate for all 16 rows with **both**
  checks: canonical declared tuples equal the contract, and effective grants
  equal precisely the triples/proxy grants specified above. Require explicit
  `policy.exceptions` entries for address-wildcard declared-port bind/inbound,
  localhost alias matching and qualified mapped behavior; include false
  `assurance.loopback_only_binding` and false `assurance.literal_address_only`.
  For an empty declaration, require an empty application bind/inbound set.
- Replace "policy contains only declared exact loopback tuples" in the network
  evidence specification with "declared destinations are exact canonical TCP
  tuples; effective bind/inbound/outbound and internal-proxy grants match the
  versioned profile specification, with residual limits explicitly receipted".
  Keep successful bind observations at the requested native loopback address.
  Update the fixture README's receipt semantics accordingly; no denial assertion
  or operation control is weakened, removed or reclassified.

This is an evidence-interface correction, not an unsatisfiable behavioral case
or permission to claim sandbox-v2 GREEN against altered fixtures. New profile
validation and patch-authentication rejection paths also need reviewed fault
coverage before the new version is frozen. All other sandbox cases remain due.

### Throwaway Seatbelt evidence, not patched-srt acceptance

Ran local probes only under `~/.local/state/kernel/astra-probe/`, using
`/usr/bin/sandbox-exec`, Python 3.15.0 on macOS 27.0 build 26A5421a, arm64.
No repository implementation or installed bundle was changed. Synthetic TCP
listeners were bound only to loopback; wildcard-bind probes immediately closed
without listening. No off-machine endpoint or network configuration was used.

`exact_ports.py` tested a network-denying profile with other operations allowed;
`exact_ports_deny_default.py` repeated it with default deny and explicit process,
read, sysctl, Mach-lookup and signal permissions. Both produced the same socket
outcomes. `inbound.py` separately used default-deny profiles, sandboxed native
and mapped loopback listeners and an unsandboxed client; each accepted and echoed
five synthetic bytes. These are deliberately small network experiments, not a
standalone product backend or full filesystem/proxy/runtime qualification.

| Operation | Unsandboxed control | Exact TCP profile |
| --- | --- | --- |
| Declared TCP connect to `127.0.0.1`, `::1`, `::ffff:127.0.0.1` | Each reached listener and echoed nonce | Each succeeded; listener journal retained |
| Other-port TCP connect, same three forms | Each succeeded | Each EPERM |
| Declared TCP bind, same three forms | Each succeeded | Each succeeded |
| Other-port TCP bind, same three forms | Each succeeded | Each EPERM |
| UDP sendto at declared TCP port, same three forms | Each syscall succeeded | Each EPERM; `ip` comparison profile allowed each sendto |
| `0.0.0.0` and `::` bind at declared port | Each succeeded | Each succeeded; no listen |
| Same wildcard binds at other port | Each succeeded | Each EPERM |
| No declared ports | Controls above reachable | All tested connects/binds/UDP returned EPERM |
| `0.0.0.0` connect at declared port | Reached local listener | Reached local listener; alias limit confirmed |
| `127.0.0.2` connect/bind | Connect timed out; bind EADDRNOTAVAIL | Connect EPERM; declared bind EADDRNOTAVAIL; other bind EPERM |
| Sandboxed inbound listener, native v4/v6 and mapped v4 | Parent connected to each | Each accepted and echoed; exit 0 |

The alternate-loopback positive control was unavailable on this host, so **no
alternate-loopback qualification is claimed** from that row. The full frozen
case requires a reachable separate listener and remains due. UDP controls here
establish syscall allowance only, not receiver-observed delivery; the full
matrix still requires its receiver evidence. A comparison profile using
`localhost` for bind/inbound also admitted mapped binds on this OS, unlike the
upstream comment's compatibility warning. Retain the warning and explicit
wildcard-bind semantics rather than generalizing one OS result to all platforms.

Reproduce each script with `PYTHONDONTWRITEBYTECODE=1 python3 -B` and its absolute
path. JSON includes generated profile bytes, selected ports, per-operation
results and listener evidence; adjacent `.txt` files retain console output.

| Probe artifact under `~/.local/state/kernel/astra-probe/` | SHA-256 |
| --- | --- |
| `exact_ports.py` | `b66f2dbf3b65ab44586687cf562c1082c90ef9715d8763b7e63bc3150f5893cd` |
| `exact_ports.json` | `a7e07cfb7805706a3fe9307b3b7fb5b4e59fcaeb63d40d9c93e2fe65e1bf2d15` |
| `exact_ports_deny_default.py` | `9dd64200ec80a90290f5bff4d44123e7483590f3539903d815bb55368297f3d0` |
| `exact_ports_deny_default.json` | `bcdbda89c0be6e613512f20ce316ff12c591a7df2d9c1e6f277a40c87ba19025` |
| `inbound.py` | `c509418399f52014e1f6264d1d66faa25fab2750ccd60814942825b0f8b36b69` |
| `inbound.json` | `898e61c2d1a0c14d28028ae2b3cc72d58cd5fe8baf8377ac398771fc933993e2` |

### Upgrade and stop boundary

Any srt, patch, supervisor/validator, transitive dependency, Node or supported
OS change requires renewed review of the exact emission path and patch, fresh
bundle/receipt hashes, these address/protocol probes, and the **full applicable
frozen matrix with logging enabled and disabled** on the exact combined package.
Do not automatically carry a patch forward or accept an upstream option with
similar naming. Prefer upstreaming a finite TCP-port option with explicit
bind/inbound limits; replacing the patch with that option still requires review
and full qualification. Off-machine egress stays under plan v6's separate
endpoint authorization and release/default-on gate.

Only this dated amendment is delivered here. No agents, implementation, fixture
edits, patch file, provisioning, installed-judge invocation or acceptance claim.
Commit/push only `kernel/sandbox-decision-2`, mark that workspace in-review, and
stop for review before implementation begins.
## Amendment 2026-11-09: advisory one-directional logging and bound diagnostics

Authority: Zack, 2026-11-09, **"go"**, visiting-architect decision only. Base:
`origin/next` at `f9a0c82ebef62184208a3493be84df365f5c83a5`. Candidate inspected:
`origin/kernel/sandbox-v4` at `c01cba3934e432b1cf176b03724850e020260f32`;
its immutable FROZEN_BASE is `d626138b2e53a29e0cff9b6b5d4dc06503b67b0d`.
Both remote heads were verified for this decision. This amendment supersedes
only conflicting logging/canary rules and their acceptance evidence. The
2026-11-06 pinned-srt exact-TCP decision, enforcement, authentication, integrity,
cleanup, receipt, opt-in and separate egress requirements remain binding.

**Decision: adopt advisory, one-directional logging and retain a bound,
non-gating canary diagnostic.** An observed, attributed, relevant unexpected
denial makes the affected check **unverifiable at any time**, including while
assertions are running. Absence of a denial event, including the preflight
canary event, is neither positive evidence nor by itself an evidence failure.
It does not prevent supported when all required non-log evidence passes.
Enabled collector faults remain failures; "advisory" does not permit discarding
received evidence, hiding loss, or switching logging off after a fault.

Verdicts continue to depend on directly measured operation outcomes, independent
protected inventories, execution and cleanup observations, and the authenticated
receipt protocol. Logs may add an unavailable reason; they cannot supply missing
operation/inventory/protocol evidence, establish a contradiction by themselves,
or certify that no attempt occurred. Preserve **unverifiable > contradicted >
supported**, retaining reliable contradiction facts even when overridden.

The installed 3.1.0 claim against v4 remains **UNVERIFIABLE**: three groups passed,
isolation stopped at an enabled canary with `event_received=false`. This is not
a retrospective v4 pass, permission to edit its freeze, or permission to erase
its failed claim. No new runtime reproduction or implementation occurs here.

### Evidence, provenance and what it establishes

Evidence A is `~/.local/state/kernel/canary-rate/REPORT.md`, including its spacing
and bisect addenda. The production-path measurements report roughly 1.5–6%
misses at approximately three-second cadence, 14/40 at twenty seconds, and 30/30
at seventy seconds. Moving/removing the foreground heartbeat did not eliminate
the misses. The minimal-path bisect first flipped at Python instead of sh:
Python 0/6 delivered, reversion to sh 6/6. Arms 2–7 were not run. That first arm
also changed script/operation shape; it alone does not isolate executable identity.
The report rejects a deterministic sixty-second renewal model and does not
justify an IID production loss-rate forecast. Interrupted/invalid windows and
all earlier failures remain evidence, not clean replacements.

Evidence B is the independent reviewer's `reviewer-attach/` scripts and JSONL
under the same external state directory. Fresh `log stream` instances and
seventy-five-second trial spacing used `/usr/bin/sandbox-exec` with
`(version 1)(allow default)(deny file-write* (subpath D))`. The attachment probe
recorded ten trials, each with one sh denial and an event at about 0.09 seconds.
The split probe recorded sh 12/12 delivered and Homebrew Python 0/12 delivered;
new versus existing target did not change that split. The executable probe
recorded Apple sh 5/5 and Perl 5/5 delivered, versus Homebrew Python, Homebrew
Node and ad-hoc-signed C each 0/5. Across the split/executable arms, excluding
the invalid copied-sh arm, that is Apple system binaries **22/22 delivered**,
third-party binaries **0/27 delivered**, with **49/49 writes blocked**. The ten
attachment trials are separate from those totals. The copied-sh arm is void:
the reviewer reports SIGKILL/exit 137; its missing target is not denial evidence.
`who.jsonl` itself records no return code, so it cannot independently establish
that termination explanation. It is excluded regardless.

This is strong evidence of a runtime-associated logging gap on **one Mac,
macOS 27.0 arm64**, not a proven mechanism or a platform-wide rate. Apple signing,
system-volume location and ad-hoc signing remain confounded. Rapid-cadence Python
denials mostly arriving remains unexplained. Neither a negative live observation
nor `log show` proves OS non-emission; the report includes live-positive events
absent from store queries. These limits do not support making a third-party
runtime's certification depend on a canary delivered for an Apple binary.
**Do not switch the canary to sh, Perl or another Apple binary to obtain green.**

Evidence C is source inspection at `c01cba3`, confirming the senior review:

- `sandbox_supervisor.mjs:135` sets `lateEvent='relevant_denial'` only while
  `finishing`; `kernel_sandbox.py:58` consumes that flag, not all relevant
  received events. A swallowed EPERM with passing assertions can therefore
  evade the denial rule even when its event arrived mid-check. Existing denial
  fixtures also fail execution evidence, masking this route. This remains a
  source-confirmed path, **not a runtime reproduction**.
- `kernel_sandbox_runtime.py:280` accepts any spooled event containing
  `canary-protected` and `deny`. It binds neither the exact target nor the probe
  identity, PID or preflight interval. A candidate-phase/lookalike event can
  satisfy it. The supervisor's canary exemption is likewise insufficiently
  bound; repairing only the Python predicate is insufficient.
- `sandbox_supervisor.mjs` generates actual and reference profiles with the same
  generator; `kernel_profile.py` compares their non-network templates. This is
  a separately generated reference, not an independent semantic oracle. The
  externally authenticated entrypoint remains a prerequisite to self-check.

The following SHA-256 values bind the evidence read for this decision. External
paths below are relative to `~/.local/state/kernel/`; source paths are Git blobs
at `c01cba3934e432b1cf176b03724850e020260f32`, not this decision checkout.

| Evidence path | SHA-256 |
| --- | --- |
| `canary-rate/REPORT.md` | `d50ad86c7767589d6f42c0f625eca4d128bf0601353cfc3be4dba2f4e4549fba` |
| `canary-rate/SEAL.json` | `56e6960e38eaf3ddb4ec69ca382116bfe347b11083fe928797f3993c8706e3dc` |
| `canary-rate/spacing-addendum/SEAL.json` | `1c80845648b1dd7a7f7b7d3a9991250b10cf2c038d625ddda69f20959519964f` |
| `canary-rate/bisect-addendum/SEAL.json` | `25e6ae91512974aab77056046f8228598b53ac187aa478de7f9b97405ca5bee2` |
| `reviewer-attach/attach.py` | `9b44d1ae32ee3f08dc2b2dd807023b74429b70950f0797b42ed91687562fdf6e` |
| `reviewer-attach/results.jsonl` | `80fb19e2f773fb9051ebd8e41bcf889f4a74de92e9e376a1e75f0dd5b4179ccf` |
| `reviewer-attach/split.py` | `fe1d416c1930b2926503d957c575eb1ef8ac41302b9600dab817faa81a9d6e27` |
| `reviewer-attach/split.jsonl` | `d9f0c08ce72a504eee755ca1d3261182d632749bbfdbda22d92488ee78dc6e43` |
| `reviewer-attach/who.py` | `99489c022919007447d948074320518b24f3d9417b09c6a523e700c936c30027` |
| `reviewer-attach/who.jsonl` | `0dc1ed5824534436f18e0cab5c22205d28a14c22e2d7fe6f7ea9e9b3d86e7f31` |
| `CHECKPOINT-tranche-1.md` (binding section starts at line 1179) | `ea6af2ad3e2e40a382a84e8512d74816e02340e5150823663b44fdd4f0a12f43` |
| `kernel_sandbox.py` | `b7d551d7070608d4c70983112b1614518094757d47b2860da665b7866b89f2e3` |
| `kernel_sandbox_runtime.py` | `4774313e0b2c16e5e72b2eb97416834f094f0d274063833aeeb912a53d664505` |
| `sandbox_supervisor.mjs` | `38d6da6b0e397adbcbfc81654465c03b0eae89bd6e2024591441c9cdd87ec93a` |
| `kernel_profile.py` | `d8a376a1104388f9a86b0e6586aed8ec0b11f191f95a734bc96e6219d735f301` |
| `tests/sandbox_fixtures/harness.py` | `135c9eb41142c2088dea0a838981282ee6c1daca8b88ec121c0e0d0beeed902c` |
| `tests/sandbox_fixtures/matrix.json` | `4af285d24a85c04500ad6755434bf07859736bd338063c22378b93d14d30fb4d` |

Seal checks in this run verified each manifest digest and its report digest,
using `spacing-addendum/PRIOR-REPORT.md` for the original seal and
`bisect-addendum/PRIOR-REPORT.md` for the spacing seal. Each successor report
starts with the unchanged predecessor bytes. The respective report digests are
`9a2a74ce9267f7532624294cecd82bebc3e97f9988b64ec677783e57af1c8059`,
`ae70c6e9e84cbbe2f11a11dfb689fbcc3538779c5d9935358a3a65d05fdcb3e6`,
and the final digest above. This verifies seal/report continuity; it is not a
new exhaustive rehash of all multi-gigabyte trial archives or a rerun of probes.

### Replacement logging and diagnostic verdict rows

"Relevant denial" below means a received, parsed denial attributable to the
check's execution that reports an unexpected denied operation affecting its
contract/environment or protected boundary. It excludes a positively bound
preflight probe, an exact reviewed benign-system exception, or a specifically
frozen expected-denial assertion. Those exclusions must be explicit, narrow and
recorded; candidate text, a path substring, the word `deny`, or merely passing
assertions cannot declare an event benign. An unknown potentially relevant event
is ambiguous evidence, not a new exemption. Trusted event provenance must be
separate from candidate stdout/stderr or provisional result text.

| Observation | Required treatment and verdict contribution |
| --- | --- |
| Attributed relevant denial during the check, with otherwise passing assertions, inventories and cleanup | **Unverifiable**, reason `observed_relevant_denial`; retain event, operation, target and attribution. Do not condition this on `finishing`, assertion failure, or a failed canary. |
| Same denial after leader exit, during cleanup/drain, or later but before receipt finalization | **Unverifiable** for its originating check, same reason and explicit phase/arrival time. A benign event drained within bounds is not a denial failure. |
| Event arrives after the drain deadline while the collector is still observed | A relevant denial still makes its origin **unverifiable**; data/pending work beyond the frozen drain bound also records `diagnostic_drain_incomplete`. A quiet, completed bounded drain is not a timeout and proves no completeness. |
| Relevant event discovered after an originating receipt was finalized | Preserve the original receipt; append a bound invalidation/correction referring to its digest and mark the originating result and dependent aggregate **unverifiable**. Never silently rewrite history or let a later receipt stand as unaffected support. Events never delivered after closure remain unobserved; no perpetual collector or omniscience is claimed. |
| Prior-invocation event appears in the current invocation's collector | Never reassign it. Retain its true origin if established; a relevant denial invalidates that origin. The receiving invocation is **unverifiable** with `diagnostic_cross_invocation` because its promised collection isolation failed, even if the old event is benign. Uncertain origin is `diagnostic_attribution_ambiguous`. |
| No denial event, or no canary event, in an otherwise healthy enabled invocation | No adverse or favorable verdict contribution. With complete passing non-log evidence, **supported** is permitted; a complete behavioral failure/lasting protected change still gives contradicted. Record absence as diagnostic, never as a collector fault inferred solely from silence. |
| Enabled collector fails startup, crashes/exits early, errors, cannot be supervised, or fails shutdown | **Unverifiable**, `diagnostic_collector_fault` (and cleanup reason where applicable). A banner/process start is only lifecycle evidence, not delivery readiness. No restart-to-green or silent disabled-mode fallback. |
| Known subscription drop, count/sequence loss after receipt, raw/event spool overflow, write/read failure, digest/count mismatch, malformed trusted diagnostic protocol, or missing required collector lifecycle evidence | **Unverifiable**, `diagnostic_loss` or `diagnostic_evidence_invalid` as appropriate. Distinguish measured collector loss from an event never observed upstream. Persisted events beyond the 100-event store tail alone are not loss. |
| Received potentially relevant denial cannot be parsed or attributed reliably | **Unverifiable**, `diagnostic_attribution_ambiguous`; preserve raw bytes and uncertainty. Do not classify arbitrary unrelated host traffic as a candidate denial. |
| Bound canary event received; protected write independently denied, scratch independently succeeds, protected object unchanged | Record `matched`, diagnostic only. This proves receipt of this event, not other events or delivery health for candidate runtimes. The expected probe denial is not an unexpected check denial. |
| Bound canary event absent; those same independent preflight effects pass | Record `absent`, diagnostic only; **supported** remains possible. A third-party runtime miss is not by itself unverifiable. |
| Lookalike, wrong-ID/PID/path/window, or candidate-phase event offered as the canary | It cannot match or exempt a denial. Keep `event_received=false` unless a genuine bound event also exists. Evaluate the rejected event independently: a current relevant denial gives unverifiable; ambiguous relevant attribution or cross-invocation delivery gives the corresponding fault; demonstrably unrelated noise gives no verdict contribution. |
| Preflight write not denied, scratch fails, protected contents change, probe crashes, or required operation evidence is missing/invalid | **Unverifiable before candidate launch**, `preflight_operation_unavailable`; retain any measured forbidden change. Event presence cannot repair enforcement/capability failure. |
| Logging intentionally disabled before invocation | Record `disabled`; do not require a collector/event/canary-log match. Complete passing non-log evidence permits **supported**. Observed operation failure, incomplete cleanup/receipt, or integrity evidence retains its ordinary effect. A mode change or an unexpected active collector is an evidence/lifecycle fault, not intentional disabled mode. |

These are the enabled-logging failure conditions: observed relevant denial,
collector/lifecycle fault, measured collector loss, invalid diagnostic evidence,
ambiguous relevant attribution, cross-invocation contamination, or incomplete
bounded drain. **Mere absence is not on that list.** Other execution, inventory,
cleanup and receipt failures still make a run unverifiable in either mode.
Expected-denial tests retain the original two-level rule: the outer suite can
pass by independently observing a nested unavailable check, and a reviewed
assertion explicitly about a denied synthetic operation can pass. Neither is a
blanket permission for ordinary candidates to swallow relevant denials.

### Bound diagnostic and required receipt interface

Keep the same-policy protected-write/scratch **operation preflight as a launch
gate** in both modes. Keep its third-party Python probe; record the actual
executable rather than assuming its signing class. Make only the event match
non-gating. Do not substitute Apple binaries, retry for an event, warm up logging
until it passes, or adapt cadence based on delivery.

The trusted parent must create an unpredictable unique `probe_id` for each
run/check/phase/repetition and a unique exact protected target incorporating that
ID. The diagnostic matcher and expected-probe exemption must both require:

1. Full invocation identity: `run_id`, `check`, base/candidate `phase`,
   `repetition`, plus `probe_id` and the supervisor session/command tag.
2. Exact canonical absolute protected path (including the unique ID), expected
   denied operation and denial result. No prefix, basename or substring match.
3. The **payload subject PID**, with trusted process start identity and absolute
   executable identity/digest; not merely the wrapper PID or the log emitter's
   `processID` (the kernel may emit as PID 0). Parse and bind the subject PID.
4. A parent-recorded preflight start/end interval and probe syscall bracket,
   clock domain/resolution and bounded conversion uncertainty. The event's
   occurrence timestamp must fall within that preflight window; the candidate
   launch must follow its close. Record reception time separately. A delayed
   event can match only if its occurrence and subject bind to preflight and it
   is received before collector closure; reception during the candidate phase
   alone must never cause candidate activity to be labeled preflight.

Freeze any timestamp tolerance before qualification, never widen it after a
miss. Missing binding fields mean `unmatched`, never a positive match. A
reliably bound delayed expected-probe event remains diagnostic, subject to the
same collector deadline rules. A rejected match alone is not a fault; an
ambiguous potentially relevant denial still is. Candidate access to the path
later does not inherit the probe exemption. Run actual matcher/exemption tests,
not just tests assigning a ready-made `event_received` boolean.

Version the **nested sandbox receipt from schema 2 to schema 3** for sandbox-v5;
leave the outer schema-2 verification protocol unchanged. The version prevents
old consumers from silently interpreting advisory absence as the old gating
canary. A classifier input interface, if retained separately, must explicitly
bind the same diagnostic semantics. Required additions/clarifications are:

- `diagnostics.semantics="advisory-one-directional-v1"`, immutable requested
  `mode`, actual `state`, `upstream_completeness="unknown"`,
  `absence_proves_nothing=true`, `absence_is_failure=false`, and
  `canary.event_gates_verdict=false`. Keep received/persisted/dropped counts,
  capacities, lifecycle/exit facts, deadlines, raw/event spool locations and
  SHA-256 values. `collector_ready=false`, `complete=false` and
  `assurance.complete_logs=false` remain honest; do not rename a banner as a
  delivery guarantee.
- `diagnostics.canary` carries the binding fields above, preflight operation
  outcomes/errno, scratch result, protected before/after identity and digest,
  probe exit/cleanup, `match_status` (`matched`, `absent`, `unmatched`, or
  `not_collected`), `event_received` (true only for a bound match), matched event
  reference, and rejected-match reasons. In disabled mode use `not_collected`
  and null event receipt rather than suggesting an attempted collection miss.
  Null diagnostic matches cannot erase failed operation evidence.
- A retained `diagnostics.events` index binds each event digest/raw reference to
  origin identity, subject PID/start identity, operation/resource, occurrence
  and receive times, lifecycle phase, attribution result and relevance decision.
  Store explicit exemption IDs and evidence. Classify **all** observed relevant
  events, not only `late_event`. `diagnostics.faults` and decision reason codes
  distinguish denial, absence, collector loss, ambiguity and lifecycle failure.
  Finalization follows event processing, cleanup and spool sealing. Correction
  records bind original receipt digest and origin when later evidence invalidates it.
- `assurance.all_attempts_detected=false`,
  `assurance.swallowed_undelivered_denial_may_be_supported=true`, and
  `assurance.independent_nonnetwork_policy_oracle=false`. Preserve false
  transient-write, semantic-attestation and exhaustive-descendant assertions.
  Keep all existing release, policy/profile, bundle, platform, inventory and
  cleanup bindings; logging changes cannot replace them.
- Product/operator qualification receipts name this decision, the evidence
  paths/digests above, one-host scope, measured executable paths/digests/signing
  observations and cadence. Per-check receipts bind that qualification record
  plus the actual OS build/architecture and Python/Node executable versions and
  digests. Do not imply that the historical measurements qualify a new host,
  runtime artifact or bundle. Retain raw nested receipts outside temporary-tree
  teardown on every outcome, including harness errors.

Required README and limits wording (also represented in operator/check receipts):

> Logs are diagnostic, absence proves nothing. An observed, attributed, relevant
> unexpected denial makes the affected check unverifiable, including during the
> check or drain. A missing event alone does not. Enabled collector failure,
> overflow, known loss or ambiguous relevant attribution still makes the check
> unverifiable. On one macOS 27.0 arm64 host, cold, spaced probes logged Apple
> system-binary denials 22/22 and third-party denials 0/27 while all 49 writes
> were blocked. Signing, system-volume location and runtime identity are not
> separated causes; rapid-cadence Python delivery remains unexplained. These
> observations are not a universal delivery rate or a proven OS mechanism.
> A candidate that swallows a denial whose event is never delivered can be
> supported when all observable required evidence passes. Neither absent logs
> nor unchanged hashes detects that attempt. Hashes establish lasting changes
> at measured boundaries, not absence of attempts, transient writes or reads.

This residual limit already exists under the current rule in practice: a
received canary does not guarantee delivery of a later third-party denial.
Requiring one canary event makes availability cadence/runtime-dependent without
closing that limit. The new rule exposes the limit and fixes ignoring denials
that actually arrive; it does not claim stronger invisible-attempt detection.

### Exact sandbox-v4 to sandbox-v5 acceptance changes

Keep v4's 201 IDs, 388 variants, freeze and historical evidence immutable. Make a
new `sandbox-v5` contract/freeze; record its parent/base, manifest and fixture
hashes. The following changes apply to its successor fixtures only. No changed
oracle may be used to report the old v4 claim as green.

| Existing exact case ID(s) | Old → new expected verdict/evidence |
| --- | --- |
| `CANARY_MISSING` (enabled) | **unverifiable → supported**, but only after separating absence from fault: replace `collector_fault="suppress_canary_event"`, `state="failed"`, `evidence_complete=false` with healthy enabled collection, complete other evidence, successful operation preflight and an absent bound event. Old evidence "missing event recorded as collector gap" → "absence diagnostic only; no known collector loss". The original combined fault input must still be unverifiable; removing only the canary check would not satisfy this revised case. |
| `SUBSCRIPTION_DROP`, `SPOOL_OVERFLOW`, `COLLECTOR_DEATH`, `AMBIGUOUS_EVENT_ID`, `CROSS_INVOCATION_EVENT`, `DRAIN_TIMEOUT` | **unverifiable → unverifiable**. Evidence changes from generic classifier-failure sufficiency to the named fault with all unrelated evidence healthy; assert typed cause and origin/phase where applicable. Keep deterministic classifier coverage and add controlled collector/pipeline reproductions so one generic failure cannot mask a broken path. |
| `LATE_RELEVANT_DENIAL` | **unverifiable → unverifiable**. Lone `late_event` flag → an attributed retained event reaching the real event-to-decision path after leader exit, otherwise passing evidence; assert `observed_relevant_denial`. |
| `DELAYED_AFTER_LEADER_EXIT` | **supported → supported**. Preserve its **benign** event and original-invocation attribution; add explicit relevance/exemption evidence. It must not become a passing relevant-denial case. |
| `BURST_OVER_100_PERSISTED` | **supported → supported**. Keep all 150 fixture events persisted and no loss; label them benign/non-denial synthetic events. Persisting 150 relevant denials cannot produce supported. This is not an OS completeness assertion. |
| `CHANGE_PLUS_COLLECTOR_LOSS` | **unverifiable → unverifiable**. Preserve measured protected-change facts and require the known-loss reason; canary absence cannot stand in for that loss. |
| `LOGGING_DISABLED_EXPLICIT`, `SWALLOWED_INVISIBLE_DENIAL_DISABLED` | **supported → supported**. Preserve disabled mode and its limited claim; add schema-3 assurance wording. Do not silently convert the latter into enabled coverage; add the enabled case below. |
| `EXPECTED_DENIAL_BEHAVIORAL_ASSERTION` | **supported → supported**, both modes. Bind the expected event to the frozen synthetic operation/assertion, PID/path and interval. An unrelated unexpected denial must still invalidate the check. |
| `PROFILE_NONNETWORK_TEMPLATE` | **unverifiable → unverifiable**, both modes. Preserve rejection of a mismatch between actual and reference, but replace any implication of an independent semantic oracle with the named residual risk below. This case does not exercise a shared generator defect. |

The shared real-receipt canary gate at `harness.py:330–338` changes from
"enabled absent preflight event makes expected-supported evidence Unavailable"
to "record absence and assess all independent evidence/faults normally". This
affects the enabled variants of these **15 exact real case IDs**, each remaining
**supported → supported** at the matrix level:

- `NETWORK_DECLARED_PORT_V4`, `NETWORK_DECLARED_PORT_V6`,
  `CACHE_WRITE_REDIRECTED_SCRATCH`, `CLEAN_CONTROL`, `DECLARED_SCRATCH_WRITE`;
- `GROUP_CHILD_CLEAN`, `SEQUENTIAL_RUN_ISOLATION`, `DECLARED_PORT_BIND_V4`,
  `DECLARED_PORT_BIND_V6`, `DECLARED_PROXY_HTTP`, `DECLARED_PROXY_CONNECT`;
- `VALID_LOOKING_FABRICATED_RESULT_LIMIT`, `CLEAN_DEFAULT_POLICY`,
  `REDIRECT_HOME_TMP_CACHE`, `EXPECTED_DENIAL_BEHAVIORAL_ASSERTION`.

For those cases an absent event alone changes the old runtime/harness outcome
**unverifiable / Unavailable → supported / accepted evidence** when all other
requirements pass. This is a v5 expectation, not a reclassification of retained
v4 observations. The disabled variants retain their semantics. The other two
v4 enabled expected-supported rows are the synthetic `BURST_OVER_100_PERSISTED`
and `DELAYED_AFTER_LEADER_EXIT` cases already specified above.

All applicable sandbox receipt checks change **schema 2 → schema 3**, including
expected-unverifiable rows, and require the new semantic/assurance fields.
Refusals remain exit 3 with no verdict. Other case IDs, operation outcomes,
non-log assertions, logging modes and verdicts stay as frozen in v4. In
particular observed denied-operation cases stay unverifiable even without logs;
reliable lasting changes remain contradicted unless independently overridden.
No broad loosening of `receipt_check` or deletion of operation controls is allowed.

Add these exact v5 case IDs with complete, independently passing non-log evidence
except for the single named condition. Each requires a disposable controlled
run **before freeze**, retained inputs/raw evidence, and a specific reason check:

| New case ID | Reproduction and required outcome |
| --- | --- |
| `MIDCHECK_RELEVANT_DENIAL_PASSING` | Real third-party payload catches a protected-write EPERM and returns passing assertions. Independently establish the denied operation and unchanged protected inventory. Deliver its correctly bound event through the production event ingestion path while the payload remains behind a progress barrier, before `finishing`. **Unverifiable**, `observed_relevant_denial`; collector and canary otherwise healthy. |
| `DRAIN_RELEVANT_DENIAL_PASSING` | Same payload/evidence, but release the attributed event after leader exit during drain and before the deadline. **Unverifiable**, same denial reason, with no injected drain fault. |
| `CANARY_LOOKALIKE_REJECTED`, `CANARY_CANDIDATE_PHASE_REJECTED`, `CANARY_WRONG_ID_REJECTED`, `CANARY_WRONG_PID_REJECTED`, `CANARY_WRONG_PATH_REJECTED`, `CANARY_OUTSIDE_WINDOW_REJECTED` | Exercise the real matcher and expected-probe exemption with the named binding mismatch isolated in matcher inputs and no genuine preflight event. `event_received=false`, no substituted match. For the full event path, retain independent attribution to a current relevant candidate denial (its real identity differs from the expected probe identity): **unverifiable**, `observed_relevant_denial`, never exempted as a canary. Also supply a correctly bound preflight positive control: `matched`, otherwise **supported**. Unresolvable attribution is separately covered by `AMBIGUOUS_EVENT_ID`; it must not substitute for these attributed-denial witnesses. |
| `ABSENT_EVENT_PASSING_ENABLED` | Healthy enabled collector, no delivered denial event, complete passing execution/receipts/inventories/cleanup. **Supported**, absence diagnostic only, with the swallowed-undelivered-denial assurance limit explicit. |
| `SWALLOWED_INVISIBLE_DENIAL_ENABLED` | Real third-party payload catches EPERM and supplies a valid neutral passing result; external fixture retains the operation witness, but neither candidate result nor delivered event exposes it to the subject judge. **Supported**, same explicit limit. Do not feed the external witness into the subject and then pretend it was invisible. |
| `THIRD_PARTY_CANARY_MISS_NON_GATING` | Same-policy third-party Python probe independently reports denied write, successful scratch and unchanged protected target, but no bound event arrives. Clean candidate and healthy collector. **Supported**, `canary.match_status="absent"`, `event_received=false`, no absence-based unavailable reason. |
| `CANARY_BOUND_DELAYED_DIAGNOSTIC` | Deliver a correctly bound preflight-occurrence event during candidate execution, inside the collection deadline. **Supported** with `matched`, explicit occurrence/reception distinction; a candidate-occurrence counterpart is covered above and must not match. |
| `POSTFINAL_RELEVANT_DENIAL_INVALIDATES` | Controlled delayed delivery after sealing a supported receipt. Preserve that receipt, append its digest-bound correction, mark origin/dependent aggregate **unverifiable**, and prove no reassignment to a later check. |

Use deterministic host-owned event injection at the real collector/parser input
boundary when OS delivery cannot be scheduled reliably. Label injected versus
live bytes; a classifier call with a preselected flag is insufficient for the
mid-check, drain or binding reproductions. Keep a valid raw event format,
provenance, event time, subject identity and phase barriers so the path actually
runs. Production candidate input must not gain access to this fault seam.
For absence tests, controlled upstream non-delivery is an explicit fixture input
before the observed collector stream; it must not manufacture healthy counters
after dropping an event already received. A measured collector drop is still
`SUBSCRIPTION_DROP` and unverifiable. Retain a real cold third-party canary run
as a labeled local observation; deterministic absence coverage must not depend
on obtaining a natural miss, and a natural hit is not a failure of that coverage.

**V5 freeze prerequisite:** reproduce every new case and strengthened path above
in disposable fixtures, and run a **complete prefreeze sweep** of all retained
and new cases/variants against the exact candidate under review. Retain exact
coverage, effects, reasons, raw streams, nested receipts, source/bundle identities,
cleanup and installed-judge inventories. Review/fix the draft before freezing;
never freeze unexercised cases or use expected-unverifiable as a proxy for the
named condition. Recalculate and freeze counts, budgets and timeout behavior
before final qualification; 201/388 describes v4, not an invented v5 count.

After review, freeze v5 once with immutable hashes and obtain fresh genuine
installed-3.1.0 baseline RED from named behavioral boundary assertions, not a
new-schema/setup error. Port the reviewed implementation above that base, rerun
the full frozen sweep, regressions and four-check installed-judge claim. A
prefreeze pass is not that claim. Preserve failed attempts, reject unavailable
baselines, retain every required repetition, and do not retry unchanged evidence
into green. Any postfreeze fixture defect requires review and a new version,
not an in-place edit. This decision schedules those gates; none is executed here.

### Finding 3 disposition: named residual risk for red-team and release

**Do not require a new independent non-generator non-network reference in this
logging tranche.** Record `NONNETWORK_GENERATOR_COMMON_MODE` as an unresolved
trusted-computing-base risk. The current comparison catches divergence between
two outputs and binds authenticated generator bytes, but a shared generator error
can broaden both identically and survive. The November 6 decision already kept
approved non-network rules bound to the pinned generator/template; it did not
establish an independent non-network policy implementation. Adding one now would
expand both the trusted policy surface and the qualification contract without
being necessary to fix the demonstrated event-classification defects.

This is deliberate risk retention, not proof that shared generation is safe.
Keep independent operation/effect probes, exact network validation, generator
pinning, release authentication and `PROFILE_NONNETWORK_TEMPLATE`. Red-team must
exercise a **shared** non-network generator/template mutation in a disposable
copy and record whether direct effect probes detect it; reject claims that
matching outputs independently validate semantics. It must also review the
bootstrap/entrypoint trust assumption. Name that separately as
`ENTRYPOINT_EXTERNAL_AUTHENTICATION`: self-check cannot authenticate the code
that must run before self-check; the caller must authenticate the entrypoint and
its launch/import environment externally. This is a prerequisite, not permission
to accept an untrusted entrypoint.

Release must carry both risks, exact qualification evidence and a recorded
owner disposition (mitigation or explicit residual acceptance). An unresolved
claim of independent non-network validation cannot ship. These requirements fit
the existing red-team/release gates; no provisioning, release approval, or new
agent is authorized by this architectural run.

### Final planner section — exact TOML changes

Current base plan is instruction version 6 with `main="next"`. The planner,
not this run, changes `project.instruction_version` to **7**, replaces the
project verdict/logging comments and the matching `sandbox` and `red-team`
blocks with the following. Preserve the existing project outcome, landing and
release-rule comments and all other item blocks/dependencies/acceptance commands,
including `egress`, `default-on`, `flake`, `mutants` and `release`. Do not append
duplicate item IDs. The red-team mandate includes the release disposition so no
new item or acceptance command is invented. This amendment's prefreeze draft
exercise precedes the immutable acceptance freeze; it is not permission to
mutate frozen tests during implementation. No `.desk/` file is edited here.

```toml
[project]
name = "kernel"
outcome = "verify.py becomes a production gate: checks run sandboxed, the verifier refuses to run when tampered with, flaky checks can lower confidence but never certify, and a contract must reject known-wrong implementations before it can be frozen."
main = "next"
instruction_version = 7
# Preserve the current landing/release rules, including the read-only installed 3.1.0 judge.
# Verdict boundary: docs/SANDBOX_DECISION.md, including amendments 2026-11-06 and 2026-11-09.
# Unverifiable precedes contradicted, which precedes supported; retain measured contradiction facts.
# Observed attributed relevant unexpected denial at any phase -> unverifiable.
# Enabled collector fault/death/overflow/known loss, invalid evidence, ambiguous relevant attribution,
# cross-invocation contamination or incomplete bounded drain -> unverifiable. No silent fallback.
# Logs are diagnostic, absence proves nothing: missing events/canary alone never gate support.
# Bound canary logging is diagnostic; independent same-policy operation preflight still gates launch.
# Supported is bounded observable contract evidence; swallowed undelivered denials may be supported.
# Hashes do not prove no attempts, no transient writes or read denial. Disabled mode stays explicit.

[[item]]
id = "sandbox"
title = "Opt-in sandbox-v5: one-directional diagnostic logs, bound non-gating canary events and complete independent evidence"
mandate = "Zack, 2026-11-09 go; docs/SANDBOX_DECISION.md amendments are binding. Preserve v4 freeze and UNVERIFIABLE claim. Before v5 freeze, reproduce every newly required case and strengthened event/fault path in disposable controlled runs and complete the full prefreeze sweep. Freeze reviewed v5 fixtures once, obtain genuine installed-3.1.0 behavioral baseline RED, then require full frozen sweep, regressions and four-check installed claim on exact candidate bytes. Observed relevant denials at any time and enabled collector faults remain unverifiable; absence alone does not. Keep same-policy operation preflight, third-party probe, pinned srt 0.0.81 exact-TCP patch, authenticated external bundle, independent inventories, cleanup and receipt protocol. Use nested sandbox receipt schema 3 and publish measured one-host logging and swallowed-denial limits. No Apple-binary substitution, retry-to-green, broadened policy or unconstrained fallback."
depends = ["integrate-1", "sandbox-spike"]
acceptance = [["python3", "-B", "tests/tamper_suite.py"]]
# Off-machine egress remains in egress; retain every on-machine operation/effect control.
# Canary absence is not collector loss. Collector crash/overflow/known drop remains unverifiable.
# New oracle/receipt semantics belong only to sandbox-v5; never rewrite or relabel v4 evidence.
# Preserve exact freeze/source/bundle/receipt bindings and all failed or unavailable observations.

[[item]]
id = "red-team"
title = "Red-team new frozen contracts and named sandbox residual risks before release"
mandate = "Zack, 2026-11-03 separate red-team agent, judged by the same frozen contract; extended by 2026-11-09 decision. Preserve new-version-only freeze procedure. Address NONNETWORK_GENERATOR_COMMON_MODE using a disposable shared-generator non-network mutation and independent operation/effect witnesses; matching generator outputs are not an independent semantic oracle. Review ENTRYPOINT_EXTERNAL_AUTHENTICATION as a caller prerequisite and the swallowed-undelivered-denial limit. Record source, observations and limits. Release must publish both named trust risks and an owner disposition of mitigation or explicit residual acceptance; no claim of independent non-network validation without new proof."
depends = ["mutants"]
acceptance = [["python3", "tests/red_team_freeze.py"]]
```
