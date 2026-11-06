# Sandbox v3 freeze interface and evidence ceiling

Freeze only. Nothing in these fixtures enforces a sandbox, provisions a runtime,
changes the installed judge, or implements a verdict classifier. Matrix.json is
the complete case registry; every row includes expected nested verdict, logging
modes, params, and required evidence. The outer claim is the conjunction of every
row and every declared logging variant, not merely a canary or return code.

## Meaningful baseline without inventing new-feature RED

The SAME command and opt-in environment are used on the old and future subject.
The first nested contract uses the old valid schema-2 syntax and a real old/new
Git fixture. `VERIFY_SANDBOX=1` requests sandboxing; `VERIFY_SANDBOX_OPERATOR`
names a host-owned JSON request outside the nested repository. The current 3.1
subject ignores this request and actually writes a disposable protected file.
A complete nested receipt plus a measured lasting forbidden write is the decisive
counterexample to each named group boundary assertion. Each group has its own
fresh witness and conjunction. The full assigned group short-circuits after that
concrete counterexample; later rows are **not qualified**, never individually
credited RED or GREEN. Classifier is folded into effect, dependency into policy:
3.1.0 kernel_runtime.validate_spec rejects empty acceptance baseline_failures.
No missing API is credited as a failing assertion.
No actual installed judge, real secret, or real runtime bundle is attacked.

If the boundary gate denies the operation, the full matrix must run. No early
success exists. Missing qualified bundle, API, evidence,
provisional/final JSON or cleanup raises without the outer schema-2 receipt:
the installed judge must call that unavailable, never meaningful RED or GREEN.
Finite observed assertion mismatches can return a complete fail result. Each
row must pass before the outer result can pass. Tests already satisfied by old
cleanup/result handling are not advertised as novel failing assertion IDs.

The contract has four acceptance assertions, one per group, over 201 cases and
388 declared logging variants:

| Group | Layers | Cases | Variants | Timeout seconds |
| --- | --- | ---: | ---: | ---: |
| effect-classifier | effect, classifier | 124 | 234 | 3660 |
| protocol | protocol | 13 | 26 | 600 |
| policy-dependency | policy, dependency | 57 | 114 | 1860 |
| isolation | isolation | 7 | 14 | 600 |

`python3 -B tests/tamper_suite.py GROUP` runs one group; the no-argument command
runs all groups for Desk. The external schema-2 checks require an explicit group.
Each assertion is `SANDBOX_<GROUP_WITH_UNDERSCORES>_BOUNDARY`. All four checks must
pass; no per-group pass substitutes for the others. The reviewed suite remains
a trusted-harness assumption: valid JSON alone cannot attest semantic execution.

Manual `measure_cost.py` records two actual unsandboxed witness invocations per
group and separate file/network positive controls under ~/.local/state/kernel/.
The checkpoint distinguishes measured cost from full-matrix projection. Budgets
charge even classifier/prelaunch variants the slowest measured nested verifier
cost, add extra sequential invocations, control costs and timeout allowances,
then add fourfold headroom, five seconds per variant, and 120 seconds fixed.
The minimum is 600 seconds, rounded up to whole minutes. Backend cost remains
unqualified until implementation; no correct-build GREEN is asserted here.

## Proposed product seams fixed for review by this freeze

These are required interfaces for the FUTURE implementation, not code supplied
by this freeze. Changing the interfaces or evidence ceiling requires review and
a new frozen contract version; do not edit frozen tests in place.

- Existing verify.py CLI stays executable with old schema-2 argv. Trusted caller
  environment `VERIFY_SANDBOX=1` opts into confinement. This is also how the legacy
  comparison can execute a real operation without an unknown-flag error.
- `VERIFY_SANDBOX_OPERATOR` is the trusted operator JSON path: schema=1,
  bundle_receipt path, diagnostics.mode (`enabled`/`disabled`), scratch_root,
  additional_protected_paths, and synthetic secret_read_paths. All paths are
  outside the nested checked tree, fixed by the host. They do not become a
  candidate-controlled policy escape. Contract runtime grants remain solely the
  decision's `[sandbox] writable_paths` and `localhost_ports`. The trusted caller
  must authenticate/hold this request and bundle receipt outside candidate
  authority; child environment must not supply the supervisor's trust inputs.
- Authenticated external bundle receipt (KERNEL_SANDBOX_BUNDLE_RECEIPT for the
  outer suite) has bundle_root, files [{path, sha256, mode(integer POSIX bits)}],
  node {executable(relative), version, artifact_sha256}, lock_sha256 and
  bundle_digest, patch_file (relative inventoried regular file),
  patch_id=kernel-srt-0.0.81-exact-tcp-v1, patch_sha256 (the patch file's own
  digest), and patch_preimages/patch_postimages (nonempty arrays of unique
  {path,sha256}, identical changed-file sets). The bundle digest covers patched
  dist bytes, patch, pre/post manifests, lock, supervisor/validator and Node.
  Paths must be regular and relative, with protected ancestors.
  The helper copies only authenticated listed files for disposable bundle attacks;
  the real bundle is never mutated. Original qualified bundle is used for
  execution/dependency fault cases; writable or altered copies must fail closed.
- Subject module `kernel_sandbox.classify_sandbox_evidence(evidence)` returns a
  dict with verdict and facts. Measured typed protected_change facts must survive
  unverifiable precedence; judge_environment_change must retain its origin.
  Evidence keys: integrity (available, before, after, changes, optional
  additional_inventory_available), execution (complete, timeout/unavailable
  reasons), cleanup (complete, survivors), assertions (complete, failed),
  diagnostics (mode, state, counts/fault/attribution/drain fields), optional
  judge_integrity. This is a deterministic classifier seam. Production must use
  that same classifier; independent source review must verify the wiring.
- `kernel_sandbox.backend_supports_policy(policy)` is the trusted host capability
  qualification seam. The adapter can force it false to prove exact-port
  unavailability fails before launching checks. Other host faults patch only the
  disposable interpreter's killpg, ps, qualified-Node launch/version query,
  facility resolver, or supervisor Popen. No global system alteration or product
  test-mode environment backdoor is supplied by these fixtures.
- New read-only seam `kernel_sandbox.validate_generated_profile(profile, context)`:
  profile is the complete generated UTF-8 string and context is the trusted
  policy/proxy/template context. It returns structured profile_validation
  evidence with validator_id=kernel-srt-profile-validator-v1, exact_match,
  inspected_profile (the complete bytes represented as a UTF-8 string), and
  errors (nonempty on rejection). It must run in the production prelaunch path,
  after patch/bundle authentication, before any candidate launch; source review
  must verify that the same inspected bytes are launched without regeneration
  or repair. Context never accepts candidate flags or profile text.
  The disposable adapter alters input only and calls the real validator; it does
  not implement a validator or fabricate its result. Missing seam is unavailable.
  Profile inspection RuntimeError/OSError are conservative prelaunch failures.

## Parent receipt schema and independent effects

A per-check `sandbox_receipt` (or top-level prelaunch failure receipt) has schema=2,
requested/enforced state plus identity, release, bundle, platform, policy,
lifecycle, integrity, diagnostics, decision, assurance. These are the decision's
required sections, not a child-written substitute for a final receipt.

- release.manifest_sha256 binds the caller-held disposable subject-package digest.
  Bundle records exact srt_version=0.0.81, node_version=v24.22.0,
  node_artifact_sha256, and lock_sha256 matching the frozen transitive lock.
  Bundle also copies patch_id, patch_sha256, patch_preimages, patch_postimages
  and bundle_digest exactly from the authenticated operator receipt. Every
  changed patch file has both a preimage and postimage digest. Merely hashing
  current bytes never authenticates the caller-held release/bundle binding.
- identity includes unique run/check/phase/repetition; source bindings remain in
  existing schema-2 records. Platform identifies OS/build/architecture and runtimes.
- policy.localhost_endpoints [{host,port,transport}] is the canonical declared
  application destination list: exactly 127.0.0.1 and ::1 TCP tuples per declared
  integer, not an exhaustive effective-authority field. Scratch, writable roots,
  secret denials, protected inventory and policy digest remain required.
  policy.network_semantics is srt-0.0.81-exact-tcp-v1. effective_network_rules
  enumerates every IP grant as {operation,selector,transport,host,port}, with
  exact multiplicity, no omissions or extras. Each declared P has local TCP
  network-bind and network-inbound at host "*", and remote TCP network-outbound
  at host "localhost". Each distinct actual proxy R has only remote TCP
  network-outbound at "localhost". No ip/UDP, wildcard port, local outbound,
  bind/inbound proxy authority or general Unix socket grant is permitted.
- policy.internal_ipc is {proxies,non_ip_rules}. Each proxy identity has exactly
  {role,host,port,transport,pid,started,ready,ownership_verified}: role http/socks,
  canonical host 127.0.0.1/::1, transport tcp, positive PID/start identity,
  ready=true and ownership_verified=true. HTTP/SOCKS may share a mux port; roles
  are unique and all proxy ports are disjoint from declarations. Proxy grants
  are counted once per distinct port. The fixed reviewed non_ip_rules is
  [{operation:"system-socket",socket_domain:"AF_SYSTEM",socket_protocol:2}].
  No other IPC is inferred from allowed application destinations.
- policy.profile_sha256 hashes the complete retained UTF-8 inspected_profile in
  policy.profile_validation; that object names validator_id, exact_match and
  errors. Every launched/enforced receipt must pass both the canonical-list and
  complete effective-rule comparisons. The read-only validator must inspect the
  complete profile/default/template, reject unrecognized rules or syntax, and
  retain/launch the identical authenticated generated bytes. Receipts cannot
  substitute a claimed marker-section count for that inspection.
- policy.exceptions must explicitly include these machine-readable entries,
  each with a nonempty detail string: address_wildcard_declared_tcp_binding has
  ports (sorted declared integers), nonloopback_inbound_exposure and
  accepted_connection_data_exchange (both true iff ports is nonempty);
  localhost_address_class_aliases has literal_spelling_enforced=false;
  mapped_outbound_qualification has status supported/unavailable,
  universal_compatibility=false, and platform {system,release,machine} equal to
  this check's platform identity, a nonempty os_build, and node_version plus
  node_artifact_sha256 equal to this check's bundle identity. Empty declarations have no application
  bind/inbound grants. Mapped support is per qualified OS/runtime, never universal.
- lifecycle.launched=false for prelaunch dependency/capability refusal; otherwise
  started_at <= exited_at <= cleanup_finished_at <= finalized_at. Preserve actual
  check and supervisor/process/collector cleanup, timeouts, identities and errors.
- integrity records typed inventories/differences including bytes, modes, links,
  types, existence and directory additions/deletions. Final-log prior prefix is
  checked separately from the parent's own append. Never call an expected trusted
  append a candidate violation. Inaccessible measurements are unavailable.
- diagnostics records disabled vs enabled/failed, operation canary and event
  outcomes separately, counts, capacity/overflow/loss, raw artifact hashes, unknown
  upstream completeness, identity attribution and bounded drain. Disabled mode
  never sets collector_ready or complete. No mode may claim complete OS logs.
- assurance booleans all_attempts_detected, transient_writes_detected,
  complete_logs, semantic_attestation, exhaustive_descendant_containment,
  loopback_only_binding and literal_address_only are explicitly false. Supported covers only the bounded frozen claim.
- assertions include the captured validated provisional bytes/hash/identity and
  the cleanup object. Complete facts/reasons must explain the aggregate decision.

Effect rows require positive unsandboxed controls, actual operation reports and
independent before/after inventories, nonce-ACK listener observations or process
liveness checks. A nested unverifiable alone never proves denial. The reviewed
payload emits SANDBOX_OPERATION before an unexpected denied operation returns 99
with no provisional result. Expected-denial assertion is separate and can return
valid pass. A swallowed denial deliberately emits a neutral valid receipt; no
imaginary attempt detection is asserted. Reads hash synthetic bytes only.

Classifier rows inject measured synthetic changes or deterministic diagnostic
facts, distinct from real confinement probes. The >100 event fixture writes 150
unique records, independent of the in-memory 100-event tail; controlled drop and
spool overflow record counts. These are classifier tests, not qualification of
OS delivery completeness. Known loss must invalidate enabled logging; intentionally
disabled logging is not collector failure. A benign, correctly attributed late
event may drain successfully without claiming completeness; late relevant denial,
drain expiry or another invocation's event remains unavailable.

## Off-machine egress moved to a separate item

The v1 `EXTERNAL_EGRESS_NO_AUTHORIZED_FIXTURE` row (both logging modes),
`egress_case` dispatcher/function and `egress_probe.py` helper are excluded from
sandbox-v3 (and v2 history). Off-machine qualification belongs to plan v6's separate `egress`
item (`tests/egress_qualification.py`, frozen later). Sandbox-v3 does not read
any external-egress receipt or contact any external endpoint. No egress code or
endpoint is provisioned here. The decision's off-machine requirement remains a
later release/default-on gate; it is not inferred from loopback.

All 16 on-machine network rows retain every ID, operation, expected verdict,
logging variant and operation control from v2: default IPv4/IPv6, wrong port,
declared IPv4/IPv6 ports, alternate loopback, empty-policy IPv4/IPv6 non-loopback
bind, UDP default, HTTP/CONNECT undeclared proxies, declared IPv4/IPv6 bind,
declared HTTP/CONNECT proxies and UDP denied despite a declared TCP port.
Eleven rows replace only the old shared evidence line with:
"declared destinations are exact canonical TCP tuples; effective
bind/inbound/outbound and internal-proxy grants match the versioned profile
specification, with residual limits explicitly receipted". The other five rows'
evidence strings remain unchanged. Successful native bind observations still
must match the requested address and port.

## New rejection cases and limits

Nineteen PROFILE_* cases cover missing/additional/duplicate/malformed rules,
broadened host, ip replacing tcp, wildcard port, local outbound predicate,
unaccounted proxy or Unix-socket authority, changed default, failed/unavailable
inspection, unknown syntax, include/macro, network operation wildcard, a grant
outside a marked network section, and a changed non-network template. Each has
both logging modes, operation clean, group policy-dependency, expected
unverifiable/exit 2/launch=false. A declared synthetic port 12345 guarantees the
input mutation has an application rule to target. The adapter records the
before/inspected hashes; a rejection must retain the inspected hash and complete
bytes, exact_match=false and a precise nonempty error list. Effective rules on
rejection may be unavailable/unrecognized; they must not be repaired to pretend
the generated profile matched. No candidate operation or protected change is
allowed. The fixture only mutates validator input, not an actual launch profile.
The production validator's input/result and launch wiring remain source-review
requirements; JSON is not semantic attestation.

PATCH_AUTHENTICATION_FAILURE appends bytes to only the authenticated patch file
in a disposable bundle copy, retaining the original expected receipt/digests.
It expects exit 3 with no verdict, no candidate operation and no bundle-executable
Popen observed by the host adapter. The real bundle/judge is never mutated; no
patch is authored or applied by this freeze. This audit is bounded process-launch
evidence, not an exhaustive code-loading attestation.

The policy/dependency timeout becomes 1860 s using the same formula with the
approved v2 calibration floor and 40 added variants (289.44 s projected cost).
The other timeouts stay 3660/600/600; measure_cost.py writes sandbox-v3-costs.json
without overwriting v2 evidence. Actual full patched-backend cost is not measured.

Declared-port binding is address-wildcard TCP authority. At declared ports,
0.0.0.0, ::, mapped, alternate or available non-loopback local binds may succeed;
listeners may accept non-loopback inbound peers and exchange data. This is a
real inbound exposure and possible communication route. The localhost outbound
predicate is an OS address class, not a spelling filter; native/alias/mapped
behavior must be recorded for the exact platform. No universal mapped support
or literal-address-only claim follows. Exact ports identify no service/process
and authenticate no server; any allowed service may relay traffic. Isolated
fixtures/caller-reviewed services remain required. Permissions, occupancy and
races can still make allowed operations unavailable. No UDP/all-port grant,
external-egress qualification, complete log, invisible-attempt detection or
hostile-host containment is implied. These limits must also be in product README
and operator/check receipts at implementation; this fixture README is not that
later implementation proof.

The complete future matrix has not run: no sandbox code or qualified bundle yet
exists. Only fixture syntax/control behavior and the legacy counterexample are
measured by this freeze. IPv6, case aliases, /private aliases, exact ports and
backend enforcement require later platform qualification. Unsupported valid policy
must fail closed without launching a check; positive exact-port rows still must
succeed before sandbox acceptance. No inference of hostile intent, no exhaustive
secret inventory, no transient-write or invisible-attempt detection is promised.

## External bundle proposal (no provisioning)

Proposed macOS operator-owned location:
`/Library/Application Support/KernelRuntime/kernel-sandbox/0.0.81/<bundle-sha256>/`.
Root-owned non-replaceable ancestors/ACLs must exclude the candidate and agent
identity from writes. chmod by that same writable owner is not qualification.
An administrator/operator provisions it in a separately authorized phase; neither
verification nor this branch installs/downloads anything. Node, supervisor and
srt are kernel runtime dependencies, not a Python-only installation.

Pin srt 0.0.81 and the exact transitive lock bytes from spike/package-lock.json:
`53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9`.
Pin Node v24.22.0 per OS/architecture, the original distribution artifact SHA-256
AND extracted executable SHA-256. No artifact hash is invented or treated as
qualified here: it is a required operator receipt field, with origin/signature
verification and OS/build/architecture qualification to be reviewed later.
Canonical bundle digest: SHA-256 of sorted JSON rows {path,type,mode,sha256/target}
for the complete bundle, including supervisor, srt/transitives/lock and Node;
reject aliases/outside dependencies. Bind bundle manifest, Node archive/executable
and lock digests in a caller-held operator release receipt under equally protected
ancestors, then bind that receipt in the kernel release manifest. A receipt read
only beside candidate-writable files is not a trust anchor.
