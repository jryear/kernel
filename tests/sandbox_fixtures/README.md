# Sandbox v1 freeze interface and evidence ceiling

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
counterexample to SANDBOX_MATRIX_BOUNDARY. This is not an unknown CLI option,
version sniff, missing API, missing Node, fabricated receipt, or setup failure.
The full matrix short-circuits after that concrete counterexample; all later
rows are explicitly **not qualified**, never counted individually RED or GREEN.
No actual installed judge, real secret, or real runtime bundle is attacked.

If the boundary gate denies the operation, the full matrix must run. No early
success exists. Missing qualified bundle, external-egress fixture, API, evidence,
provisional/final JSON or cleanup raises without the outer schema-2 receipt:
the installed judge must call that unavailable, never meaningful RED or GREEN.
Finite observed assertion mismatches can return a complete fail result. Each
row must pass before the outer result can pass. Tests already satisfied by old
cleanup/result handling are not advertised as novel failing assertion IDs.

The contract has one acceptance assertion for this conjunction, not 182 claims
that every individual case newly fails in 3.1.0. The reviewed suite remains a
trusted-harness assumption: valid JSON alone cannot attest semantic execution.

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
  bundle_digest. Paths must be regular and relative, with protected ancestors.
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

## Parent receipt schema and independent effects

A per-check `sandbox_receipt` (or top-level prelaunch failure receipt) has schema=1,
requested/enforced state plus identity, release, bundle, platform, policy,
lifecycle, integrity, diagnostics, decision, assurance. These are the decision's
required sections, not a child-written substitute for a final receipt.

- release.manifest_sha256 binds the caller-held disposable subject-package digest.
  Bundle records exact srt_version=0.0.81, node_version=v24.22.0,
  node_artifact_sha256, and lock_sha256 matching the frozen transitive lock.
- identity includes unique run/check/phase/repetition; source bindings remain in
  existing schema-2 records. Platform identifies OS/build/architecture and runtimes.
- policy includes fresh scratch_root, normalized writable roots, secret denials,
  protected inventory, backend/internal-IPC exceptions, policy digest, and exact
  localhost_endpoints [{host,port,transport}]. Exact TCP tuples must equal the
  declared integers at 127.0.0.1 and ::1; wildcard, other 127/8, UDP and undeclared
  ports cannot silently appear. Runtime internal IPC is separately enumerated.
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
  complete_logs, semantic_attestation and exhaustive_descendant_containment are
  explicitly false. Supported covers only the bounded frozen claim.
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

## External egress and qualification limits

No external endpoint, privileged namespace or bundle is provisioned or contacted
in this phase. The separately frozen egress_probe.py permits only a numeric private
isolated endpoint, never DNS, real credentials, or arbitrary Internet addresses.
For future qualification the operator supplies KERNEL_SANDBOX_EGRESS_RECEIPT and
its caller-held SHA-256 in KERNEL_SANDBOX_EGRESS_RECEIPT_SHA256. Schema=1, kind is
isolated-network-fixture, with authorization_ref, qualification_sha256, endpoint
{address,port}, and independent observation_path journal. The qualified fixture
must echo a synthetic nonce and journal its hash, proving the unsandboxed control
is reachable. A denied operation AND absent candidate nonce establish the negative
case; missing traffic alone is insufficient. Missing authorization/qualification
is outer unavailable, never an external-egress pass. This qualification remains
unproved here; human authorization cannot be manufactured by a receipt field.

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
