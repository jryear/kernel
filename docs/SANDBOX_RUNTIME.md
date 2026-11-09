# Sandbox v5 runtime draft

Sandbox execution is opt-in and remains development work until the complete
reviewed sandbox-v5 freeze, qualification matrix and independent review pass. The runtime depends on
Node v24.22.0, `@anthropic-ai/sandbox-runtime` 0.0.81, the exact transitive
lock, the assembly patch `kernel-srt-0.0.81-exact-tcp-v1`, the trusted supervisor,
and the read-only profile validator. Checks do not download, install, patch, or
resolve dependencies.

The build-time patch also frames the embedded diagnostic collector's UTF-8
stream across pipe chunks and processes each denial with its own command tag.
It bounds partial lines at 65,536 characters and reports malformed, orphaned,
oversized or truncated framing as ambiguous evidence. The supervisor persists
subscription events through observed collector close and records arrivals after
the drain deadline as unavailable evidence. These repairs do not establish
complete OS delivery. Missing canary events alone do not change a verdict;
known loss, ambiguous attribution or incomplete shutdown remains unverifiable. Exact
patch bytes and changed module postimages are authenticated in each new bundle;
the TCP policy emission remains unchanged by the diagnostic framing repair.

Enabled collection also retains a separate raw stdout spool capped at 8 MiB,
with received/retained byte counts, hash, process identity, exact log predicate
and lifecycle timestamps. The supervisor observes the log command's startup
banner before publishing prepared launch data; that banner is startup progress,
not a readiness or completeness guarantee. The one-shot protected/scratch
canary uses isolated Python without site hooks. Its denied protected write and
successful scratch write remain launch gates; the bound event is diagnostic only. Missing events are never replaced by retries or quiet drains.

## Development bundle

Use an explicit trusted-caller opt-in (`KERNEL_SANDBOX_DEV=1`) only with the
local development receipt. Assembly creates a new directory at
`~/.local/state/kernel/dev-bundle-v3`; it refuses to replace an existing bundle
or receipt. It never writes the historical `dev-bundle` directory or
`~/code/_kernel`.

After the patch inputs and supervisor have been reviewed into the source tree:

```sh
python3 -B sandbox_runtime/assemble.py --dev \
  --node "$HOME/.local/bin/node" \
  --destination "$HOME/.local/state/kernel/dev-bundle-v3" \
  --receipt "$HOME/.local/state/kernel/dev-bundle-v3.receipt.json"
```

The assembler requires Node `v24.22.0`, checks the frozen lock SHA-256
`53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9`, runs
`npm ci` with scripts and network audit disabled in the fresh external staging
directory, and applies the exact patch with pre/postimage validation. This is
an operator/build action, never a verifier startup action. Its receipt has
`dev_only: true`, `qualification: "development-only"`,
`node.artifact_sha256: "UNQUALIFIED_LOCAL_EXECUTABLE"`, and the SHA-256 of the
actual executable bytes in the assembled bundle. The current local Node is a
Homebrew-linked build; the assembler copies its non-system dynamic libraries
into `node/lib` and relocates only the disposable development copies. It does
not qualify an official Node release, protected ownership, ACLs, or a production
bundle.

The bundle digest is SHA-256 of compact sorted-key JSON containing sorted
regular-file rows `{path, sha256, mode}`. The external receipt lists those same
files and binds the lock, Node version and executable, patch ID and patch-file
digest, changed-file preimages/postimages, and bundle digest. The receipt is
outside the digest tree to avoid self-reference.

## Operator provisioning

Production provisioning is Zack-only. Use an authenticated official Node archive
and checksum from the official Node release metadata. The archive digest must be
provided as an operator input; a locally computed executable digest is not a
substitute for the release artifact digest. Create a root-owned, non-writable
receipt parent outside candidate authority, then run:

```sh
sudo ./sandbox_runtime/provision.sh \
  --node-archive /absolute/path/node-v24.22.0-darwin-arm64.tar.gz \
  --node-archive-sha256 <authenticated-official-archive-sha256> \
  --receipt /absolute/protected/path/kernel-sandbox-bundle.json
```

Use the `darwin-x64` archive on Intel macOS. The script rejects unsafe receipt
ancestry, writable bundle ancestry, archive/version/hash mismatches, and any
existing digest directory or receipt. It must include the archive's Node
dynamic libraries with the executable, create the same patched bundle bytes
used for the inventory and digest, establish root ownership and deny ACLs,
write the caller-held receipt, and print its SHA-256. The verifier's trusted
caller authenticates that exact receipt digest using
`KERNEL_SANDBOX_BUNDLE_RECEIPT_SHA256`; the child environment cannot supply or
override the trust input. Do not run provisioning as part of this implementation
or a test.

## Policy and evidence limits

The versioned profile uses TCP-only exact-port rules. For each declared port,
Seatbelt grants bind and inbound access on host `*` at that port and outbound
access to the OS `localhost` address class at that port. This allows binding to
`0.0.0.0`, `::`, or another available local address on a declared port. A
listener can accept non-loopback inbound traffic and exchange data with peers.
This is an actual inbound exposure; the rules do not identify services, peers,
processes, or purpose. Empty declarations grant no application bind/inbound
ports. Undeclared ports, UDP, and unbounded localhost access are not allowed.

Seatbelt's `localhost` predicate is an OS address class, not a literal-address
spelling check. Native IPv4 and IPv6 loopback and this host's tested mapped
address behavior must be recorded for the exact OS/runtime. No universal mapped
address compatibility is claimed. Do not broaden outbound policy to repair an
unavailable mapped connection. Any reachable service on an allowed port can
receive candidate TCP and may itself relay traffic; allowed access does not
authenticate the service or guarantee availability. Isolated fixture services
and caller-reviewed services remain necessary.

The trusted proxy is separate from declared destinations. It may forward only
canonical loopback destination/port pairs and must reject alternate addresses,
arbitrary DNS forwarding, undeclared destinations, and UDP. Exact-profile
validation compares the complete generated policy and refuses unknown,
additional, missing, duplicate, wildcard-port, or non-TCP network grants.
Failure occurs before candidate launch; there is no broad-policy retry,
unsandboxed fallback, or alternate backend.

Receipts must not claim loopback-only binding, literal-address-only matching,
complete OS log delivery, absence of invisible attempts, no transient write and
restore, complete hostile-process containment, external-egress qualification,
service identity, or production readiness. These limits remain even when the
bounded frozen assertions pass.

## Advisory diagnostics and nested receipt schema 3

The November 9 amendment in `SANDBOX_DECISION.md` defines v5. The outer
verification protocol stays schema 2. Nested sandbox receipts use schema 3 and
`diagnostics.semantics="advisory-one-directional-v1"`. Requested mode stays
immutable. Event absence proves nothing and does not gate a verdict; collector
faults, known loss, invalid evidence, unresolved relevant attribution and
cross-invocation contamination still make execution unverifiable. All received
relevant unexpected denials contribute `observed_relevant_denial`, including
mid-check and drain arrivals.

The trusted operator request supplies `qualification_record` and
`qualification_record_sha256`. Each receipt retains that authenticated record,
actual OS/build/architecture, Python and Node versions, absolute executable
identities and digests. The historical measurement record describes one host;
it does not qualify a new bundle or a production installation.

`diagnostics.canary` binds run/check/phase/repetition, unique probe ID, exact
canonical target, command tag and session suffix, operation/result, actual
payload PID/start identity and executable digest. Parent preflight and syscall
intervals use Unix realtime, with a fixed one millisecond timestamp uncertainty;
no tolerance is increased after a miss. Occurrence time comes from retained raw
Sandbox-sender collector framing. Reception time and phase come from bounded
raw-chunk offset records. The same third-party Python operation preflight gates
launch in both modes. Enabled matches are `matched`, `absent` or `unmatched`;
disabled collection is `not_collected` with null event receipt. A match is only
a diagnostic observation. Process identities remain sampled evidence.

For a reviewed assertion explicitly testing a synthetic denial, the trusted
operator may supply `expected_denials`. Each declaration names a unique ID,
check, phase, assertion ID, exact operation and canonical target, frozen contract
SHA-256, source entry/path SHA-256, and actual executable SHA-256. The parent
validates these against the frozen check before matching observed PID/start,
executable and execution interval. Payload configuration, stdout/stderr and
provisional result text cannot grant an exemption. A different target or
unexpected denial remains unavailable evidence.

Sealed per-check receipts remain immutable. A subsequently received event with
a retained prior command/session identity is attributed to its original check.
The parent appends a correction naming the original receipt digest and origin,
marks the origin result and dependent aggregate unverifiable, and records
`diagnostic_cross_invocation` on the receiver. Unknown origin stays ambiguous;
no later check inherits an old denial. The test-only anonymous-pipe collector
preloads are not part of production launch or its configuration surface.
