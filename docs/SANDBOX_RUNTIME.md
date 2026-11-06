# Kernel sandbox runtime bundle

**Status: BLOCKED; do not provision or claim qualification.** The v2 implementation
has not supplied a trusted supervisor yet, and source investigation found that
pinned srt 0.0.81 does not express the frozen exact localhost-port policy. The
architecture decision requires unsupported valid policy to fail closed and
return to architecture review. Until that boundary is resolved and the supervisor
is implemented/reviewed, `sandbox_runtime/provision.sh` intentionally refuses to
run and the command below is a future operator command only.

Sandbox execution is opt-in (`VERIFY_SANDBOX=1`) and requires the separately
provisioned, authenticated macOS runtime. The repo stages the exact
`@anthropic-ai/sandbox-runtime` 0.0.81 dependency and transitive lock from the
sandbox spike. The supported Node target is v24.22.0. No check downloads or
installs a dependency.

## Prepare and provision

Zack must obtain the official Node v24.22.0 macOS archive for the target
architecture and verify its SHA-256 against the official Node release checksum
before invoking the operator script. Create a caller-held receipt parent outside
the repository and all candidate-writable roots, then run from the repository:

```sh
sudo ./sandbox_runtime/provision.sh \
  --node-archive /absolute/path/node-v24.22.0-darwin-arm64.tar.gz \
  --node-archive-sha256 <verified-official-archive-sha256> \
  --receipt /absolute/protected/path/kernel-sandbox-bundle.json
```

Use `darwin-x64` on Intel macOS. After the architecture gate is resolved, the script checks the supplied archive
digest, archive layout, executable version and exact npm lock; stages the
supervisor, locked srt dependencies and exact Node executable; computes the sorted
canonical bundle digest; then places the bundle under
`/Library/Application Support/KernelRuntime/kernel-sandbox/0.0.81/<digest>/`.
It sets root ownership, removes group/other write permission, adds an explicit
write-deny ACL, and refuses to overwrite an existing digest directory or
receipt. It writes the receipt to the caller-provided protected path and prints
the receipt SHA-256. Zack must retain that digest as a caller-held trust input
outside candidate authority. The script does not provision or qualify any
external endpoint.

The canonical bundle digest is SHA-256 over compact sorted-key JSON for the
sorted relative-path inventory, including directories and regular files. The
receipt `files` array contains regular files only, matching the fixture reader
interface; symlinks and special files are rejected. Each file row is
`{path,type,mode,sha256}`. The external operator receipt
contains these rows, the absolute bundle root, `srt_version`, exact lock digest,
Node archive and executable digests, Node version and `bundle_digest`. The
receipt is separate from the digest directory, avoiding a self-referential hash.
Provisioning authenticates the Node archive bytes against the operator-supplied
official checksum. The final directory is immutable to ordinary candidate
identities; the operator owns the trust boundary and must keep the receipt under
ancestors the candidate cannot replace.

At the current architecture stop the script checks for the missing
`sandbox_supervisor.mjs` and exits before creating any `/Library` path. Once a
reviewed supervisor and an exact-port backend exist, it assumes the platform's
`npm`, `python3`, `tar`, `shasum`, `chown`,
`chmod` and `find` tools are trusted. It never runs `sudo` internally and must
only be run by Zack after reviewing the exact command and receipt destination.
Do not run it during development or from an acceptance check.

## Development bundle

A development bundle may use the locally installed exact Node v24.22.0 binary
and the same locked npm dependencies in `~/.local/state/kernel/dev-bundle`.
It must live outside the repository and `~/code/_kernel`. A development receipt
must set `dev_only: true`, state that the Node archive artifact digest is
unavailable/unqualified, and include the actual executable digest. It is useful
for local test wiring only; it cannot qualify a production bundle, Node artifact,
filesystem ownership, ACL, or release trust. The official provisioning script refuses development receipts and accepts only
a verified official Node archive. No development receipt is currently available
because the trusted supervisor is absent.

The trusted Python parent authenticates the receipt and launches the trusted
Node supervisor from the same bundle. The supervisor imports the embedded srt
library by an absolute bundle-relative path and starts only the sandboxed check
under the effective policy. Node, the supervisor, srt, its complete transitive
lock, OS build and architecture are part of the supported runtime identity.
Any enforcement dependency upgrade requires new qualification. Missing Node,
sandbox facilities, policy support, authentication or receipt evidence fails
closed; checks never fall back to unconstrained execution.

No four-check GREEN or DEV-ONLY claim is available in this blocked state.
Development results, if produced after the architecture gate is resolved, must be
labelled DEV-ONLY. Qualification waits for Zack's separately provisioned bundle
and the external installed-judge claim. This
implementation does not qualify off-machine egress, Linux or VM enforcement,
complete OS log delivery, invisible attempted operations, transient writes,
semantic execution, or exhaustive hostile descendant containment.
