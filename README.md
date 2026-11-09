# Kernel 3.1.0 schema 2 evidence workflow

New contracts use schema 2. Historical schema 1 retains its mechanical behavior
and carries visible `legacy-schema1` assurance. Do not rewrite frozen contracts
in place: migration requires a versioned contract, independent evidence review,
a fresh trusted committed baseline and renewed RED-to-GREEN evidence.

Use Python 3.11+ and the external read-only verifier. Commit the task and reviewed
harness before implementation. The caller must be a clean exact Git commit;
staged, unstaged and nonignored untracked inputs are rejected. Base and candidate
checks execute from separate fixed snapshots. Choose the trusted base with `--base`
or `VERIFY_BASE`, never a candidate-controlled TOML field.

```bash
python3 ~/code/_kernel/adopt.py /path/to/repo --project project
python3 ~/code/_kernel/verify.py tasks/TASK.toml --repo . --base FROZEN --baseline
python3 ~/code/_kernel/verify.py tasks/TASK.toml --repo . --base FROZEN \
  --claim "observable result" --implementer-model "actual model/runtime" \
  --log /private/external/path/claims.jsonl
```

Adoption preserves existing destinations unless `--force` is supplied and always
preserves existing AGENTS.md. It copies a runnable `evidence/schema2_check.py`
example observing app.txt. Prepare app.txt with `old` on base and change it to
`new` on candidate. Rename and review the task before freezing it. Do not mistake
the example for an application acceptance contract. Default schema2 logs are in
an external temporary directory; an explicit log must also be outside the caller.

Every check kind declares name/kind/positive integer timeout, structured argv,
entry, complete repository chain, evidence patterns, unique assertion IDs and
exact baseline failed IDs. Acceptance has at least one intended baseline failure;
regression has none; adversarial specifies its intended base failures explicitly.
All candidate assertions must pass. Plain exit1, missing imports, setup errors,
missing/invalid receipts, timeout or reserved99 never establish meaningful RED.
Reviewed harnesses emit a complete protocol1 terminal JSON result only after
observing their assertions. Setup exceptions must propagate without a receipt.
The example shows VERIFY_RESULT_JSON, VERIFY_RUN_ID, VERIFY_TREE and VERIFY_ROOT.
Fresh complete results and exit/status consistency are validated for every kind.

Allowed argv is [entry,args...], [runtime,entry,args...] or
[runtime,"--",entry,args...]. The direct entry must be executable. Recognized
external runtime basenames: python, python3, python3.<digits>, node, bash, sh.
No flags precede entry except the one delimiter. Script arguments after entry
are opaque inputs. Shell strings, inline/module execution, package aliases,
setup commands and service lifecycle commands are unsupported in schema2.
Entry and all declared chain files must be base-tracked regular files, with
entry included by evidence. Symlink evidence/chain and gitlinks are unsupported.

Tracked leaf bytes, executable modes, index and HEAD are checked before and after
every check and at the final observed tree boundary. Bindings record fixed commit,
Git tree and canonical byte-safe manifest digest; UTF8 names include spaces and
non-ASCII, while invalid UTF8 names are explicitly unsupported. Ignored outputs
are outside source binding. Optional worktree.link dependencies cannot overlap
tracked source or evidence, need committed ignore rules to remain clean, and are
reported separately as external inputs. Runtime installations and linked inputs
are not covered by source assurance.

This is observed source boundary assurance under a reviewed trusted harness,
not malicious-code sandboxing, semantic execution proof, independent review
attestation, exhaustive dynamic dependency protection, external hermeticity,
general service lifecycle/descendant cleanup, or product/provider readiness.
A process can fabricate a valid JSON receipt. Review must inspect assertions and
setup exception boundaries and challenge no-op reporters. Transient self-restoring
mutation entirely within one invocation or after the final observed boundary
remains outside detection. Checks protect only the declared execution chain;
reviewers must identify actual helpers, imports and configuration.

Exit0 means SUPPORTED/BASELINE_READY for the stated protocol; exit1 means
CONTRADICTED, exit2 UNVERIFIABLE/BASELINE_NOT_READY, exit3 SPEC_ERROR. Review
metadata is recorded as a declaration and does not prove independent review.
Local checks, contract support, UI judgment, provider evidence and release
acceptance remain distinct. Installation or publication requires separate authority.

Startup release integrity requires a trusted SHA-256 of MANIFEST.sha256 from
outside the candidate: --release-sha256 HEX or VERIFY_RELEASE_SHA256. Missing
digests or changed release bytes refuse with exit 3 before judging or importing
runtime modules. Publish/hold that digest separately; calculating it from an
untrusted candidate is not authentication. The caller must authenticate verify.py
itself externally: replacing the entire guard remains outside self-check assurance.
For local development only, an operator can compute a digest of their reviewed
package and export it before running the six legacy regression tests.

Schema1 and schema2 checks now start in a separate POSIX session/process group. The receipt
records group cleanup, observed descendants, escaped survivors, timeout and OS
kill/observation failures. Survivors and missing cleanup/assertion evidence make
the verdict unverifiable. Escaped descendants are named even when best-effort
remediation subsequently kills them. Detection uses ps sampling plus an inherited
invocation marker; hostile children can erase it and escape between observations.
This is observed cleanup evidence, not exhaustive containment or sandboxing.
Legacy schema1 services (as distinct from checks) remain outside this guarantee.

## Sandbox v3 runtime boundary

The opt-in macOS sandbox runtime is a separately assembled dependency bundle,
not part of the Python-only install. It pins Node v24.22.0, srt 0.0.81, the
frozen transitive npm lock, the reviewed exact-TCP patch, supervisor, and profile
validator. See [docs/SANDBOX_RUNTIME.md](docs/SANDBOX_RUNTIME.md) for fresh
external assembly, receipt authentication, and the Zack-only provisioning
command. Verification itself never installs or patches dependencies.

The sandbox-v3 receipt binds the complete regular-file bundle inventory and
patch preimages/postimages. Development receipts state `dev_only: true` and
`qualification: "development-only"`; they do not establish production trust or
qualification. The exact-port profile permits wildcard-address TCP bind and
inbound at declared ports, so a listener may expose data beyond localhost.
The `localhost` predicate is an OS address class and does not guarantee literal
address spelling. No service identity, external-egress restriction, complete
logging, invisible-attempt detection, or exhaustive process containment is
claimed. A passing bounded check is not a production release or authorization.

Sandbox diagnostic logging is advisory: logs are diagnostic, and absence proves
nothing. An observed, attributed, relevant unexpected denial makes the affected
check unverifiable, including during the check or drain. A missing event alone
does not. Enabled collector failure, overflow, known loss or ambiguous relevant
attribution still makes the check unverifiable. On one macOS 27.0 arm64 host,
cold, spaced probes logged Apple system-binary denials 22/22 and third-party
denials 0/27 while all 49 writes were blocked. Signing, system-volume location
and runtime identity were not separated causes; rapid-cadence Python delivery
remains unexplained. These observations are not a universal delivery rate or a
proven OS mechanism.

A candidate that swallows a denial whose event is never delivered can be
supported when all observable required evidence passes. Neither absent logs nor
unchanged hashes detects that attempt. Hashes establish lasting changes at
measured boundaries, not absence of attempts, transient writes or reads. The
non-network profile comparison shares a generator and is not an independent
semantic oracle. The caller must authenticate the verifier entrypoint externally.
