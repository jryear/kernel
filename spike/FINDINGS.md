# srt 0.0.81 architecture spike — 2026-11-03

Research only. No sandbox product path, default change, installation of a kernel
release, or release claim was implemented. `sandbox_probe.py` exits 0 when the
research run completed and recorded observations. It does not decide a pass or a
kernel verdict. Setup exceptions do not become successful security evidence.

## Reproduce and inspect

- Dependency: `npm ci --prefix spike --no-audit --no-fund` (exact 0.0.81 in
  package.json and package-lock.json; no global installation).
- Run: `python3 spike/sandbox_probe.py`. Generated results are under ignored
  `spike/results/`. The committed `evidence/observations.json` and filtered
  `evidence/cli-collector.log` preserve the reviewed implementation run.
- Observations bind package source bytes and probe/lockfile bytes. This run used
  macOS on this machine, Node and Homebrew Python 3.15; it is not Linux evidence.
- No secret contents were read: synthetic `.env` and SSH fixtures were used, plus
  an open-and-close attempt on the real `~/.ssh` directory without reading bytes.
  All application connections were loopback. External egress was not exercised.

## Observations

| Case | CLI | Embedded library |
| --- | --- | --- |
| Collector before check | Separate `/usr/bin/log stream` started before CLI, alive after 700 ms | Store subscription before initialize, initialize with monitor enabled, then 700 ms delay |
| Known-denied canary | EPERM; no matching external canary log in committed run | EPERM and one matching subscribed denial |
| 150 denied writes | 150 EPERM; 150 matching external log lines | 150 EPERM; 148 matching subscribed denial events |
| Write confinement | Allowed directory write succeeded; explicitly protected and unlisted temp paths returned EPERM | Same; protected fixture hashes unchanged before/after each case |
| Read denial | Synthetic SSH fixture, `.env`, and actual SSH directory open returned EPERM | Same |
| Loopback policy | Direct 127.0.0.1 worked; proxy request to non-allowlisted 127.0.0.2 returned HTTP 403 | Same |
| Events after exit | Collector bytes increased after exit in late case; delayed child denial was observed | Burst 157 events at exit and after drain; late case 11 at exit, 17 after drain |

Counts above refer to the committed observation, not future desk reruns. The
embedded counts include startup/system denials; matching the canary path isolates
the actual burst denial count. An attempted denial does not establish intent.
Two seconds is an observation window, not proof that no later events exist.

The actual embedded session received 221 subscription events but retained only
100 at the end. A separate **synthetic store-only** exercise inserted 150 events:
`getTotalCount()` was 150, retained tail was 100, preattached subscription saw 150.
This confirms truncation independently of OS log delivery. A subscription can
avoid the store's truncation; it cannot recover events the upstream monitor
never emitted. The burst's 148 matching events for 150 EPERM outcomes is an
observed completeness gap, not proof of its root cause or misattribution. The committed CLI run also had a missing first canary log despite EPERM;
its collector process was alive, but readiness was unacknowledged. No claim
of universally dropped or misattributed macOS events follows from these samples.

## Source facts in the pinned local package

- `dist/cli.js:399` calls `SandboxManager.initialize(runtimeConfig)` without
  requesting the log monitor. CLI confinement is usable; its built-in invocation
  does not supply a filesystem violation evidence stream. Our CLI log stream is
  a separate host collector, not evidence of CLI's own monitor.
- `dist/sandbox/sandbox-manager.js:777` defaults `enableLogMonitor` to false;
  `:845` starts macOS monitoring when true. `initialize` returns after starting
  the stream, without an acknowledged collector-ready protocol.
- `dist/sandbox/sandbox-violation-store.js:9` sets maxSize to 100; `:23` truncates
  the tail. Subscribe before executing and persist externally; polling the tail
  after a check cannot reconstruct a large burst.
- `dist/sandbox/macos-sandbox-utils.js:1223` splits stdout chunks and uses
  `.find` for a violation and a command line. Chunk batching/fragmentation is a
  plausible contributor to missing/misattributed evidence; this spike did not
  isolate that cause. Attribution carriers are not authenticated intent.

## Recommendation, not implementation

Prefer the **embedded library in a trusted host-side supervisor**. It provides
explicit monitor enablement, subscription before execution, unique command IDs,
and lifecycle control for a drain after leader exit. CLI remains usable as a
confinement wrapper only, with a separately supervised collector when explanatory
logs are wanted. Neither path supplies a complete authoritative denial ledger.

Keep the trusted verifier, frozen contract, fixtures, protected source metadata,
receipt writer, expected release digest and the pinned srt installation outside
all candidate write roots. The local installation here is for research only;
putting product srt in writable candidate node_modules would allow replacement
before a later invocation. Restrict writes to the exact per-check disposable
directory, deny secret reads explicitly, and configure only required loopback
network paths. Fail closed on dependency/setup/cleanup uncertainty.

Hash protected paths before and after **each check** outside the candidate's
write authority, including the contract, verifier components, evidence and Git
metadata. A deterministic forbidden change is contradiction; missing/ambiguous
hash or execution evidence is unverifiable. Missing logs never establish safety
or a contradiction. Keep syscall/effect observations, boundary hashes, process
cleanup evidence and explanatory logs distinct. Subscription overflow, monitor
failure, a missing canary or ambiguous attribution must be recorded explicitly.
A bounded drain is useful operationally but must not certify log completeness.
Transient self-restoring tampering remains a separate boundary to address with
confinement; endpoint hashing alone does not prove it absent.

## Limits left open

External egress blocking is **not dynamically proved**, to honor the task's
no-network boundary. The non-allowlisted proxy probe uses only 127.0.0.2 and
cannot accidentally dial an external host. Source/policy inspection supports the
configured localhost-only intent; it is not an external network escape test.
Neither collector offers a ready acknowledgement. This spike does not prove
exhaustive denial capture, attribution correctness, multi-check isolation,
production readiness, Linux behavior or security under malicious srt replacement.
