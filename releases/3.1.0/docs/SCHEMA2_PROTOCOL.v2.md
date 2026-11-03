# Schema 2 evidence protocol — rubric version 2

This explicit preimplementation correction supplements `SCHEMA2_PROTOCOL.md` version 1, frozen at `1afbc6f64598239b31a560e8f15180e377e4082c`. The JSON result protocol remains 1, TOML schema remains 2, and proposed kernel release remains 3.1.0. Version 1 records and fixtures are preserved. Four independent source-review defects in that rubric are corrected; they are not application findings.

## B1: integrity at each check boundary

Capture the committed source identity before checks begin. Before **and after every individual check**, compare that tree's tracked bytes, executable modes, index and HEAD with the captured commit. Also check source identity after the tree checks finish and before removing snapshots. A stage/edit, second check/use, third check/restore sequence must be UNVERIFIABLE even if the final tree matches the original. Mutation during a completed earlier check cannot be accepted as a later check's input.

This does not detect every transient write followed by restoration within one check, or mutation after the final observed boundary. It is source boundary assurance, not continuous process monitoring or an OS sandbox. The independent fixture deliberately exercises mutation between multiple checks.

## B2: precise argv entry grammar

For this slice, accept only these forms:

1. Direct executable: `[entry, ...script_args]` or `["./" + entry, ...script_args]`, with frozen regular executable entry.
2. Recognized interpreter: `[runtime, entry, ...script_args]`.
3. Recognized interpreter with one delimiter: `[runtime, "--", entry, ...script_args]`.

Recognized interpreter executable basenames are `python`, `python3`, `python3.<digits>`, `node`, `bash`, or `sh`. Runtime is an external executable, not a repository helper or symlink into mutable source. No other interpreter flags precede entry. Entry must be the directly executed script at the specified position; finding the entry anywhere later in argv is insufficient. For example `[python, mutable_runner.py, frozen_entry.py]` and `[python, "--", mutable_runner.py, frozen_entry.py]` are SPEC_ERROR, even though the frozen entry appears as an argument. A repeated or misplaced pre-entry delimiter is SPEC_ERROR. Script arguments after the direct entry are opaque script inputs. Shell `-c`, Python `-c`/`-m`, package runners and unknown launcher grammars remain unsupported until separately contracted.

The direct entry and declared supporting chain retain the version1 evidence/path protection requirements. This grammar is explicit and bounded; it is not proof of every runtime's internal implementation.

## B3: byte-safe manifest oracle and modes

Read tracked Git object bytes directly. Do not decode blob content as text or normalize newline sequences. Repository filenames are UTF-8 strings in the documented canonical manifest; preserve spaces and non-ASCII characters. A tracked path that cannot be decoded as UTF-8 is explicitly unsupported rather than silently renamed. Git NUL-delimited tree enumeration avoids quoting and whitespace ambiguity. Binary PNG-like bytes, CRLF content and a filename containing both a space and non-ASCII characters are included in the independent positive fixture. Executable-mode change invalidates source identity even when bytes are unchanged. The mode fixture sets Git `core.fileMode=false`; a Git-status-only check misses the physical executable-bit change.

The manifest remains sorted rows `{path, mode, sha256}`, canonical JSON using `ensure_ascii=False`, `sort_keys=True`, `separators=(",", ":")` and UTF-8 bytes. This corrects the version1 grader's text-only oracle. It adds no claim about linked dependencies, runtime binaries, database/provider data or hostile receipt forgery.

## B4: every check kind and actual baseline CLI

Regression and adversarial checks use the same complete terminal result handshake and declared-chain protection as acceptance. Positive controls exercise all three kinds. Missing/malformed results for secondary regression/adversarial checks cannot support a claim; changing a helper declared only by such a secondary check contradicts it.

Actual `--baseline` invocation must reject import/setup exceptions, unexpected failed assertions, or a valid result whose failed-ID set differs from the declared expected baseline failure set. Schema1 baseline output visibly records `legacy-schema1`; its historical mechanical readiness rules remain unchanged.

## Versioned verification

`tasks/kernel-evidence-validity-001-v2.toml` runs the unchanged version1 core, negative and original26 regression commands together with new version2 fixtures. Version2 uses a byte-safe subclass oracle and appends twelve named cases for these four findings. Original assertions and source files remain frozen; implementation cannot change either rubric. A later genuine rubric defect requires another explicit version and full old/new rerun.
