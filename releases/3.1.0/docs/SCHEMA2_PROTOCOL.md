# Kernel 3.1.0 schema 2 evidence protocol — version 1

This protocol improves meaningful baseline failure, a declared protected command chain, and source artifact binding. It assumes a reviewed trusted frozen harness and a cooperative candidate. A process can forge JSON; this protocol is not an OS sandbox, proof of semantic truth, independent review attestation, external dependency hermeticity, or general service lifecycle assurance.

## Contract

`spec_version = 2` retains the existing id/project/goal/scope/notes fields. Every check, including regression, declares:

- `name`, `kind`, `timeout` (positive integer).
- `argv`: nonempty string array, executed directly with shell=False.
- `entry`: literal repository-relative regular file used as an argv element.
- `chain`: nonempty list of literal repository-relative supporting files, including entry. These files must exist at base, resolve within the snapshot, and contain no symlink, absolute path, parent traversal, or glob. Entry must also be included by `evidence` patterns. Interpreter inline-code/module modes (`-c`, `-m`), shell command strings, and package-script aliases are forbidden for this slice; argv must execute the declared file directly. Chain files are automatically protected regardless of mutable scope.
- `evidence`: nonempty frozen paths/patterns, as in schema 1.
- `assertions`: nonempty unique string IDs naming observable invariants checked by this check.
- `baseline_failures`: unique subset of assertions, nonempty for acceptance, empty for regression; adversarial may declare an empty or nonempty intended failure set.

Schema 2 forbids `cmd` and `expect_exit`, and cannot use shell strings for worktree setup or service start/ready/stop. Reject these combinations as SPEC_ERROR until an independently versioned structured lifecycle protocol exists. `[worktree].link` remains supported for declared external dependencies; links must not cover tracked source or evidence. Runtime executable availability and linked dependencies remain external inputs. This protocol protects the declared repository chain; the author must identify actual dynamic helpers and dependencies. It does not prove that declaration exhaustive.

## Terminal result

For each invocation the verifier creates a fresh file path outside tracked source, sets `VERIFY_RESULT_JSON` to it, and supplies `VERIFY_RUN_ID` (fresh nonempty token), `VERIFY_TREE` (`base` or `candidate`) and `VERIFY_ROOT` (the actual snapshot cwd). The trusted harness is the declared result writer. This policy is not enforced by OS permissions against candidate code.

A terminal JSON object is exactly:

```
{"protocol":1,"check":"check name","phase":"base","run_id":"token","assertions":[{"id":"OBSERVABLE_ID","status":"fail","detail":"observed old, expected new"}]}
```

Top-level keys and row keys are exact. Every declared ID occurs once, no extra IDs, and detail is a string. Status is `pass` or `fail`. Exit 0 requires all pass; exit 1 requires at least one fail. Other exits, missing/malformed/stale/wrong-phase/wrong-check/wrong-token/incomplete/duplicate results, and exit/status disagreement are harness failures. Exit 99 and timeout remain harness failures even if valid-looking JSON exists. Import/setup exceptions without a valid terminal result cannot establish RED. A reviewed harness must emit results only after reaching its assertions, never catch setup exceptions as assertion failure.

Baseline readiness requires each check's failing IDs to equal its `baseline_failures` exactly. Candidate support requires all checks' assertion IDs pass. Unexpected baseline assertion failure is NOT_READY. A valid unmet candidate assertion is CONTRADICTED. Invalid result or unavailable harness is UNVERIFIABLE/NOT_READY, never SUPPORTED/READY.

## Source identity

Before any checks (including baseline), require the input repository has no staged, unstaged or nonignored untracked paths. Resolve candidate HEAD and selected base/merge-base commits and their Git tree IDs once. Execute base and candidate in separate detached clean snapshots, never the caller's live tree. Preserve existing caller files; linked external inputs are not source content.

For each commit form a manifest of all tracked leaf files: sorted by path, rows `{ "path": relative_path, "mode": git_mode, "sha256": sha256(blob_bytes) }`. Serialize with Python `json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Its SHA256 is `manifest_sha256`; regular executable modes are included. Reject symlink evidence/chain paths. Gitlinks/submodules require explicit unsupported error rather than silently claiming their descendants bound.

After each tree finishes, compare tracked file bytes/modes, index and HEAD against the resolved snapshot; any mutation, deletion or HEAD change invalidates support. Also check the caller source remained at the original clean HEAD. Nonignored files created inside snapshots invalidate clean-source assurance. Verdict logs must be outside the caller repository for schema 2 (SPEC_ERROR otherwise); terminal JSON lives outside snapshots. Ignored scratch outputs are not part of the tracked source claim.

A successful schema2 JSONL record includes:

```
"assurance":"schema2-evidence-validity",
"source_binding":{
 "base":{"commit":"...","tree":"...","manifest_sha256":"..."},
 "candidate":{"commit":"...","tree":"...","manifest_sha256":"..."},
 "candidate_snapshot":true,"clean_before":true,"unchanged_after":true
}
```

Baseline with `--log` writes a corresponding record with `verdict` `baseline_ready` or `baseline_not_ready`, base binding and candidate input identity. For completion, every base/candidate check row records its validated assertion result or result protocol error and actual exit. Success does not erase raw check output. Printed output includes the assurance label. Verification remains source-only and cannot bind external services, runtime installation, linked dependencies or credentials.

## Legacy and adoption

Schema 1 retains 3.0.1 mechanical behavior and exit codes. Every schema1 completion record and stdout labels assurance `legacy-schema1`. Baseline stdout also includes that label. Do not silently strengthen or rewrite historical specs. Default task and AGENTS templates, README/FRONTIER and adoption guidance describe schema2 and the structured result writer; `adopt.py` copies the schema2 template while preserving existing destination files without `--force`. Version is 3.1.0. Existing old six plus twenty fixtures retain their exact bytes and pass together.

## Bootstrap independence

The slice's outer contract is schema1 because the sealed installed 3.0.1 is its bootstrap verifier. It runs a frozen independent stdlib CLI grader against the candidate verifier; the mutable verifier cannot certify its own acceptance. The grader's exit1 is reserved for named invariant failures, exit99 for fixture infrastructure unavailable. Independent direct receipts, exact Git revisions and review are required alongside the outer mechanical verdict. Original user false-support fixtures are reproduced on sealed3.0.1 and retained separately; legacy behavior remains visibly limited, not misrepresented as newly hardened.
