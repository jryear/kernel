#!/usr/bin/env python3
"""Mechanical completion gate for contracted agent work.

A contract is trusted only when it is committed at the selected base revision.
The implementation agent owns *how* the outcome is achieved; this verifier only
judges whether the frozen observable contract was satisfied.

Normal completion establishes:
  1. the frozen task spec came from the base revision, never the candidate copy
  2. acceptance checks are RED on a clean base worktree and GREEN on candidate
  3. regression checks pass on both base and candidate
  4. adversarial checks pass on candidate
  5. declared evidence, protected paths, the task spec, and verifier are unchanged
  6. obvious test bypasses were not introduced
  7. every implementation change is inside declared scope

Verdicts:
  SUPPORTED     exit 0  contract evidence supports the completion claim
  CONTRADICTED  exit 1  candidate behavior or diff contradicts the contract
  UNVERIFIABLE  exit 2  evidence cannot establish the claim
  SPEC_ERROR    exit 3  invalid invocation or contract

`--baseline` checks whether a newly frozen contract is ready for delegation:
acceptance is red on base, regressions are green, and the evidence harness runs.

Python 3.11+, standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

VERIFIER_VERSION = "3.1.0"
SPEC_VERSION = 1
KINDS = ("acceptance", "adversarial", "regression")
HARNESS_EXIT = 99
DEFAULT_BASE = "main"
DEFAULT_PROTECTED = ["tests/acceptance/*"]
DEFAULT_TEST_GLOBS = ["*test*", "*spec*", "*__tests__*"]
BYPASS = re.compile(
    r"\.(skip|only)\s*\("
    r"|\b(xit|xdescribe|xtest|fit|fdescribe)\s*\("
    r"|\b(it|test|describe)\.(todo|skip|only)\b"
    r"|@ts-(ignore|nocheck|expect-error)"
    r"|pytest\.mark\.(skip|xfail)|unittest\.skip"
    r"|eslint-disable"
)


class SpecError(ValueError):
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    if check and result.returncode:
        raise SpecError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip() if result.returncode == 0 else ""


def repo_relative(repo: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return None


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def changed_files(repo: Path, merge_base: str) -> list[str]:
    """Committed-since-base + staged + unstaged + untracked."""
    files = set(filter(None, git(repo, "diff", "--name-only", merge_base).splitlines()))
    files |= set(filter(None, git(repo, "ls-files", "--others", "--exclude-standard").splitlines()))
    return sorted(files)


def added_lines(repo: Path, merge_base: str, path: str, untracked: set[str]) -> list[str]:
    if path in untracked:
        try:
            return (repo / path).read_text(errors="replace").splitlines()
        except OSError:
            return []
    diff = git(repo, "diff", "-U0", merge_base, "--", path, check=False)
    return [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]


def tracked_files_at(repo: Path, revision: str) -> list[str]:
    output = git(repo, "ls-tree", "-r", "--name-only", revision)
    return [line for line in output.splitlines() if line]


def expand_patterns(paths: list[str], patterns: list[str]) -> set[str]:
    return {path for path in paths if matches(path, patterns)}


def require_string(mapping: dict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SpecError(f"spec field {key!r} must be a non-empty string")
    return value.strip()


def require_string_list(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise SpecError(f"{label} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise SpecError(f"{label} must not be empty")
    return [item.strip() for item in value]


def validate_spec_legacy(spec: dict) -> tuple[list[dict], dict]:
    if not isinstance(spec, dict):
        raise SpecError("task spec must be a TOML table")

    allowed_top = {
        "spec_version", "id", "project", "goal", "bypass_policy",
        "scope", "worktree", "service", "checks", "notes",
    }
    unknown_top = sorted(set(spec) - allowed_top)
    if unknown_top:
        deprecated = {"base", "require_red", "timebox_minutes"}.intersection(unknown_top)
        if deprecated:
            raise SpecError(
                "deprecated/inert task fields are not allowed: " + ", ".join(sorted(deprecated))
                + "; base is selected at invocation, RED→GREEN is mandatory, and timeboxes are operator metadata"
            )
        raise SpecError("unknown top-level task fields: " + ", ".join(unknown_top))
    version = spec.get("spec_version")
    if version != SPEC_VERSION:
        raise SpecError(f"spec_version must be {SPEC_VERSION} (got {version!r})")
    require_string(spec, "id")
    require_string(spec, "project")
    require_string(spec, "goal")

    bypass_policy = spec.get("bypass_policy", "fail")
    if bypass_policy not in ("fail", "flag"):
        raise SpecError("bypass_policy must be 'fail' or 'flag'")
    scope = spec.get("scope", {})
    if not isinstance(scope, dict):
        raise SpecError("[scope] must be a table")
    unknown_scope = sorted(set(scope) - {"include", "exclude", "protected", "test_files"})
    if unknown_scope:
        raise SpecError("unknown [scope] fields: " + ", ".join(unknown_scope))
    include = require_string_list(scope.get("include", ["*"]), "scope.include", allow_empty=False)
    exclude = require_string_list(scope.get("exclude", []), "scope.exclude")
    protected = require_string_list(scope.get("protected", DEFAULT_PROTECTED), "scope.protected")
    test_files = require_string_list(scope.get("test_files", DEFAULT_TEST_GLOBS), "scope.test_files")

    raw_checks = spec.get("checks", [])
    if not isinstance(raw_checks, list):
        raise SpecError("[[checks]] must be an array of tables")
    checks: list[dict] = []
    names: set[str] = set()
    for index, raw_check in enumerate(raw_checks, start=1):
        if not isinstance(raw_check, dict):
            raise SpecError(f"check #{index} must be a table")
        unknown_check = sorted(set(raw_check) - {"name", "kind", "cmd", "expect_exit", "timeout", "evidence"})
        if unknown_check:
            raise SpecError(f"check #{index} has unknown fields: {', '.join(unknown_check)}")
        cmd = require_string(raw_check, "cmd")
        name = raw_check.get("name", cmd)
        if not isinstance(name, str) or not name.strip():
            raise SpecError(f"check #{index} name must be a non-empty string")
        name = name.strip()
        if name in names:
            raise SpecError(f"check names must be unique: {name!r}")
        names.add(name)
        kind = raw_check.get("kind", "acceptance")
        if kind not in KINDS:
            raise SpecError(f"check {name!r} has kind {kind!r}; expected one of {KINDS}")
        try:
            expect_exit = int(raw_check.get("expect_exit", 0))
            timeout = int(raw_check.get("timeout", 300))
        except (TypeError, ValueError) as error:
            raise SpecError(f"check {name!r} expect_exit/timeout must be integers") from error
        if expect_exit == HARNESS_EXIT:
            raise SpecError(f"check {name!r} cannot expect reserved harness exit {HARNESS_EXIT}")
        if timeout <= 0:
            raise SpecError(f"check {name!r} timeout must be > 0")
        evidence = require_string_list(raw_check.get("evidence", []), f"check {name!r} evidence")
        if kind in ("acceptance", "adversarial") and not evidence:
            raise SpecError(
                f"check {name!r} ({kind}) must declare evidence files/patterns; "
                "declared evidence is automatically protected"
            )
        checks.append({
            **raw_check,
            "name": name,
            "kind": kind,
            "cmd": cmd,
            "expect_exit": expect_exit,
            "timeout": timeout,
            "evidence": evidence,
        })

    if not any(check["kind"] == "acceptance" for check in checks):
        raise SpecError("contract needs at least one acceptance check")

    return checks, {
        "include": include,
        "exclude": exclude,
        "protected": protected,
        "test_files": test_files,
        "bypass_policy": bypass_policy,
    }


def validate_spec(spec: dict) -> tuple[list[dict], dict]:
    if isinstance(spec, dict) and spec.get("spec_version") == 2:
        from kernel_runtime import validate_spec as validate_schema2
        try:
            return validate_schema2(spec, validate_spec_legacy)
        except (ValueError, OSError) as error:
            raise SpecError(str(error)) from error
    return validate_spec_legacy(spec)


def load_frozen_spec(repo: Path, spec_path: Path, merge_base: str) -> tuple[dict, bytes, str]:
    rel = repo_relative(repo, spec_path)
    if rel is None:
        raise SpecError("task spec must live inside the repository")
    result = subprocess.run(["git", "show", f"{merge_base}:{rel}"], cwd=repo, capture_output=True)
    if result.returncode != 0:
        raise SpecError(
            f"task spec {rel!r} is not committed at base {merge_base[:12]}; "
            "freeze the contract before delegating implementation"
        )
    raw = result.stdout
    try:
        spec = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SpecError(f"frozen spec parse error: {error}") from error
    return spec, raw, rel


def load_review_metadata(path: Path | None) -> dict:
    empty = {"ran": None, "reviewer_model": None, "findings": [], "accepted_findings": []}
    if path is None:
        return empty
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SpecError(f"review metadata error: {error}") from error
    if not isinstance(value, dict) or set(value) != set(empty):
        raise SpecError(f"review metadata must contain exactly: {', '.join(empty)}")
    if value["ran"] is not None and type(value["ran"]) is not bool:
        raise SpecError("review metadata 'ran' must be true, false, or null")
    if value["reviewer_model"] is not None and (
        not isinstance(value["reviewer_model"], str) or not value["reviewer_model"].strip()
    ):
        raise SpecError("reviewer_model must be a non-empty string or null")
    findings = value["findings"]
    if not isinstance(findings, list) or any(
        not isinstance(item, dict)
        or set(item) != {"id", "kind", "summary", "citations"}
        or not all(isinstance(item[key], str) and item[key].strip() for key in ("id", "kind", "summary"))
        or item["kind"] not in ("counterexample", "unapproved_check")
        or not isinstance(item["citations"], list)
        or not item["citations"]
        or not all(isinstance(citation, str) and citation.strip() for citation in item["citations"])
        for item in findings
    ):
        raise SpecError("review findings need id, kind, summary, and non-empty citations")
    ids = [item["id"] for item in findings]
    if len(ids) != len(set(ids)):
        raise SpecError("review finding ids must be unique")
    accepted = value["accepted_findings"]
    if (
        not isinstance(accepted, list)
        or any(not isinstance(item, str) for item in accepted)
        or len(accepted) != len(set(accepted))
        or not set(accepted).issubset(ids)
    ):
        raise SpecError("accepted_findings must name distinct finding ids")
    if value["ran"] is not True and (findings or accepted):
        raise SpecError("review findings require ran=true")
    return value


class Service:
    """Optional dev service started independently for base and candidate trees."""

    def __init__(self, cfg: dict, root: Path, tree: str, env: dict):
        self.cfg, self.root, self.tree, self.env = cfg, root, tree, env
        self.proc: subprocess.Popen | None = None
        self.log = tempfile.NamedTemporaryFile(prefix=f"verify-svc-{tree}-", suffix=".log", delete=False)

    def __enter__(self):
        start = self.cfg.get("start")
        if not start:
            return self
        if not isinstance(start, str):
            raise RuntimeError("service.start must be a string")
        self.proc = subprocess.Popen(
            start,
            shell=True,
            cwd=self.root,
            env=self.env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        ready = self.cfg.get("ready")
        deadline = time.monotonic() + int(self.cfg.get("ready_timeout", 60))
        if ready:
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"service exited early on {self.tree} (log: {self.log.name})")
                if subprocess.run(ready, shell=True, cwd=self.root, env=self.env, capture_output=True).returncode == 0:
                    return self
                time.sleep(1)
            raise RuntimeError(f"service not ready on {self.tree} within timeout (log: {self.log.name})")
        return self

    def __exit__(self, *_exc):
        stop = self.cfg.get("stop")
        if stop:
            subprocess.run(stop, shell=True, cwd=self.root, env=self.env, capture_output=True)
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.log.close()


def run_check(root: Path, check: dict, env: dict) -> dict:
    start = time.monotonic()
    from kernel_process import execute
    cleanup = None
    try:
        code, output, cleanup = execute(['/bin/sh', '-c', check['cmd']], root, env, check['timeout'])
    except OSError as error:
        code, output = HARNESS_EXIT, 'check executable unavailable: ' + str(error)
    complete = cleanup is not None and cleanup['complete']
    return {
        "name": check["name"],
        "kind": check["kind"],
        "exit": code,
        "expected_exit": check["expect_exit"],
        "passed": code == check["expect_exit"] and code != HARNESS_EXIT and complete,
        "harness_error": code == HARNESS_EXIT or not complete,
        "seconds": round(time.monotonic() - start, 2),
        "output_tail": output[-1500:],
        "cleanup": cleanup,
    }


def run_tree(root: Path, tree: str, checks: list[dict], service_cfg: dict) -> tuple[list[dict], str | None]:
    env = {**os.environ, "VERIFY_TREE": tree, "VERIFY_ROOT": str(root)}
    try:
        with Service(service_cfg, root, tree, env):
            return [run_check(root, check, env) for check in checks], None
    except (RuntimeError, ValueError) as error:
        return [], str(error)


def prepare_base_worktree(repo: Path, merge_base: str, cfg: dict) -> tuple[Path | None, str | None]:
    parent = Path(tempfile.mkdtemp(prefix="verify-base-parent-"))
    worktree = parent / "tree"
    try:
        git(repo, "worktree", "add", "--detach", str(worktree), merge_base)
        links = require_string_list(cfg.get("link", []), "worktree.link")
        for rel in links:
            src, dst = repo / rel, worktree / rel
            if src.exists() and not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.symlink_to(src.resolve(), target_is_directory=src.is_dir())
        setup = cfg.get("setup")
        if setup:
            if not isinstance(setup, str):
                return worktree, "worktree.setup must be a string"
            result = subprocess.run(
                setup,
                shell=True,
                cwd=worktree,
                text=True,
                capture_output=True,
                timeout=int(cfg.get("setup_timeout", 600)),
            )
            if result.returncode:
                return worktree, f"base setup failed: {(result.stdout + result.stderr)[-700:]}"
        return worktree, None
    except (SpecError, OSError, subprocess.SubprocessError) as error:
        return worktree if worktree.exists() else None, str(error)


def cleanup_worktree(repo: Path, worktree: Path | None) -> None:
    if worktree is None:
        return
    git(repo, "worktree", "remove", "--force", str(worktree), check=False)
    try:
        worktree.parent.rmdir()
    except OSError:
        pass


def validate_evidence(repo: Path, merge_base: str, checks: list[dict]) -> tuple[set[str], list[str]]:
    tracked = tracked_files_at(repo, merge_base)
    protected: set[str] = set()
    missing: list[str] = []
    for check in checks:
        for pattern in check["evidence"]:
            found = expand_patterns(tracked, [pattern])
            if not found:
                missing.append(f"{check['name']}: {pattern}")
            protected.update(found)
    return protected, missing


def baseline_verdict(checks: list[dict], results: list[dict], error: str | None) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if error:
        return False, [f"base service/setup failed: {error}"]
    by_name = {result["name"]: result for result in results}
    for check in checks:
        result = by_name.get(check["name"])
        if result is None:
            reasons.append(f"missing base result: {check['name']}")
            continue
        if result["harness_error"]:
            reasons.append(f"harness error on base: {check['name']}")
        elif check["kind"] == "acceptance" and result["passed"]:
            reasons.append(f"acceptance already passes on base: {check['name']}")
        elif check["kind"] == "regression" and not result["passed"]:
            reasons.append(f"regression fails on base: {check['name']}")
    return not reasons, reasons


def print_results(prefix: str, results: list[dict]) -> None:
    for result in results:
        state = "HARNESS" if result["harness_error"] else "pass" if result["passed"] else "fail"
        print(f"  [{result['kind'][:5]}] {prefix}:{state}  {result['name']}")


def check_release(expected: str | None) -> None:
    """Authenticate the manifest with a caller-held digest before loading helpers.

    The caller must also trust this entrypoint: self-authentication cannot defend
    against replacement of the guard itself. No candidate-local trust fallback.
    """
    try:
        if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise ValueError("caller must supply --release-sha256 or VERIFY_RELEASE_SHA256")
        root = Path(__file__).resolve().parent
        manifest = root / "MANIFEST.sha256"
        if manifest.is_symlink():
            raise ValueError("manifest must not be a symlink")
        raw = manifest.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected.lower():
            raise ValueError("manifest does not match caller-held digest")
        seen = set()
        for line in raw.decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
            if not match:
                raise ValueError("malformed release manifest")
            digest, name = match.groups()
            parts = name.split("/")
            if any(part in ("", ".", "..") for part in parts) or name.startswith("/") or name in seen:
                raise ValueError("unsafe or duplicate manifest path")
            seen.add(name)
            path = root
            for part in parts:
                path = path / part
                if path.is_symlink():
                    raise ValueError("symlink in release path: " + name)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("release file changed: " + name)
        if not {"verify.py", "kernel_runtime.py", "kernel_report.py"}.issubset(seen):
            raise ValueError("manifest omits a verifier component")
    except (OSError, UnicodeError, ValueError) as error:
        raise SpecError("release integrity: " + str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description="Mechanical completion gate for frozen agent contracts.")
    parser.add_argument("spec", type=Path, nargs="?")
    parser.add_argument("--release-sha256", default=os.environ.get("VERIFY_RELEASE_SHA256"),
                        help="trusted SHA-256 of release manifest, held outside candidate")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", default=os.environ.get("VERIFY_BASE", DEFAULT_BASE),
                        help=f"trusted base ref (default: VERIFY_BASE or {DEFAULT_BASE!r})")
    parser.add_argument("--baseline", action="store_true",
                        help="validate frozen contract against base only; no candidate verdict")
    parser.add_argument("--claim", default="", help="agent's completion claim")
    parser.add_argument("--raw-claim-file", type=Path,
                        help="file containing claim captured before verification")
    parser.add_argument("--implementer-model", help="model/runtime that performed implementation")
    parser.add_argument("--review-metadata", type=Path,
                        help="optional JSON describing independent contract review")
    parser.add_argument("--verifier-access", choices=("yes", "no", "unknown"), default="unknown",
                        help="whether implementer could inspect verifier before its claim")
    parser.add_argument("--verifier-inspection-reported", choices=("yes", "no", "unknown"), default="unknown")
    parser.add_argument("--log", type=Path, help="claim log (default: <repo>/.claims/claims.jsonl)")
    parser.add_argument("--keep-worktree", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    try:
        check_release(args.release_sha256)
        if args.version:
            print(VERIFIER_VERSION)
            return 0
        if args.spec is None:
            raise SpecError("task spec is required")
        repo = Path(git(args.repo.resolve(), "rev-parse", "--show-toplevel"))
        args._resolved_candidate = git(repo, "rev-parse", "HEAD")
        resolved_base = git(repo, "rev-parse", f"{args.base}^{{commit}}")
        merge_base = git(repo, "merge-base", resolved_base, args._resolved_candidate)
        spec, raw_spec, spec_rel = load_frozen_spec(repo, args.spec, merge_base)
        if spec.get("spec_version") == 2:
            from kernel_runtime import verify as verify_schema2
            try:
                return verify_schema2(args, repo, merge_base, spec, raw_spec, spec_rel, globals())
            except (ValueError, OSError, UnicodeError) as error:
                raise SpecError(str(error)) from error
        checks, policy = validate_spec(spec)
        review = load_review_metadata(args.review_metadata)
    except (SpecError, OSError) as error:
        print(f"SPEC_ERROR  {error}", file=sys.stderr)
        return 3

    evidence_files, missing_evidence = validate_evidence(repo, merge_base, checks)
    if missing_evidence:
        print("SPEC_ERROR  declared evidence does not exist at frozen base:", file=sys.stderr)
        for item in missing_evidence:
            print(f"  - {item}", file=sys.stderr)
        return 3

    raw_claim = None
    raw_claim_captured_at = None
    if args.raw_claim_file:
        try:
            raw_claim = args.raw_claim_file.read_text(encoding="utf-8")
        except OSError as error:
            print(f"SPEC_ERROR  raw claim error: {error}", file=sys.stderr)
            return 3
        raw_claim_captured_at = now_utc()

    service_cfg = spec.get("service", {})
    worktree_cfg = spec.get("worktree", {})
    if not isinstance(service_cfg, dict) or not isinstance(worktree_cfg, dict):
        print("SPEC_ERROR  [service] and [worktree] must be tables", file=sys.stderr)
        return 3

    base_results: list[dict] = []
    base_error: str | None = None
    worktree: Path | None = None
    worktree, base_error = prepare_base_worktree(repo, merge_base, worktree_cfg)
    if worktree is not None and not base_error:
        base_results, base_error = run_tree(worktree, "base", checks, service_cfg)
    if worktree is not None and not args.keep_worktree:
        cleanup_worktree(repo, worktree)

    ready, baseline_reasons = baseline_verdict(checks, base_results, base_error)
    if args.baseline:
        state = "READY" if ready else "NOT_READY"
        print(f"BASELINE_{state}  {spec['id']}  base={merge_base[:12]}  assurance=legacy-schema1")
        print_results("base", base_results)
        for reason in baseline_reasons:
            print(f"  - {reason}")
        return 0 if ready else 2

    candidate_results, candidate_error = run_tree(repo, "candidate", checks, service_cfg)

    log = (args.log or repo / ".claims" / "claims.jsonl").resolve()
    log_rel = repo_relative(repo, log)
    verifier_rel = repo_relative(repo, Path(__file__).resolve())

    untracked = set(filter(None, git(repo, "ls-files", "--others", "--exclude-standard").splitlines()))
    files = [path for path in changed_files(repo, merge_base) if path != log_rel]

    automatically_protected = {spec_rel, *evidence_files}
    if verifier_rel:
        automatically_protected.add(verifier_rel)
    protected_patterns = policy["protected"]
    protected_hits = sorted(
        path for path in files
        if path in automatically_protected or matches(path, protected_patterns)
    )
    out_of_scope = sorted(
        path for path in files
        if path not in protected_hits
        and (matches(path, policy["exclude"]) or not matches(path, policy["include"]))
    )

    mutable_test_changes = sorted(
        path for path in files
        if matches(path, policy["test_files"]) and path not in automatically_protected
    )
    bypasses: list[dict] = []
    for path in mutable_test_changes:
        for line in added_lines(repo, merge_base, path, untracked):
            if BYPASS.search(line):
                bypasses.append({"file": path, "line": line.strip()[:200]})

    contradicted: list[str] = []
    unverifiable: list[str] = []
    warnings: list[str] = []

    if candidate_error:
        unverifiable.append(f"candidate service failed: {candidate_error}")
    harness = [
        f"{tree}:{result['name']}"
        for tree, results in (("base", base_results), ("candidate", candidate_results))
        for result in results if result["harness_error"]
    ]
    if harness:
        unverifiable.append(f"harness errors (exit {HARNESS_EXIT}); not evidence: {', '.join(harness)}")

    candidate_failures = [
        result["name"] for result in candidate_results
        if not result["passed"] and not result["harness_error"]
    ]
    if candidate_failures:
        contradicted.append(f"failed on candidate: {', '.join(candidate_failures)}")
    if protected_hits:
        contradicted.append(f"protected evidence/path changed: {', '.join(protected_hits)}")
    if out_of_scope:
        contradicted.append(f"out-of-scope changes: {', '.join(out_of_scope)}")
    if bypasses:
        message = "test bypass patterns added: " + "; ".join(
            f"{item['file']}: {item['line']}" for item in bypasses[:5]
        )
        (contradicted if policy["bypass_policy"] == "fail" else warnings).append(message)

    if not ready:
        unverifiable.extend(baseline_reasons)

    if mutable_test_changes:
        warnings.append(
            "agent-owned test files changed; these may support development but are not independent completion evidence: "
            + ", ".join(mutable_test_changes[:8])
        )

    verdict = "unverifiable" if unverifiable else "contradicted" if contradicted else "supported"
    if not files and verdict == "supported":
        warnings.append("no implementation files changed")

    record = {
        "schema": 1,
        "assurance": "legacy-schema1",
        "at": now_utc(),
        "verifier_version": VERIFIER_VERSION,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "task_id": spec["id"],
        "project": spec["project"],
        "goal": spec["goal"],
        "spec_path": str((repo / spec_rel).resolve()),
        "spec_source": "base",
        "spec_sha256": hashlib.sha256(raw_spec).hexdigest(),
        "base_ref": args.base,
        "merge_base": merge_base,
        "head": git(repo, "rev-parse", "HEAD"),
        "dirty_before_log": bool(git(repo, "status", "--porcelain")),
        "claim": args.claim or raw_claim or "",
        "raw_claim": raw_claim,
        "raw_claim_captured_at": raw_claim_captured_at,
        "implementer_model": args.implementer_model,
        "verifier_access": args.verifier_access,
        "verifier_inspection_reported": args.verifier_inspection_reported,
        "contract_review": review,
        "changed_files": files,
        "protected_changes": protected_hits,
        "out_of_scope": out_of_scope,
        "mutable_test_changes": mutable_test_changes,
        "bypasses": bypasses,
        "base_checks": base_results,
        "candidate_checks": candidate_results,
        "verdict": verdict,
        "reasons": contradicted + unverifiable,
        "warnings": warnings,
    }

    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"{verdict.upper()}  {spec['id']}  ({len(files)} files changed)  assurance=legacy-schema1")
    base_by_name = {result["name"]: result for result in base_results}
    for result in candidate_results:
        base_result = base_by_name.get(result["name"])
        before = ""
        if base_result:
            state = "HARNESS" if base_result["harness_error"] else "pass" if base_result["passed"] else "fail"
            before = f"base:{state} -> "
        state = "HARNESS" if result["harness_error"] else "pass" if result["passed"] else "FAIL"
        print(f"  [{result['kind'][:5]}] {before}candidate:{state}  {result['name']}")
    for reason in record["reasons"]:
        print(f"  - {reason}")
    for warning in warnings:
        print(f"  ! {warning}")
    print(f"  logged -> {log}")
    return {"supported": 0, "contradicted": 1, "unverifiable": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
