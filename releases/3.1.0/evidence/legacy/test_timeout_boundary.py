#!/usr/bin/env python3
"""Independent stdlib timeout-boundary evidence. No database or network use.

Run the same frozen bytes against either verifier with --verifier and --receipt.
This runner returns 1 for an assertion failure, 99 for unavailable fixture setup,
and 0 only when all required boundaries pass. Temporary mini-repositories are
local synthetic fixtures, never application repositories. Check timeout commands
use shell exec and a single Python child; broader process cleanup is not tested.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True


class SetupUnavailable(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AssertionError(message)


# Frozen observable helper: its marker comes from each Git tree, not VERIFY_TREE.
CHECK_SOURCE = '''from pathlib import Path
import sys
import time
marker = Path("app.txt").read_text().strip()
kind, mode = sys.argv[1:3]
base = marker == "base"
if (mode == "timeout_base" and base) or (mode == "timeout_candidate" and not base):
    time.sleep(2)
    raise SystemExit(0)
if mode == "fail_candidate" and not base:
    raise SystemExit(1)
if mode == "harness_candidate" and not base:
    raise SystemExit(99)
if mode == "expected":
    raise SystemExit(0 if base else 7)
raise SystemExit(1 if kind == "acceptance" and base else 0)
'''

CASE_NAMES = [
    "unit_timeout_acceptance", "unit_timeout_adversarial", "unit_timeout_regression",
    "unit_finite_failure", "unit_actual_99", "unit_custom_expected_exit",
    "unit_expected_99_forbidden", "cli_base_timeout_acceptance",
    "cli_base_timeout_adversarial", "cli_base_timeout_regression",
    "cli_candidate_timeout_acceptance", "cli_candidate_timeout_adversarial",
    "cli_candidate_timeout_regression", "cli_finite_red_to_green",
    "cli_candidate_failure_acceptance", "cli_candidate_failure_adversarial",
    "cli_candidate_failure_regression", "cli_actual_99",
    "cli_custom_expected_exit", "cli_expected_99_forbidden",
]


class BoundarySuite:
    def __init__(self, verifier, root):
        self.verifier = verifier
        self.root = root
        self.rows = []
        self.details = None
        self.sha = hashlib.sha256(verifier.read_bytes()).hexdigest()
        self.git_binary = shutil.which("git")
        if not self.git_binary:
            raise SetupUnavailable("Git executable unavailable")
        self.home = root / "sanitized-home"
        self.home.mkdir()
        self.empty_template = root / "empty-git-template"
        self.empty_template.mkdir()
        # No inherited provider variables, credential helpers, Git configs or hooks.
        self.env = {
            "PATH": os.pathsep.join(dict.fromkeys([str(Path(self.git_binary).parent), str(Path(sys.executable).parent), "/usr/bin", "/bin"])),
            "HOME": str(self.home), "TMPDIR": str(root), "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "", "GIT_ASKPASS": "/usr/bin/false",
            "GIT_AUTHOR_NAME": "Independent Timeout Fixture",
            "GIT_AUTHOR_EMAIL": "timeout-fixture@example.test",
            "GIT_COMMITTER_NAME": "Independent Timeout Fixture",
            "GIT_COMMITTER_EMAIL": "timeout-fixture@example.test",
        }
        module_spec = importlib.util.spec_from_file_location("reviewed_timeout_verifier", verifier)
        if module_spec is None or module_spec.loader is None:
            raise SetupUnavailable("Cannot load supplied verifier")
        self.module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(self.module)
        for name in ["run_check", "baseline_verdict", "validate_spec", "SpecError"]:
            require(hasattr(self.module, name), "Required verifier interface missing: " + name)

    def process(self, argv, cwd, timeout=15, setup=False):
        start = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=cwd, env=self.env, text=True, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SetupUnavailable("Fixture process unavailable: " + type(error).__name__) from error
        data = {"argv": argv, "returncode": result.returncode,
                "seconds": round(time.monotonic() - start, 3),
                "stdout": result.stdout, "stderr": result.stderr}
        if self.details is not None:
            self.details.setdefault("processes", []).append(data)
        if setup and result.returncode != 0:
            raise SetupUnavailable("Disposable Git setup failed: " + result.stderr[-700:])
        return data

    def git(self, repo, *args):
        result = self.process([self.git_binary, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args], repo, setup=True)
        return result["stdout"].strip()

    def check(self, kind, source, expected=0, timeout=1):
        cmd = "exec " + shlex.quote(sys.executable) + " -B -c " + shlex.quote(source)
        check = {"name": "probe", "kind": kind, "cmd": cmd,
                 "expect_exit": expected, "timeout": timeout, "evidence": ["checks/check.py"]}
        start = time.monotonic()
        result = self.module.run_check(self.root, check, self.env)
        self.details.setdefault("innerChecks", []).append({"source": source, "kind": kind,
            "expectedExit": expected, "secondsObserved": round(time.monotonic() - start, 3), "result": result})
        return check, result

    def timeout_unit(self, kind, expected=0):
        check, result = self.check(kind, "import time; time.sleep(2)", expected)
        ready, reasons = self.module.baseline_verdict([check], [result], None)
        self.details["baseline"] = {"ready": ready, "reasons": reasons}
        # Collect all observed properties before asserting, so baseline evidence remains visible.
        require(result["exit"] == 99, "Actual check timeout must record exit99, got " + repr(result["exit"]))
        require(result["harness_error"] is True, "Actual timeout must be harness_error=true")
        require(result["passed"] is False, "Actual timeout must never pass")
        require("TIMEOUT" in result["output_tail"], "Timeout diagnostic absent")
        require(ready is False, "Actual timeout must never establish BASELINE_READY")

    def unit_timeout_acceptance(self): self.timeout_unit("acceptance")
    def unit_timeout_adversarial(self): self.timeout_unit("adversarial")
    def unit_timeout_regression(self): self.timeout_unit("regression")

    def unit_finite_failure(self):
        check, result = self.check("acceptance", "raise SystemExit(1)")
        ready, reasons = self.module.baseline_verdict([check], [result], None)
        self.details["baseline"] = {"ready": ready, "reasons": reasons}
        require(result["exit"] == 1 and not result["passed"] and not result["harness_error"], "Finite exit1 must remain ordinary RED")
        require(ready is True and not reasons, "Finite acceptance failure must still establish valid baseline RED")

    def unit_actual_99(self):
        check, result = self.check("acceptance", "raise SystemExit(99)")
        ready, reasons = self.module.baseline_verdict([check], [result], None)
        self.details["baseline"] = {"ready": ready, "reasons": reasons}
        require(result["exit"] == 99 and result["harness_error"] and not result["passed"], "Actual reserved99 must stay harness failure")
        require(not ready, "Actual99 cannot establish BASELINE_READY")

    def unit_custom_expected_exit(self):
        check, result = self.check("acceptance", "raise SystemExit(7)", expected=7)
        require(result["exit"] == 7 and result["passed"] and not result["harness_error"], "Explicit expected non99 failure must count as pass")
        self.timeout_unit("acceptance", expected=7)

    def unit_expected_99_forbidden(self):
        spec = {"spec_version": 1, "id": "timeout-001", "project": "synthetic", "goal": "reserved99 must remain unavailable",
            "checks": [{"name": "reserved", "kind": "acceptance", "cmd": "exit 99", "expect_exit": 99, "evidence": ["checks/check.py"]}]}
        try:
            self.module.validate_spec(spec)
        except self.module.SpecError as error:
            self.details["specError"] = str(error)
            require("99" in str(error) and "reserved" in str(error), "Wrong reason for rejected expected99")
        else:
            raise AssertionError("Expected exit99 must remain forbidden")

    def mini_repo(self, kind="acceptance", mode="normal", expected=0):
        case = self.root / self.details["name"]
        repo = case / "repo"
        repo.mkdir(parents=True)
        self.git(repo, "init", "-b", "main", "--template=" + str(self.empty_template))
        (repo / "checks").mkdir()
        (repo / "tasks").mkdir()
        (repo / "app.txt").write_text("base\n")
        (repo / "checks/check.py").write_text(CHECK_SOURCE)
        checks = []
        if kind != "acceptance":
            checks.append(("control acceptance", "acceptance", "normal", 0))
        checks.append(("target", kind, mode, expected))
        text = 'spec_version = 1\nid = "timeout-boundary-001"\nproject = "synthetic"\ngoal = "classify actual check outcomes"\nbypass_policy = "fail"\n\n[scope]\ninclude = ["app.txt"]\nprotected = ["checks/*", "tasks/*"]\ntest_files = []\n'
        for name, check_kind, behavior, expect in checks:
            command = "exec " + shlex.quote(sys.executable) + " -B checks/check.py " + shlex.quote(check_kind) + " " + shlex.quote(behavior)
            text += '\n[[checks]]\nname = ' + json.dumps(name) + '\nkind = ' + json.dumps(check_kind) + '\ncmd = ' + json.dumps(command) + '\nexpect_exit = ' + str(expect) + '\ntimeout = 1\nevidence = ["checks/check.py"]\n'
        (repo / "tasks/check.toml").write_text(text)
        self.git(repo, "add", "app.txt", "checks/check.py", "tasks/check.toml")
        self.git(repo, "commit", "-m", "Freeze synthetic contract and executable evidence")
        base = self.git(repo, "rev-parse", "HEAD")
        (repo / "app.txt").write_text("candidate\n")
        self.git(repo, "add", "app.txt")
        self.git(repo, "commit", "-m", "Synthetic candidate marker only")
        candidate = self.git(repo, "rev-parse", "HEAD")
        self.details["fixture"] = {"kind": kind, "mode": mode, "expectedExit": expected,
            "baseSha": base, "candidateSha": candidate,
            "frozenContractSha256": hashlib.sha256(text.encode()).hexdigest(),
            "frozenCheckSourceSha256": hashlib.sha256(CHECK_SOURCE.encode()).hexdigest(),
            "appOnlyChanged": self.git(repo, "diff", "--name-only", base) == "app.txt",
            "clean": self.git(repo, "status", "--porcelain") == ""}
        require(self.details["fixture"]["appOnlyChanged"] and self.details["fixture"]["clean"], "Mini-repo must bind a clean marker-only candidate")
        return repo, base, case

    def cli(self, repo, base, case, baseline=False):
        log = case / "verdict.jsonl"
        cmd = [sys.executable, "-B", str(self.verifier), "tasks/check.toml", "--repo", str(repo), "--base", base]
        if baseline:
            cmd += ["--baseline"]
        else:
            cmd += ["--claim", "synthetic timeout boundary control", "--implementer-model", "fixed local app marker fixture", "--log", str(log)]
        result = self.process(cmd, repo, timeout=15)
        record = None
        if log.exists():
            try:
                record = json.loads(log.read_text().splitlines()[-1])
            except (ValueError, IndexError) as error:
                raise AssertionError("Verifier wrote an invalid outcome record") from error
            require(record["verifier_sha256"] == self.sha, "Outcome source SHA does not match supplied verifier")
            self.details.setdefault("verifierRecords", []).append(record)
        return result, record

    def base_timeout(self, kind):
        repo, base, case = self.mini_repo(kind, "timeout_base")
        result, _ = self.cli(repo, base, case, baseline=True)
        require(result["returncode"] == 2, "Timeout base must exit2, got " + str(result["returncode"]))
        require("BASELINE_NOT_READY" in result["stdout"] and "BASELINE_READY" not in result["stdout"], "Timeout must not claim BASELINE_READY")
        require("base:HARNESS  target" in result["stdout"], "Base timeout must be reported HARNESS, not ordinary failure")

    def candidate_timeout(self, kind):
        repo, base, case = self.mini_repo(kind, "timeout_candidate")
        result, record = self.cli(repo, base, case)
        require(record is not None, "Missing timeout outcome record")
        target = next(c for c in record["candidate_checks"] if c["name"] == "target")
        self.details["targetClassification"] = target
        require(result["returncode"] == 2 and record["verdict"] == "unverifiable", "Timeout-only candidate must be UNVERIFIABLE exit2, got " + str(result["returncode"]) + "/" + record["verdict"])
        require(target["exit"] == 99 and target["harness_error"] and not target["passed"], "Candidate timeout must record reserved99 harness failure")
        require(any("harness errors" in reason for reason in record["reasons"]), "Missing harness reason")
        require(not any("failed on candidate" in reason for reason in record["reasons"]), "Timeout alone must not claim ordinary candidate contradiction")

    def cli_base_timeout_acceptance(self): self.base_timeout("acceptance")
    def cli_base_timeout_adversarial(self): self.base_timeout("adversarial")
    def cli_base_timeout_regression(self): self.base_timeout("regression")
    def cli_candidate_timeout_acceptance(self): self.candidate_timeout("acceptance")
    def cli_candidate_timeout_adversarial(self): self.candidate_timeout("adversarial")
    def cli_candidate_timeout_regression(self): self.candidate_timeout("regression")

    def cli_finite_red_to_green(self):
        repo, base, case = self.mini_repo("regression", "normal")
        baseline, _ = self.cli(repo, base, case, baseline=True)
        require(baseline["returncode"] == 0 and "BASELINE_READY" in baseline["stdout"], "Healthy finiteRED control must remain baseline ready")
        result, record = self.cli(repo, base, case)
        require(result["returncode"] == 0 and record["verdict"] == "supported", "FiniteRED to GREEN must remain SUPPORTED")
        base_check = next(c for c in record["base_checks"] if c["kind"] == "acceptance")
        require(base_check["exit"] == 1 and not base_check["harness_error"], "Positive control RED must be actual finite exit1")
        require(all(c["passed"] and not c["harness_error"] for c in record["candidate_checks"]), "Positive control candidate must actually pass")

    def candidate_failure(self, kind):
        repo, base, case = self.mini_repo(kind, "fail_candidate")
        baseline, _ = self.cli(repo, base, case, baseline=True)
        require(baseline["returncode"] == 0 and "BASELINE_READY" in baseline["stdout"], "Ordinary failure control baseline must be ready")
        result, record = self.cli(repo, base, case)
        target = next(c for c in record["candidate_checks"] if c["name"] == "target")
        self.details["targetClassification"] = target
        require(result["returncode"] == 1 and record["verdict"] == "contradicted", "Actual ordinary candidate failure must remain CONTRADICTED exit1")
        require(target["exit"] == 1 and not target["passed"] and not target["harness_error"], "Actual exit1 must not become a harness failure")

    def cli_candidate_failure_acceptance(self): self.candidate_failure("acceptance")
    def cli_candidate_failure_adversarial(self): self.candidate_failure("adversarial")
    def cli_candidate_failure_regression(self): self.candidate_failure("regression")

    def cli_actual_99(self):
        repo, base, case = self.mini_repo("acceptance", "harness_candidate")
        result, record = self.cli(repo, base, case)
        require(result["returncode"] == 2 and record["verdict"] == "unverifiable", "Actual99 must remain UNVERIFIABLE exit2")
        target = record["candidate_checks"][0]
        self.details["targetClassification"] = target
        require(target["exit"] == 99 and target["harness_error"] and not target["passed"], "Real99 classification changed")

    def cli_custom_expected_exit(self):
        repo, base, case = self.mini_repo("acceptance", "expected", expected=7)
        baseline, _ = self.cli(repo, base, case, baseline=True)
        require(baseline["returncode"] == 0, "Mismatch against expected7 must remain finite base RED")
        result, record = self.cli(repo, base, case)
        require(result["returncode"] == 0 and record["verdict"] == "supported", "Expected actual7 must remain supported")
        base_check, target = record["base_checks"][0], record["candidate_checks"][0]
        require(base_check["exit"] == 0 and base_check["expected_exit"] == 7 and not base_check["passed"], "Expected-exit base mismatch not exercised")
        require(target["exit"] == 7 and target["passed"] and not target["harness_error"], "Expected actual7 must remain non-harness pass")

    def cli_expected_99_forbidden(self):
        repo, base, case = self.mini_repo("acceptance", "normal", expected=99)
        result, record = self.cli(repo, base, case, baseline=True)
        require(result["returncode"] == 3 and "reserved harness exit 99" in result["stderr"], "Expected99 must remain SPEC_ERROR exit3")
        require(record is None, "Invalid reserved-exit contract must not write completion evidence")

    def run(self):
        for name in CASE_NAMES:
            start = time.monotonic()
            self.details = {"name": name}
            try:
                getattr(self, name)()
                status, message = "pass", ""
            except SetupUnavailable as error:
                status, message = "unavailable", str(error)
            except AssertionError as error:
                status, message = "fail", str(error)
            except Exception as error:
                status, message = "unavailable", type(error).__name__ + ": " + str(error)
                self.details["traceback"] = traceback.format_exc()
            self.details.update(status=status, message=message, seconds=round(time.monotonic() - start, 3))
            self.rows.append(self.details)
            print(status.upper() + " " + name + (": " + message if message else ""), flush=True)
        self.details = None
        return 99 if any(r["status"] == "unavailable" for r in self.rows) else 1 if any(r["status"] == "fail" for r in self.rows) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    start = time.monotonic()
    record = {"schema": 1, "suite": str(Path(__file__).resolve()),
        "suiteSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "verifier": str(args.verifier.resolve()), "python": sys.version,
        "classificationScope": "actual check timeout classification only; no process-group cleanup, database, network, installed-kernel or application acceptance claim",
        "sanitizedEnvironment": "allowlist only; disposable HOME; no provider/Git credentials/configs/hooks; no remote protocols"}
    try:
        verifier = args.verifier.resolve(strict=True)
        if sys.version_info < (3, 11):
            raise SetupUnavailable("Python3.11+ required")
        with tempfile.TemporaryDirectory(prefix="kernel-timeout-evidence-") as scratch:
            suite = BoundarySuite(verifier, Path(scratch))
            record.update(verifierSha256=suite.sha, verifierVersion=suite.module.VERIFIER_VERSION)
            exit_code = suite.run()
            record["cases"] = suite.rows
    except AssertionError as error:
        exit_code = 1
        record["setupFailure"] = str(error)
    except Exception as error:
        exit_code = 99
        record["setupUnavailable"] = type(error).__name__ + ": " + str(error)
    cases = record.get("cases", [])
    record.update(rawExit=exit_code, elapsedSeconds=round(time.monotonic() - start, 3),
        counts={s: sum(r["status"] == s for r in cases) for s in ["pass", "fail", "unavailable"]})
    try:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(record, indent=2) + "\n")
    except OSError as error:
        print("HARNESS receipt unavailable: " + str(error), file=sys.stderr)
        return 99
    print(json.dumps({"rawExit": exit_code, "counts": record["counts"], "elapsedSeconds": record["elapsedSeconds"], "receipt": str(args.receipt)}), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
