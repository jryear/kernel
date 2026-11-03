#!/usr/bin/env python3
"""Stdlib smoke/regression tests for verify.py's trust invariants."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFY = HERE / "verify.py"


def run(cmd: list[str], cwd: Path, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if result.returncode != expect:
        raise AssertionError(
            f"expected exit {expect}, got {result.returncode}\n$ {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit_all(repo: Path, message: str) -> None:
    run(["git", "add", "-A"], repo)
    run(["git", "commit", "-m", message], repo)


def make_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir(parents=True)
    run(["git", "init", "-b", "main"], repo)
    run(["git", "config", "user.email", "kernel@example.test"], repo)
    run(["git", "config", "user.name", "Kernel Selftest"], repo)

    write(repo / "app.txt", "old\n")
    write(repo / "tests/acceptance/new_behavior.sh", "#!/bin/sh\ngrep -q '^new$' app.txt\n")
    write(repo / "tests/acceptance/adversarial.sh", "#!/bin/sh\n! grep -q '^unsafe$' app.txt\n")
    write(repo / "tests/unit/regression.sh", "#!/bin/sh\ntest -f app.txt\n")
    for script in (repo / "tests").rglob("*.sh"):
        script.chmod(0o755)

    write(repo / "tasks/demo.toml", '''\
spec_version = 1
id = "demo-001"
project = "demo"
goal = "app exposes new behavior"
bypass_policy = "fail"

[scope]
include = ["app.txt", "tests/unit/*"]
protected = ["tests/acceptance/*"]
test_files = ["*test*", "*spec*", "tests/unit/*"]

[[checks]]
name = "new behavior"
kind = "acceptance"
cmd = "sh tests/acceptance/new_behavior.sh"
evidence = ["tests/acceptance/new_behavior.sh"]

[[checks]]
name = "safe behavior"
kind = "adversarial"
cmd = "sh tests/acceptance/adversarial.sh"
evidence = ["tests/acceptance/adversarial.sh"]

[[checks]]
name = "regression"
kind = "regression"
cmd = "sh tests/unit/regression.sh"
''')
    commit_all(repo, "freeze contract")
    return repo


def test_supported(root: Path) -> None:
    repo = make_repo(root / "supported")
    run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main", "--baseline"], repo, 0)
    run(["git", "switch", "-c", "work"], repo)
    write(repo / "app.txt", "new\n")
    result = run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main", "--claim", "done"], repo, 0)
    assert "SUPPORTED" in result.stdout


def test_modified_evidence_contradicted(root: Path) -> None:
    repo = make_repo(root / "evidence")
    run(["git", "switch", "-c", "work"], repo)
    write(repo / "app.txt", "new\n")
    write(repo / "tests/acceptance/new_behavior.sh", "#!/bin/sh\nexit 0\n")
    result = run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main"], repo, 1)
    assert "protected evidence/path changed" in result.stdout


def test_uncommitted_contract_rejected(root: Path) -> None:
    repo = make_repo(root / "uncommitted")
    write(repo / "tasks/new.toml", (repo / "tasks/demo.toml").read_text().replace("demo-001", "demo-002"))
    result = run(["python3", str(VERIFY), "tasks/new.toml", "--repo", ".", "--base", "main"], repo, 3)
    assert "not committed at base" in result.stderr


def test_working_spec_cannot_choose_base(root: Path) -> None:
    repo = make_repo(root / "base-field")
    run(["git", "switch", "-c", "work"], repo)
    spec = (repo / "tasks/demo.toml").read_text()
    write(repo / "tasks/demo.toml", spec.replace("spec_version = 1", 'spec_version = 1\nbase = "HEAD"'))
    # Frozen base copy remains authoritative, so the candidate's injected base field is ignored;
    # changing the protected spec is still a contradiction once behavior passes.
    write(repo / "app.txt", "new\n")
    result = run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main"], repo, 1)
    assert "protected evidence/path changed" in result.stdout


def test_regression_failure_contradicted(root: Path) -> None:
    repo = make_repo(root / "regression")
    run(["git", "switch", "-c", "work"], repo)
    write(repo / "app.txt", "new\n")
    write(repo / "tests/unit/regression.sh", "#!/bin/sh\nexit 1\n")
    result = run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main"], repo, 1)
    assert "failed on candidate: regression" in result.stdout



def test_test_bypass_contradicted(root: Path) -> None:
    repo = make_repo(root / "bypass")
    run(["git", "switch", "-c", "work"], repo)
    write(repo / "app.txt", "new\n")
    regression = repo / "tests/unit/regression.sh"
    regression.write_text(regression.read_text() + "# pytest.mark.skip\n", encoding="utf-8")
    result = run(["python3", str(VERIFY), "tasks/demo.toml", "--repo", ".", "--base", "main"], repo, 1)
    assert "test bypass patterns added" in result.stdout


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="kernel-selftest-") as temp:
        root = Path(temp)
        tests = [
            test_supported,
            test_modified_evidence_contradicted,
            test_uncommitted_contract_rejected,
            test_working_spec_cannot_choose_base,
            test_regression_failure_contradicted,
            test_test_bypass_contradicted,
        ]
        for test in tests:
            case_root = root / test.__name__
            case_root.mkdir(parents=True)
            test(case_root)
            print(f"PASS {test.__name__}")
    print(f"PASS all {len(tests)} kernel self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
