#!/usr/bin/env python3
"""Pin this kernel's minimal files into a project repository."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

KERNEL = Path(__file__).resolve().parent


def is_git_repo(path: Path) -> bool:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=path, capture_output=True, text=True)
    return result.returncode == 0


def copy(src: Path, dst: Path, force: bool) -> str:
    if dst.exists() and not force:
        return f"skip  {dst} (exists)"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return f"write {dst}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Adopt the minimal frontier kernel into a repository.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--project", required=True, help="project slug used only to stamp the task template")
    parser.add_argument("--force", action="store_true", help="overwrite existing kernel-managed files")
    args = parser.parse_args()

    repo = args.repo.expanduser().resolve()
    if not repo.is_dir():
        parser.error(f"repository directory does not exist: {repo}")
    if not is_git_repo(repo):
        parser.error(f"not a git repository: {repo}")

    messages = []
    template = (KERNEL / "task.template.toml").read_text(encoding="utf-8")
    template = template.replace('project = "project"', f'project = "{args.project}"', 1)
    task_dst = repo / "tasks" / "task.template.toml"
    if task_dst.exists() and not args.force:
        messages.append(f"skip  {task_dst} (exists)")
    else:
        task_dst.parent.mkdir(parents=True, exist_ok=True)
        task_dst.write_text(template, encoding="utf-8")
        messages.append(f"write {task_dst}")

    messages.append(copy(KERNEL / "review.template.json", repo / "tasks" / "review.template.json", args.force))

    agents_dst = repo / "AGENTS.md"
    if not agents_dst.exists():
        messages.append(copy(KERNEL / "AGENTS.template.md", agents_dst, False))
    else:
        messages.append(f"skip  {agents_dst} (preserved)")

    claims = repo / ".claims"
    claims.mkdir(exist_ok=True)
    gitignore = claims / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n!.gitignore\n", encoding="utf-8")
        messages.append(f"write {gitignore}")

    for message in messages:
        print(message)
    print("\nNext: edit AGENTS.md and tasks/task.template.toml; keep ~/code/_kernel read-only to implementation agents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
