"""Parses a commit diff into changed files and line ranges."""

import subprocess
from pathlib import Path

from unidiff import PatchSet

# Hash of git's empty tree; lets the first commit of a repo be diffed like any other.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout


def parent_of(repo: Path, commit: str) -> str:
    try:
        return _git(repo, "rev-parse", f"{commit}^").strip()
    except subprocess.CalledProcessError:
        return EMPTY_TREE


def changed_lines(
    repo: Path, commit: str = "HEAD", extensions: tuple[str, ...] | None = None
) -> dict[Path, set[int]]:
    """Map each added/modified file (relative to repo) to its added line numbers in `commit`.

    Deleted lines are ignored: only code that exists after the commit can be fuzzed.
    """
    diff = _git(repo, "diff", "-U0", "--no-color", "--no-renames", parent_of(repo, commit), commit)
    result: dict[Path, set[int]] = {}
    for patched in PatchSet(diff):
        if patched.is_removed_file:
            continue
        path = Path(patched.path)
        if extensions and path.suffix not in extensions:
            continue
        lines = {
            line.target_line_no
            for hunk in patched
            for line in hunk
            if line.is_added and line.target_line_no is not None
        }
        if lines:
            result[path] = lines
    return result
