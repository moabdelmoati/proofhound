"""Turns SecBench.js cases into two-commit git repos (benign -> vulnerable) with ground truth.

ProofHound scans commits, but SecBench.js gives a vulnerable package version. Each case becomes:

  commit A  "fixed" mode: the fixed npm version.   "introduce" mode: the package without the sink file.
  commit B  the vulnerable npm version              <- the commit ProofHound scans

"fixed" mode is used when the vulnerable->fixed diff is small (a realistic commit); otherwise
"introduce" mode, where commit B adds the file that contains the sink.
"""

import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

from proofhound.core.config import SandboxSettings
from proofhound.core.fuzzing.sandbox import TARGET, DockerSandbox

NODE_IMAGE = "node:22-trixie-slim"
MAX_FIX_DIFF_LINES = 200
CLASSES = ("command-injection", "path-traversal", "code-injection", "prototype-pollution", "redos")


@dataclass
class SecBenchCase:
    id: str  # SecBench.js directory name, e.g. "command-exists_1.2.2"
    vuln_class: str
    package: str
    version: str
    fixed_version: str | None
    sink: str  # "file:line:col" inside the package
    fix_commit: str | None
    exploit: str  # path of the SecBench.js jest exploit, relative to the SecBench.js root

    @property
    def sink_file(self) -> str:
        return self.sink.rsplit(":", 2)[0]


def load_case(secbench: Path, vuln_class: str, case_id: str) -> SecBenchCase:
    case_dir = secbench / vuln_class / case_id
    meta = json.loads((case_dir / "package.json").read_text(encoding="utf-8"))
    version = case_id.rsplit("_", 1)[1]
    package = next(
        name for name, ver in meta["dependencies"].items()
        if ver == version and name.replace("/", "-") == case_id.rsplit("_", 1)[0]
    )
    fixed = meta.get("fixedVersion")
    fix_commit = meta.get("fixCommit") or None
    exploit = next(case_dir.glob("*.test.js"))
    return SecBenchCase(
        id=case_id,
        vuln_class=vuln_class,
        package=package,
        version=version,
        fixed_version=fixed if fixed and re.match(r"^\d", fixed) else None,
        sink=meta["sink"],
        fix_commit=fix_commit,
        exploit=exploit.relative_to(secbench).as_posix(),
    )


def _resolve_sink(sink: str, package_root: Path) -> str:
    """SecBench's sink is often just `file.js:line:col` even when the real file lives deeper
    (e.g. `packages/bignumber/src.ts/fixednumber.js`). If the top-level path is missing, search
    the package for the exact basename; a single JS/TS file match wins. Returns the input
    unchanged when the path exists, nothing is found, or several files share the name."""
    if not sink:
        return sink
    rel, _, pos = sink.partition(":")
    if (package_root / rel).exists() or "/" in rel:
        return sink
    matches = [p for p in package_root.rglob(rel) if p.is_file() and "node_modules" not in p.parts]
    if len(matches) != 1:
        return sink
    return matches[0].relative_to(package_root).as_posix() + (f":{pos}" if pos else "")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "core.autocrlf=false", *args],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout


def _npm(sandbox: DockerSandbox, workdir: Path, script: str) -> None:
    result = sandbox.run(
        ["sh", "-c", f"export npm_config_cache=/tmp/.npm; cd {TARGET} && {script}"],
        target=workdir, out=workdir / ".out", timeout_s=600, image=NODE_IMAGE, network=True,
    )
    shutil.rmtree(workdir / ".out", ignore_errors=True)
    if result.exit_code != 0:
        raise RuntimeError(f"npm step failed:\n{result.output[-2000:]}")


def _unpack(sandbox: DockerSandbox, workdir: Path, package: str, version: str, dest: str) -> Path:
    _npm(
        sandbox, workdir,
        f"tgz=$(npm pack -q {package}@{version}) && mkdir -p {dest} "
        f"&& tar xzf $tgz -C {dest} --strip-components=1 && rm $tgz",
    )
    return workdir / dest


def _rmtree(path: Path) -> None:
    def _unlock(func, p, _):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onexc=_unlock)


def _replace_tree(repo: Path, source: Path) -> None:
    for item in repo.iterdir():
        if item.name != ".git":
            _rmtree(item) if item.is_dir() else item.unlink(missing_ok=True)
    shutil.copytree(source, repo, dirs_exist_ok=True)


def build_case(
    case: SecBenchCase, dest: Path, sandbox: DockerSandbox | None = None, split: str = "eval"
) -> dict:
    """Create `dest/repo` (two commits, dependencies installed) and `dest/case.yaml`.

    `split` tags the case: "eval" for the benchmark, "train" for distillation data generation
    (a package must appear in only one split — never both — to avoid leakage).
    """
    sandbox = sandbox or DockerSandbox(SandboxSettings())
    _rmtree(dest)
    dest.mkdir(parents=True)
    vulnerable = _unpack(sandbox, dest, case.package, case.version, "pkg-vulnerable")

    mode = "introduce"
    fixed = None
    if case.fixed_version:
        # SecBench.js metadata is noisy (some fixedVersion values do not exist on npm).
        try:
            fixed = _unpack(sandbox, dest, case.package, case.fixed_version, "pkg-fixed")
        except RuntimeError:
            fixed = None
    resolved = _resolve_sink(case.sink, vulnerable)
    if resolved != case.sink:
        case.sink = resolved

    if fixed is not None:
        diff = subprocess.run(
            ["git", "diff", "--no-index", "--numstat", str(fixed), str(vulnerable)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,  # git diff --no-index returns 1 on diff
        ).stdout
        changed = sum(
            int(a) + int(d) for a, d, *_ in (line.split("\t") for line in diff.splitlines())
            if a.isdigit() and d.isdigit()
        )
        if 0 < changed <= MAX_FIX_DIFF_LINES and (vulnerable / case.sink_file).exists():
            mode = "fixed"

    repo = dest / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "proofhound-benchmark")
    _git(repo, "config", "user.email", "benchmark@proofhound.local")

    if mode == "fixed":
        _replace_tree(repo, fixed)
    else:
        _replace_tree(repo, vulnerable)
        sink_path = repo / case.sink_file
        if sink_path.exists():
            sink_path.unlink()  # "introduce" mode: commit B is the one that adds the sink file
        # If the sink file is missing we still have a usable repo for the "reached" check, so
        # fall through rather than fail the whole case here.
    (repo / ".gitignore").write_text("node_modules/\npackage-lock.json\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")

    _replace_tree(repo, vulnerable)
    (repo / ".gitignore").write_text("node_modules/\npackage-lock.json\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", f"{case.package}@{case.version}")
    commit = _git(repo, "rev-parse", "HEAD").strip()

    _npm(sandbox, repo, "npm install -q --omit=dev --ignore-scripts --no-audit --no-fund")
    for tmp in ("pkg-vulnerable", "pkg-fixed"):
        _rmtree(dest / tmp)

    manifest = {
        **asdict(case),
        "commit": commit,
        "commit_mode": mode,
        "split": split,
        "ground_truth": {"class": case.vuln_class, "sink": case.sink},
    }
    (dest / "case.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return manifest
