import subprocess

import pytest

from proofhound.core.config import SandboxSettings
from proofhound.core.fuzzing import sandbox as sandbox_module
from proofhound.core.fuzzing.sandbox import DockerSandbox, SandboxUnavailable

DAEMON_DOWN = (
    "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; check if the "
    "path is correct and if the daemon is running"
)


def _fake_run(returncode: int, stdout: str = "", stderr: str = ""):
    def run(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    return run


def test_daemon_down_raises_instead_of_looking_like_a_failed_command(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_module.subprocess, "run", _fake_run(1, stderr=DAEMON_DOWN))
    with pytest.raises(SandboxUnavailable):
        DockerSandbox(SandboxSettings()).run(["node", "--check", "h.js"], tmp_path, tmp_path / "out", 30)


def test_a_real_syntax_error_is_still_a_normal_result(tmp_path, monkeypatch):
    error = "/work/out/harness.js:3\nSyntaxError: Unexpected token '}'"
    monkeypatch.setattr(sandbox_module.subprocess, "run", _fake_run(1, stderr=error))
    result = DockerSandbox(SandboxSettings()).run(["node", "--check", "h.js"], tmp_path, tmp_path / "out", 30)
    assert result.exit_code == 1
    assert "SyntaxError" in result.output


def test_check_ready_fails_when_docker_is_down(monkeypatch):
    monkeypatch.setattr(sandbox_module.subprocess, "run", _fake_run(1, stderr=DAEMON_DOWN))
    with pytest.raises(SandboxUnavailable, match="failed to connect"):
        DockerSandbox(SandboxSettings()).check_ready()


def test_check_ready_fails_when_docker_is_not_installed(monkeypatch):
    def missing(args, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(sandbox_module.subprocess, "run", missing)
    with pytest.raises(SandboxUnavailable):
        DockerSandbox(SandboxSettings()).check_ready()


def test_check_ready_passes_when_the_image_exists(monkeypatch):
    monkeypatch.setattr(sandbox_module.subprocess, "run", _fake_run(0, stdout="[{}]"))
    DockerSandbox(SandboxSettings()).check_ready()
